# Technical Debt Report — Oracle Forms/PL-SQL HRMS

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Analyzed revision:** `1c33787` (branch `main`)
**Date:** 2026-08-17
**Scope:** 43 source files / 8,587 lines — PL/SQL packages (`plsql/packages`), triggers (`plsql/triggers`), schema DDL (`schema/`), seed data (`data/seed`), Forms XML exports and PLL library exports (`forms/`)
**Platform:** Oracle Forms 11g/12c against Oracle Database 19c, ~200 concurrent users across three offices

## Executive summary

The codebase is a functionally rich but structurally fragile legacy HRMS. Static analysis of the current sources found **56 findings**. The dominant themes are (1) an authentication path that does not actually authenticate, (2) database objects that reference columns and constants that do not exist or do not agree across layers, and (3) money- and leave-balance arithmetic that is computed differently in each layer that reports it.

Three findings are severe enough to be treated as production incidents rather than debt:

- `PKG_SECURITY.authenticate` issues a session for any known active e-mail **without ever comparing a password** (SEC-01).
- `TRG_EMP_BEFORE_UPDATE` inserts into `EMPLOYEE_HISTORY` using six column names that do not exist in the table DDL, so the trigger cannot compile and every `UPDATE` on `EMPLOYEES` is at risk of failing (DI-01).
- Leave-request audit rows are silently discarded because the trigger passes an `ACTION_TYPE` value that violates both the column length and the check constraint, and `PKG_AUDIT` swallows the error (DI-02).

There is **no automated test suite, no build system, and no `DATA_DICTIONARY.md`** in the repository, so none of the mismatches below are caught before deployment. Column-description cross-referencing was therefore performed against DDL `COMMENT ON` statements instead of a data dictionary.

### Severity counts

| Severity | Count |
|---|---|
| CRITICAL | 5 |
| HIGH | 17 |
| MEDIUM | 24 |
| LOW | 10 |
| **Total** | **56** |

### Category breakdown

| Category | Findings | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|---|
| Security (SEC) | 12 | 3 | 5 | 3 | 1 |
| Race conditions (RC) | 6 | 0 | 2 | 3 | 1 |
| Performance (PERF) | 7 | 0 | 2 | 4 | 1 |
| Validation drift (VAL) | 7 | 0 | 1 | 3 | 3 |
| Architecture (ARCH) | 10 | 0 | 3 | 4 | 3 |
| Data integrity (DI) | 14 | 2 | 4 | 7 | 1 |

### Confidence convention

Findings are marked **[confirmed]** when the defect is fully visible in the current sources, and **[inferred]** when the source (usually an author comment) asserts a condition that the code in this repository does not demonstrate on its own. Inferred findings are still worth acting on, but they need runtime validation before being called bugs.

---

## Security findings

### SEC-01 — Authentication never verifies the password (authentication bypass) — CRITICAL [confirmed]

**File:** `plsql/packages/PKG_SECURITY.pkb:30-80`

```sql
FUNCTION authenticate(...) RETURN NUMBER IS
    v_emp_id     NUMBER;
    v_session_id NUMBER;
    v_stored_hash VARCHAR2(200);
    v_input_hash  VARCHAR2(200);
BEGIN
    SELECT EMP_ID INTO v_emp_id FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
    ...
    -- NOTE: In the real system, passwords are stored in a separate
    -- USER_CREDENTIALS table. For this legacy codebase, we simulate
    -- authentication against a simplified model.
    SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
    INSERT INTO USER_SESSIONS (...) VALUES (v_session_id, v_emp_id, ...);
    RETURN v_session_id;
```

**Issue:** `p_password` is never read. `v_stored_hash` and `v_input_hash` are declared and never assigned, and `hash_password` is never called from this function. Any caller supplying an active employee's e-mail address — including an empty or NULL password — receives a valid `SESSION_ID`, and `HRMS_LOGIN.xml:64-101` treats a non-null return as a successful login.

**Impact:** Complete authentication bypass for every account in the system, including HR and payroll roles. All downstream authorization (`has_permission`, `is_session_valid`) trusts this session.

**Recommendation:** Introduce the `USER_CREDENTIALS` table the comment refers to, hash with a salted, iterated KDF, compare in constant time, and fail closed. Until then, treat the application as unauthenticated and place it behind an external authenticator (SSO/LDAP proxy).

### SEC-02 — Password hashing uses MD5 — CRITICAL [confirmed]

**File:** `plsql/packages/PKG_SECURITY.pkb:14-24`

```sql
RETURN RAWTOHEX(
    DBMS_CRYPTO.HASH(
        UTL_RAW.CAST_TO_RAW(p_password),
        DBMS_CRYPTO.HASH_MD5
    )
);
```

**Issue:** MD5 is a fast, unsalted, collision-broken digest; it is unsuitable for password storage. The function is also dead code (see SEC-01), which means the weak primitive is what any future "real" implementation would most likely adopt.

**Impact:** Any leaked digest set is recoverable with commodity hardware; identical passwords produce identical hashes across accounts.

**Recommendation:** Replace with PBKDF2 (`DBMS_CRYPTO.PBKDF2` on 19c) or delegate to an external identity provider; store per-user salts and an algorithm/version marker to allow migration.

### SEC-03 — Hard-coded encryption key, and the key is the wrong length for AES-256 — CRITICAL [confirmed]

**Files:** `plsql/packages/PKG_SECURITY.pkb:6-7`, `179-206`; `schema/tables/01_core_tables.sql:146`

```sql
-- VULNERABILITY: Encryption key hard-coded in source
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
...
v_raw := DBMS_CRYPTO.ENCRYPT(
    src => UTL_RAW.CAST_TO_RAW(p_ssn),
    typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
    key => c_encryption_key);
```

**Issue:** Two defects in the same constant. First, the SSN encryption key is committed in source, so anyone with repository or `ALL_SOURCE` read access can decrypt every SSN — and key rotation requires a code deployment. Second, the literal is 30 bytes, while `ENCRYPT_AES256` requires a 32-byte key; short keys are rejected by `DBMS_CRYPTO`. `decrypt_ssn` masks that failure by returning `'***DECRYPT_ERROR***'` from a bare `WHEN OTHERS` (lines 203-205), so the breakage surfaces as unreadable data rather than an error. Meanwhile `01_core_tables.sql:146` documents the column as `'AES-256 encrypted SSN - decrypted only in PKG_SECURITY'`.

**Impact:** Either SSNs are protected by a publicly known key, or (more likely, given the key length) SSN encryption/decryption fails at runtime and the documented protection does not exist at all.

**Recommendation:** Move to Transparent Data Encryption or a wallet/`DBMS_CREDENTIAL`-backed key, use a 32-byte key derived from that secret, remove the `WHEN OTHERS` mask, and rotate the exposed key as part of remediation.

### SEC-04 — `change_password` validates complexity and then changes nothing — HIGH [confirmed]

**File:** `plsql/packages/PKG_SECURITY.pkb:211-234`

```sql
IF LENGTH(p_new_password) < 8 THEN ... END IF;
-- NOTE: Actual password update would go to USER_CREDENTIALS table
-- This is a stub for the legacy system model
PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
```

**Issue:** The procedure returns successfully and writes an audit record asserting a password change that never happened. `p_old_password` is never verified.

**Impact:** Users and auditors are told credentials rotated when they did not; incident response after a breach would rely on false audit evidence.

**Recommendation:** Implement the update against the credential store, verify the old password first, and remove the audit write from the stub path.

### SEC-05 — SQL injection in `search_employees` — HIGH [confirmed]

**File:** `plsql/packages/PKG_EMPLOYEE.pkb:445-499`

```sql
IF p_last_name IS NOT NULL THEN
    -- VULNERABILITY: String concatenation instead of bind variable
    v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
END IF;
...
OPEN p_cursor FOR v_sql;
```

**Issue:** Five of the seven filters (`p_last_name`, `p_first_name`, `p_dept_id`, `p_status`, `p_location_code`) are concatenated into the statement text with no escaping or bind. The package header notes Forms LOVs pass validated values, but the procedure is a public API of the package.

**Impact:** Any caller (Forms, reports, ad-hoc scripts, or a compromised account) can read arbitrary data the `HRMS` schema can see via `UNION`-style injection.

**Recommendation:** Convert every predicate to a bind variable with `DBMS_SQL`/`OPEN ... USING`, or replace the dynamic build with a single static statement using `(p_x IS NULL OR col = p_x)` predicates.

### SEC-06 — Login credentials handled in cleartext by the Forms layer — HIGH [confirmed]

**File:** `forms/xml-exports/HRMS_LOGIN.xml:10-14`, `45-51`, `64-101`

```xml
Known Issues:
  - Password field transmitted in cleartext (Forms applet limitation)
  - No account lockout after failed attempts
  - No CAPTCHA or 2FA support
...
<Item Name="PASSWORD" ItemType="Text Field" ... ConcealData="Yes"/>
```

**Issue:** `ConcealData="Yes"` only masks the glyphs on screen; the value is passed as a plain bind into `PKG_SECURITY.authenticate`. The export itself documents cleartext transmission and the absence of 2FA.

**Impact:** Credentials are exposed to anyone who can observe the Forms traffic, and there is no second factor to contain the exposure.

**Recommendation:** Terminate Forms traffic over TLS end to end (HTTPS + encrypted Forms listener), and add an external MFA step at the authenticator once SEC-01 is fixed.

### SEC-07 — No account lockout or failed-attempt tracking — HIGH [confirmed]

**Files:** `plsql/packages/PKG_SECURITY.pkb:26-80`; `plsql/packages/PKG_SECURITY.pks` header; `schema/tables/04_performance_tables.sql:153-168`

**Issue:** `authenticate` records only successful sessions in `USER_SESSIONS`; there is no failed-attempt counter, no lockout threshold, and no throttling anywhere in the package. `SYSTEM_PARAMETERS` seeds `PASSWORD_MIN_LENGTH` (`data/seed/01_reference_data.sql:193`) but nothing lockout-related.

**Impact:** Unlimited online credential guessing; no detection signal for brute-force attempts.

**Recommendation:** Persist failed attempts per username/IP, lock or exponentially back off after a threshold, and emit an audit/alert event on lockout.

### SEC-08 — Authorization keyed to a surrogate `GRADE_ID`, which sequences will break — HIGH [confirmed]

**Files:** `plsql/packages/PKG_SECURITY.pkb:134-174`; `data/seed/01_reference_data.sql:23-42`; `schema/sequences/hrms_sequences.sql:11`

```sql
IF v_grade_id >= 8 THEN
    RETURN TRUE;  -- Senior management - full access
END IF;
IF p_action = 'VIEW' AND v_grade_id >= 5 THEN RETURN TRUE; END IF;
```

**Issue:** The permission model compares `JOB_TITLES.GRADE_ID` — a meaningless surrogate key — against 5 and 8. It works today only because the seed happens to assign `GRADE_ID = GRADE_LEVEL` for grades 1-10. `SEQ_JOB_GRADE` starts at 100, so every grade created through the normal path receives `GRADE_ID >= 100` and grants **full access to all modules**.

**Impact:** Silent privilege escalation to full HR/payroll access the first time a new job grade is added.

**Recommendation:** Base the check on `JOB_GRADES.GRADE_LEVEL` (or an explicit role/permission table) and add a regression test that a newly created grade does not confer elevated rights.

### SEC-09 — Session lifetime measured from login, not last activity; no invalidation on termination — MEDIUM [confirmed]

**Files:** `plsql/packages/PKG_SECURITY.pkb:98-127`; `plsql/packages/PKG_EMPLOYEE.pkb:737-739`

```sql
IF (SYSDATE - v_login_time) * 24 * 60 > c_session_timeout_min THEN
```

**Issue:** `USER_SESSIONS.LOGIN_TIME` is the only clock, so an active user is logged out 30 minutes after login while an idle session stays valid until that same deadline. Termination processing still carries `-- TODO: Revoke system access via PKG_SECURITY`, so terminated employees' sessions are not closed.

**Impact:** Poor usability plus a window in which terminated staff retain a valid session.

**Recommendation:** Track `LAST_ACTIVITY_TIME` and expire on idle; close all sessions for an employee as part of `terminate_employee`.

### SEC-10 — User enumeration and ambiguous identity resolution at login — MEDIUM [confirmed]

**Files:** `plsql/packages/PKG_SECURITY.pkb:40-57`; `schema/tables/01_core_tables.sql:134-142`

```sql
WHEN NO_DATA_FOUND THEN
    -- VULNERABILITY: Timing attack - different response time for
    -- invalid user vs invalid password
    RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
WHEN TOO_MANY_ROWS THEN
    SELECT MIN(EMP_ID) INTO v_emp_id FROM EMPLOYEES WHERE UPPER(EMAIL) = ...
```

**Issue:** Unknown users fail fast on a different code path than (nominal) password failure, and duplicate e-mails are resolved by `MIN(EMP_ID)` — the login lands on an arbitrary account. `EMPLOYEES` has **no unique constraint on `EMAIL`** (only `UK_EMP_NUMBER`), so duplicates are permitted by the schema.

**Impact:** Account enumeration; and with duplicate e-mails, a user can be authenticated as a different employee.

**Recommendation:** Add a unique constraint on active e-mail (functional index on `CASE WHEN ACTIVE_FLAG='Y' THEN UPPER(EMAIL) END`), make failure paths uniform, and reject rather than guess on ambiguity.

### SEC-11 — Hard-coded SMTP configuration; integration credentials in cleartext parameters — MEDIUM [confirmed / inferred]

**Files:** `plsql/packages/PKG_NOTIFICATION.pkb:6-10`; `plsql/packages/PKG_INTEGRATION.pks:12`; `schema/tables/04_performance_tables.sql:110-124`

```sql
-- Hard-coded SMTP config (should be in SYSTEM_PARAMETERS)
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
```

**Issue:** Mail routing is compiled into the package body (confirmed), and port 25 with no `STARTTLS`/auth means employee data leaves the database unencrypted. `PKG_INTEGRATION.pks:12` states FTP credentials live in `SYSTEM_PARAMETERS` in cleartext; no code in this repository reads them, and `SYSTEM_PARAMETERS.PARAM_VALUE` has no encryption, so the exposure is credible but unverified here (inferred).

**Impact:** Environment promotion requires code changes; notification content (including salary and leave details) traverses the network in the clear; shared secrets are readable by anyone with `SELECT` on `SYSTEM_PARAMETERS`.

**Recommendation:** Read SMTP settings from `SYSTEM_PARAMETERS`, require TLS and SMTP auth, and move all integration credentials to a wallet/`DBMS_CREDENTIAL` object with restricted grants.

### SEC-12 — Blanket `WHEN OTHERS` masks cryptographic and audit failures — LOW [confirmed]

**Files:** `plsql/packages/PKG_SECURITY.pkb:203-205`; `plsql/packages/PKG_AUDIT.pkb:27-31`; `plsql/packages/PKG_EMPLOYEE.pkb:171-178`

**Issue:** Decryption failures become a sentinel string, and audit/history failures become a silent `ROLLBACK` with no diagnostic (see DI-02 for the consequence).

**Impact:** Security-relevant failures are invisible in production.

**Recommendation:** Log with `SQLERRM` and `DBMS_UTILITY.FORMAT_ERROR_BACKTRACE` to an error table that cannot itself be swallowed, and alert on non-zero counts.

---

## Race condition findings

### RC-01 — `MAX()+1` employee-number generation despite an existing sequence — HIGH [confirmed]

**Files:** `plsql/packages/PKG_EMPLOYEE.pkb:34-55`; `schema/sequences/hrms_sequences.sql:18-21`

```sql
-- BUG: race condition under concurrent inserts - no SELECT FOR UPDATE
SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
INTO v_max_num
FROM EMPLOYEES
WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
```

**Issue:** Two concurrent hires read the same maximum and derive the same `EMP-NNNNNN`. `SEQ_EMP_NUMBER` exists precisely for this and is used only in the exception fallback (line 54, and it draws from `SEQ_EMPLOYEE`, not `SEQ_EMP_NUMBER`). `UK_EMP_NUMBER` turns the race into a hard insert failure rather than corruption — the failure surfaces to the Forms user mid-transaction, after `HRMS_EMPLOYEE.xml:323-333` has already assigned `EMP_ID`.

**Impact:** Duplicate-key failures during concurrent onboarding; the full table scan also grows linearly with headcount.

**Recommendation:** Generate from `SEQ_EMP_NUMBER` (`'EMP-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0')`) and delete the `MAX()` path.

### RC-02 — Leave balance check-then-write has no lock (TOCTOU) — HIGH [confirmed]

**File:** `plsql/packages/PKG_LEAVE.pkb:146-182`

```sql
IF v_leave_type.ACCRUAL_FLAG = 'Y' THEN
    v_balance := get_leave_balance(p_emp_id, p_leave_type_id);
    IF v_balance < v_total_days THEN RAISE_APPLICATION_ERROR(-20201, ...); END IF;
END IF;
...
UPDATE LEAVE_BALANCES SET PENDING = PENDING + v_total_days ...
```

**Issue:** `get_leave_balance` (lines 369-387) is an unlocked `SELECT ... INTO` whose result decides whether the subsequent `INSERT`/`UPDATE` proceeds. Two requests submitted concurrently both pass the check and both add to `PENDING`.

**Impact:** Employees can exceed their entitlement; `LEAVE_BALANCES.AVAILABLE` (a generated column) can go negative with no constraint to stop it.

**Recommendation:** `SELECT ... FOR UPDATE` the balance row (or `MERGE` with a `CHECK (AVAILABLE >= 0)` constraint) before validating, and hold the lock through the `PENDING` update.

### RC-03 — Payroll period status read without a lock before dependent insert — MEDIUM [confirmed]

**File:** `plsql/packages/PKG_PAYROLL.pkb:232-263`

```sql
SELECT STATUS INTO v_status FROM PAY_PERIODS WHERE PERIOD_ID = p_period_id;
IF v_status = 'CLOSED' THEN RAISE_APPLICATION_ERROR(-20102, ...); END IF;
SELECT SEQ_PAYROLL_RUN.NEXTVAL INTO v_run_id FROM DUAL;
INSERT INTO PAYROLL_RUNS (...);
```

**Issue:** The period can be closed by another session between the check and the insert. Contrast `approve_payroll` (lines 560-564), which correctly uses `FOR UPDATE`.

**Impact:** Payroll runs created against a closed period, bypassing period-close controls.

**Recommendation:** Add `FOR UPDATE` to the `PAY_PERIODS` read, or enforce the rule with a trigger/constraint on `PAYROLL_RUNS`.

### RC-04 — `reverse_payroll` performs no status check and takes no lock — MEDIUM [confirmed]

**File:** `plsql/packages/PKG_PAYROLL.pkb:583-600`

```sql
UPDATE PAYROLL_RUNS SET STATUS = 'REVERSED', ... WHERE RUN_ID = p_run_id;
UPDATE PAYROLL_DETAILS SET STATUS = 'REVERSED' WHERE RUN_ID = p_run_id;
```

**Issue:** Unlike `approve_payroll`, there is no state-machine guard: a run in any status (including `PAID` or already `REVERSED`) can be reversed, repeatedly and concurrently, and `p_reason` is accepted but never stored.

**Impact:** Irreversible payroll state changes with no recorded justification; concurrent reversal/approval can interleave.

**Recommendation:** Lock the run, allow reversal only from permitted statuses, persist `p_reason`, and pass old/new values to `PKG_AUDIT`.

### RC-05 — Balance updates silently affect zero rows — MEDIUM [confirmed]

**File:** `plsql/packages/PKG_LEAVE.pkb:176-182`, `241-248`, `354-360`

**Issue:** `submit_leave_request`, `approve_leave_request` and `cancel_leave_request` update `LEAVE_BALANCES` filtered on `CALENDAR_YEAR = EXTRACT(YEAR FROM ... START_DATE)` without checking `SQL%ROWCOUNT`. If no row exists for that employee/type/year — or the request spans a year boundary — the balance change is simply lost while the request itself succeeds. `adjust_leave_balance` (lines 408-419) shows the intended pattern of checking and initializing.

**Impact:** `LEAVE_REQUESTS` and `LEAVE_BALANCES` drift apart permanently; year-end requests consume no balance.

**Recommendation:** Check `SQL%ROWCOUNT`, call `initialize_balances` and retry, and split multi-year requests across the correct calendar years.

### RC-06 — Interim commits leave batch jobs non-atomic — LOW [confirmed]

**Files:** `plsql/packages/PKG_PAYROLL.pkb:322-326`; `plsql/packages/PKG_LEAVE.pkb:542-548`

```sql
-- Commit every 50 employees to avoid long transactions
-- ISSUE: Partial commits mean a failure leaves payroll half-calculated
IF MOD(v_emp_count, 50) = 0 THEN COMMIT; END IF;
```

**Issue:** Both payroll calculation and monthly accrual commit mid-loop with no restart marker, and the accrual counter increments per employee regardless of whether any accrual occurred.

**Impact:** A mid-run failure leaves a partially calculated payroll or partially accrued month, and re-running double-accrues the employees already processed.

**Recommendation:** Make batches restartable — track per-employee processing state, and make re-runs idempotent (`MERGE` keyed on run/period/employee).

---

## Performance findings

### PERF-01 — Day-by-day loop with a query per day for business-day counting — HIGH [confirmed]

**File:** `plsql/packages/PKG_LEAVE.pkb:12-40`

```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count FROM HOLIDAYS WHERE HOLIDAY_DATE = v_date ...
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Issue:** One context switch and one `HOLIDAYS` query per weekday in the range. Called on every leave submission and indirectly from reporting paths.

**Impact:** A one-month request issues ~22 round trips; annual/report-wide use multiplies this by employee count.

**Recommendation:** Replace with a single set-based query (generate the date range with `CONNECT BY LEVEL` or a calendar table and left-join `HOLIDAYS` once), or cache holidays in a package-level collection.

### PERF-02 — Duplicate business-day logic in `PKG_COMMON` that ignores holidays — MEDIUM [confirmed]

**File:** `plsql/packages/PKG_COMMON.pkb:132-165`

**Issue:** `business_days_between` and `add_business_days` use the same day-by-day loops but skip only weekends — they never consult `HOLIDAYS`. Two functions in two packages now answer "how many business days" differently.

**Impact:** SLA/notification dates computed from `PKG_COMMON` disagree with leave durations computed by `PKG_LEAVE`.

**Recommendation:** Delete the duplicates and have all callers use one holiday-aware, set-based implementation.

### PERF-03 — A new SMTP connection is opened per notification — HIGH [confirmed]

**File:** `plsql/packages/PKG_NOTIFICATION.pkb:78-135`

```sql
FOR notif_rec IN (... FETCH FIRST p_batch_size ROWS ONLY) LOOP
    v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
    ...
    UTL_SMTP.QUIT(v_connection);
```

**Issue:** Connection setup/teardown happens inside the loop, so a 50-message batch performs 50 TCP handshakes and 50 SMTP sessions; each is a synchronous network wait inside the scheduler job.

**Impact:** Queue drain time is dominated by connection latency, and a slow mail host can make the 5-minute job overlap itself. There is also no rate limiting (noted in `PKG_NOTIFICATION.pks`).

**Recommendation:** Open one connection per batch, reuse it across recipients, and add a retry cap driven by `RETRY_COUNT`.

### PERF-04 — Row-by-row payroll and accrual processing — MEDIUM [confirmed]

**Files:** `plsql/packages/PKG_PAYROLL.pkb:266-327`, `353-543`; `plsql/packages/PKG_LEAVE.pkb:459-552`

**Issue:** `calculate_payroll` loops employees and calls `calculate_employee_pay`, which itself issues 5-10 single-row `INSERT`s plus a full-year YTD aggregation (`get_ytd_earnings`, line 414) per employee. Accrual nests a leave-type loop inside an employee loop with a balance query per pair. The source itself flags this at lines 266-269.

**Impact:** Payroll runtime scales as employees × elements with no batching; at 200 employees the aggregate re-reads `PAYROLL_DETAILS` 200 times.

**Recommendation:** Convert to set-based `INSERT ... SELECT` per element type with `FORALL` fallbacks, and compute YTD once per run into a temporary/materialized structure.

### PERF-05 — `CONNECT BY` org hierarchy with a documented ceiling — MEDIUM [confirmed]

**Files:** `schema/views/hrms_views.sql:42-57`; `plsql/packages/PKG_EMPLOYEE.pkb:828-835`

```sql
-- WARNING: Performance degrades significantly with >500 employees
... SYS_CONNECT_BY_PATH(FIRST_NAME || ' ' || LAST_NAME, ' > ') AS ORG_PATH,
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
```

**Issue:** Hierarchy plus `SYS_CONNECT_BY_PATH` string building is evaluated on every read, with no result caching and no `NOCYCLE` guard.

**Impact:** Org-chart screens and reports degrade as headcount approaches the documented limit; a manager loop raises `ORA-01436` for all consumers.

**Recommendation:** Add `NOCYCLE`, index `MANAGER_EMP_ID`, and materialize the hierarchy (materialized view refreshed on change) for read-heavy screens.

### PERF-06 — `NOCACHE` on every sequence except `SEQ_AUDIT` — MEDIUM [confirmed]

**File:** `schema/sequences/hrms_sequences.sql:9-49`

```sql
CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
...
CREATE SEQUENCE HRMS.SEQ_AUDIT START WITH 1 INCREMENT BY 1 CACHE 100;
```

**Issue:** 24 of 25 sequences are `NOCACHE`, forcing a recursive dictionary update per `NEXTVAL`. High-volume generators (`SEQ_PAYROLL_DETAIL`, `SEQ_NOTIFICATION`, `SEQ_LEAVE_BALANCE`) are the worst affected.

**Impact:** `SQ` enqueue contention and row-cache latch pressure during payroll runs; measurable throughput loss with 200 concurrent users.

**Recommendation:** Set `CACHE 100-1000` on high-volume sequences (gaps are acceptable for surrogate keys) and document why any sequence must remain `NOCACHE`.

### PERF-07 — Per-employee YTD aggregation inside the payroll loop — LOW [confirmed]

**File:** `plsql/packages/PKG_PAYROLL.pkb:414`, `802-819`

**Issue:** `get_ytd_earnings` aggregates `PAYROLL_DETAILS` joined to `PAYROLL_RUNS` and `PAY_PERIODS` for the whole year, once per employee per run, with no supporting composite index defined in `schema/`.

**Impact:** Repeated large aggregations during the run's critical window.

**Recommendation:** Compute YTD for all employees in one pass; add an index on `PAYROLL_DETAILS(EMP_ID, ELEMENT_TYPE, STATUS)`.

---

## Validation drift findings

### VAL-01 — Future hire-date limit differs across three layers — HIGH [confirmed]

**Files:** `forms/xml-exports/HRMS_EMPLOYEE.xml:382-386`; `plsql/triggers/trg_employees.sql:34-38`; `plsql/packages/PKG_EMPLOYEE.pkb` (no equivalent check)

```sql
-- Forms
IF :EMPLOYEE.HIRE_DATE > SYSDATE + 90 THEN
    MESSAGE('Hire date cannot be more than 90 days in the future');
-- Trigger
IF :NEW.HIRE_DATE > SYSDATE + 180 THEN
    RAISE_APPLICATION_ERROR(-20501, 'Hire date cannot be more than 180 days in the future');
```

**Issue:** Forms enforces 90 days, the trigger 180, and the package layer none. Any non-Forms path (batch load, integration, direct package call) silently accepts 91-180 days.

**Impact:** Inconsistent business rule; data entered via one channel is rejected when edited through another.

**Recommendation:** Define the window once in `SYSTEM_PARAMETERS`, enforce it in `PKG_VALIDATION`, and have both Forms and the trigger call that single function.

### VAL-02 — Client and server e-mail validation disagree — MEDIUM [confirmed]

**Files:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:14-41`; `plsql/packages/PKG_COMMON.pkb:265-268`; `plsql/packages/PKG_VALIDATION.pkb:50-55`

```sql
-- client
v_dot_pos := INSTR(p_email, '.', v_at_pos);
IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN RETURN FALSE;
-- server
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

**Issue:** The client check is positional and, per its own comment, rejects addresses whose only dot placement it does not expect, while accepting strings the server regex rejects (e.g. spaces before `@`). The two implementations can drift further with no test to detect it.

**Impact:** Valid corporate addresses (subdomains) are blocked in Forms; invalid addresses reach the server layer and depend on it alone.

**Recommendation:** Have the PLL call `PKG_VALIDATION.validate_email_format` so there is exactly one rule.

### VAL-03 — Client SSN/phone validation accepts alphabetic input — MEDIUM [confirmed]

**Files:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:47-90`; `plsql/packages/PKG_COMMON.pkb:270-280`

```sql
-- client
v_digits := TRANSLATE(p_ssn, '0123456789-', '0123456789');
IF LENGTH(v_digits) != 9 THEN RETURN FALSE; END IF;
-- server
RETURN REGEXP_LIKE(REGEXP_REPLACE(p_ssn, '[^0-9]', ''), '^\d{9}$');
```

**Issue:** `TRANSLATE` only removes the characters listed in the *from* string; letters are left untouched and counted, so a nine-letter string passes the client check. The server correctly strips all non-digits first. The same pattern appears in `validate_phone`.

**Impact:** Non-numeric identifiers pass client validation and produce confusing server-side rejections — or are stored if a code path skips the server check.

**Recommendation:** Delegate both functions to the server-side validators; if a client-only variant is required, use `REGEXP_LIKE` with an explicit digit pattern.

### VAL-04 — Client salary validation comment contradicts the code — LOW [confirmed]

**File:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:101-135`

```sql
-- BUG: Uses a hard-coded cache that's populated at form startup
-- and never refreshed. ...
    -- Direct DB query (not cached - contradicts the comment above)
    SELECT MIN_SALARY, MAX_SALARY INTO v_min, v_max FROM JOB_GRADES WHERE GRADE_ID = p_grade_id;
```

**Issue:** The stale-cache defect described in the header does not exist in this code; the function queries `JOB_GRADES` live. It does, however, return a differently worded message than `PKG_VALIDATION.validate_salary_for_grade` (`plsql/packages/PKG_VALIDATION.pkb:17-48`) and omits the grade name.

**Impact:** Misleading documentation drives incorrect remediation; users see two different messages for the same rule.

**Recommendation:** Delete the inaccurate comment and call the server-side validator so message text and thresholds come from one place.

### VAL-05 — `validate_required_fields` claims dictionary-driven behavior but hard-codes one table — LOW [confirmed]

**File:** `plsql/packages/PKG_VALIDATION.pkb:99-122`

```sql
-- Simplified validation - in production would use data dictionary
-- to check NOT NULL columns
IF p_table_name = 'EMPLOYEES' THEN ... END IF;
RETURN NULL;
```

**Issue:** Every table other than `EMPLOYEES` returns `NULL`, i.e. "valid". The repository also has **no `DATA_DICTIONARY.md`**, so column semantics can only be cross-referenced against DDL comments.

**Impact:** Callers believe required-field validation ran when it did not.

**Recommendation:** Drive the check from `ALL_TAB_COLUMNS.NULLABLE`, or restrict the signature to the tables actually supported.

### VAL-06 — Half-day flag overrides the entire date range — MEDIUM [confirmed]

**Files:** `plsql/packages/PKG_LEAVE.pkb:128-138`; `schema/tables/03_leave_tables.sql:63-91`; `forms/xml-exports/HRMS_LEAVE.xml:121-125`, `152-160`

```sql
IF p_half_day_flag = 'Y' THEN
    v_total_days := 0.5;
ELSE
    v_total_days := calculate_business_days(p_start_date, p_end_date, v_emp_rec.LOCATION_CODE);
END IF;
```

**Issue:** Nothing constrains `START_DATE = END_DATE` when `HALF_DAY_FLAG = 'Y'`. The table check constraints only bound `END_DATE >= START_DATE` and the AM/PM domain, and the Forms layer exposes the flag alongside a free date range.

**Impact:** A two-week request flagged half-day deducts 0.5 days; balances and manager calendars understate absence.

**Recommendation:** Reject `HALF_DAY_FLAG = 'Y'` when the dates differ (package check plus a table-level `CHECK`), and derive `TOTAL_DAYS` accordingly.

### VAL-07 — Overlap detection ignores half-day periods — LOW [confirmed]

**File:** `plsql/packages/PKG_LEAVE.pkb:45-60`

**Issue:** `check_leave_overlap` compares only dates and status, so an AM half-day and a PM half-day on the same date are treated as a conflict, while a full-day request over an existing half-day is treated identically to a full overlap.

**Impact:** Legitimate half-day pairs are rejected; the half-day feature is unusable for split days.

**Recommendation:** Include `HALF_DAY_FLAG`/`HALF_DAY_PERIOD` in the overlap predicate.

---

## Architecture findings

### ARCH-01 — Declared circular package dependency; the code shows a one-way edge — MEDIUM [confirmed / inferred]

**Files:** `plsql/packages/PKG_EMPLOYEE.pks:6-9`; `plsql/packages/PKG_PAYROLL.pks:6-9`; `plsql/packages/PKG_EMPLOYEE.pkb:273`; `plsql/packages/PKG_SECURITY.pkb:75`; `README.md:127`

```sql
-- PKG_EMPLOYEE.pks
--   - Circular dependency with PKG_PAYROLL (salary validation)
-- PKG_PAYROLL.pks
--   - Circular dependency with PKG_EMPLOYEE (is_active check)
```

**Issue:** Both specs declare the cycle, but in the current bodies only `PKG_EMPLOYEE → PKG_PAYROLL` exists (5 references, e.g. line 273 `-- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record`); `PKG_PAYROLL.pkb` references only `PKG_COMMON` and `PKG_AUDIT`. A second latent cycle is closer: `PKG_SECURITY.pkb:75` calls `PKG_EMPLOYEE.set_session_context`, and `PKG_EMPLOYEE.pkb:738` carries `-- TODO: Revoke system access via PKG_SECURITY`, which would close it.

**Impact:** Spec-declared cycles already force lock-step recompilation and invalidate dependents on any change; implementing the outstanding TODOs would create a true body-level cycle.

**Recommendation:** Extract the shared primitives (salary record creation, session context) into a lower layer that both packages depend on, and fix the spec headers to describe actual dependencies.

### ARCH-02 — Autonomous transactions commit independently of the business transaction — HIGH [confirmed]

**Files:** `plsql/packages/PKG_AUDIT.pkb:6-31`; `plsql/packages/PKG_EMPLOYEE.pkb:137-179`; `plsql/packages/PKG_NOTIFICATION.pkb:16-63`; `plsql/packages/PKG_COMMON.pkb:16`, `46`; `plsql/triggers/trg_audit.sql:32-39`

```sql
PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
    INSERT INTO AUDIT_LOG (...);
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK;   -- audit failure is invisible
```

**Issue:** Audit rows, employee history, notifications and error logs each commit in their own transaction, invoked from row triggers and package procedures. If the parent transaction rolls back, those records survive.

**Impact:** Audit trail and history assert changes that never happened (and vice versa, per DI-02), notifications are sent for rolled-back actions, and every call adds a commit to hot paths.

**Recommendation:** Keep audit/history in the parent transaction (they are part of the business fact), or write to a queue table committed by the parent and drained asynchronously. Reserve autonomous transactions for genuine fire-and-forget logging with its own alerting.

### ARCH-03 — Flat-file integration via `UTL_FILE` with no retry or acknowledgement — HIGH [confirmed]

**Files:** `plsql/packages/PKG_INTEGRATION.pkb:6-9`, `16-80`, `94-143`; `plsql/packages/PKG_PAYROLL.pkb:826-894`; `plsql/packages/PKG_INTEGRATION.pks:8-13`

```sql
c_gl_output_dir       CONSTANT VARCHAR2(30) := 'GL_FEED_OUT';
c_benefits_output_dir CONSTANT VARCHAR2(30) := 'BENEFITS_FEED_OUT';
c_time_input_dir      CONSTANT VARCHAR2(30) := 'TIME_ATTENDANCE_IN';
```

**Issue:** GL journals, benefits feeds, pay registers and time imports all move as delimited files written from PL/SQL, with directory names compiled in, no checksum/manifest, no idempotency key and — per the spec header — no retry logic for failed transfers. CSV fields are concatenated without escaping (`PKG_PAYROLL.pkb:869-880`), so a comma or quote in a name corrupts the row.

**Impact:** Silent partial financial feeds; a re-run produces a second file with no way for the consumer to detect duplication.

**Recommendation:** Move to an acknowledged transport (queue/REST/DB link) with a transfer log, per-file idempotency keys, and a proper CSV writer (or `APEX_DATA_EXPORT`-style escaping) in the interim.

### ARCH-04 — Stub implementations that report success — HIGH [confirmed]

**Files:** `plsql/packages/PKG_INTEGRATION.pkb:153-203`; `plsql/packages/PKG_REPORTING.pkb:200`; `plsql/packages/PKG_PAYROLL.pkb:784-785`; `plsql/packages/PKG_SECURITY.pkb:230-233`; `plsql/packages/PKG_EMPLOYEE.pkb:737-739`

```sql
IF v_line IS NOT NULL AND SUBSTR(v_line, 1, 1) != '#' THEN
    -- Parse CSV: emp_number,date,hours_regular,hours_overtime
    -- TODO: Implement actual parsing and database update
    v_imported := v_imported + 1;
END IF;
...
PKG_COMMON.log_info('PKG_INTEGRATION', 'import_time_attendance',
    'Imported: ' || v_imported || ', Errors: ' || v_errors, p_user);
```

**Issue:** `import_time_attendance` counts lines, stores nothing, and logs an import summary that implies success. `sync_org_structure` (196-203) logs `'Org structure sync completed'` while doing nothing. `get_payslip` returns `0 AS YTD_GROSS`/`0 AS YTD_NET` placeholders. `change_password` is a stub (SEC-04). `terminate_employee` leaves COBRA, access revocation and final pay as TODOs.

**Impact:** Operators cannot distinguish "worked" from "did nothing"; timesheet hours are never applied to pay, and payslips display zero YTD figures to employees.

**Recommendation:** Make unimplemented paths fail loudly (`RAISE_APPLICATION_ERROR` with an explicit "not implemented"), and track the missing functionality as work items rather than silent no-ops.

### ARCH-05 — Hard-coded 2024 tax constants while a `TAX_BRACKETS` table exists — MEDIUM [confirmed]

**Files:** `plsql/packages/PKG_PAYROLL.pkb:602-686`, `688-738`; `schema/tables/02_payroll_tables.sql:159-176`

```sql
-- 2024 Federal tax brackets (Single)
-- TODO: Read from TAX_BRACKETS table instead of hard-coding
IF v_taxable <= 11600 THEN v_tax := v_taxable * 0.10;
ELSIF v_taxable <= 47150 THEN v_tax := 1160 + (v_taxable - 11600) * 0.12;
```

**Issue:** Bracket boundaries, standard deductions, allowance amounts and flat state rates are literals in the package body, even though `TAX_BRACKETS` and `SEQ_TAX_BRACKET` exist for exactly this. `MARRIED_JOINT`/`SINGLE`/`MARRIED_SEPARATE` are the only handled statuses — any other value yields `v_tax := 0`.

**Impact:** Every tax-year change is a code deployment; unhandled filing statuses under-withhold to zero, which is a compliance exposure.

**Recommendation:** Load brackets from `TAX_BRACKETS` keyed by tax year and filing status, and raise on an unknown status instead of returning zero.

### ARCH-06 — Payroll element identity hard-coded as numeric literals — MEDIUM [confirmed]

**Files:** `plsql/packages/PKG_PAYROLL.pkb:405-499`, `776-796`, `849-860`; `data/seed/01_reference_data.sql:122-153`; `schema/tables/02_payroll_tables.sql:37-62`

```sql
SEQ_PAYROLL_DETAIL.NEXTVAL, p_run_id, p_emp_id, 100, 'TAX', -v_federal_tax, ...
...
SUM(CASE WHEN pd.ELEMENT_ID = 102 THEN ABS(pd.AMOUNT) ELSE 0 END) AS SOCIAL_SECURITY,
```

**Issue:** Base pay (`1`), federal tax (`100`), state tax (`101`), FICA (`102`) and Medicare (`103`) are literals in inserts, payslip queries and the pay register, while `PAY_ELEMENTS.ELEMENT_CODE` exists as the stable business key.

**Impact:** Reseeding or migrating reference data with different IDs silently mis-labels tax amounts on payslips and statutory reports.

**Recommendation:** Resolve element IDs by `ELEMENT_CODE` once per run (or use a package-level constant map validated at startup).

### ARCH-07 — Fiscal calendar hard-coded to an October start — LOW [confirmed]

**File:** `plsql/packages/PKG_COMMON.pkb:167-195`

**Issue:** `get_fiscal_year`/`get_fiscal_quarter` embed an October-to-September fiscal calendar with no configuration, while payroll and leave logic key off `EXTRACT(YEAR FROM ...)` calendar years.

**Impact:** Two competing year definitions across reporting; a fiscal-calendar change requires code edits.

**Recommendation:** Store the fiscal start month in `SYSTEM_PARAMETERS` and derive both functions from it.

### ARCH-08 — JSON audit payloads built by string concatenation — LOW [confirmed]

**Files:** `plsql/triggers/trg_audit.sql:18-30`, `51-58`; `plsql/packages/PKG_COMMON.pkb` (`log_error` payload)

```sql
v_new_json := '{"emp_id":' || :NEW.EMP_ID ||
              ',"salary":' || :NEW.BASE_SALARY ||
              ',"effective":"' || TO_CHAR(:NEW.EFFECTIVE_DATE, 'YYYY-MM-DD') || '"}';
```

**Issue:** Values are interpolated without escaping and numbers are formatted with session NLS settings, so a decimal comma or a quote in text produces invalid JSON.

**Impact:** Audit payloads that downstream tooling cannot parse; NLS-dependent output.

**Recommendation:** Use `JSON_OBJECT`/`JSON_SERIALIZE` (available on 19c).

### ARCH-09 — Termination leaves security, benefits and final pay unhandled — MEDIUM [confirmed]

**File:** `plsql/packages/PKG_EMPLOYEE.pkb:737-739`

```sql
-- TODO: Integrate with benefits system to trigger COBRA
-- TODO: Revoke system access via PKG_SECURITY
-- TODO: Calculate final pay via PKG_PAYROLL.calculate_final_pay
```

**Issue:** The termination workflow updates employment status only. Access revocation, COBRA notification and final pay are manual.

**Impact:** Terminated employees retain system access (compounding SEC-09) and statutory benefit/pay obligations depend on manual follow-up.

**Recommendation:** Implement the three steps inside the termination transaction with explicit failure handling, and add a reconciliation report for terminated-but-active accounts.

### ARCH-10 — No tests, no build, and folklore workarounds in shared library code — LOW [confirmed]

**Files:** `forms/libraries/HRMS_COMMON_LIB.pll.sql:32-35`; repository root (no test directory, no build manifest); `README.md`

```sql
MESSAGE(p_module || '.' || p_location || ': ' || v_errmsg);
MESSAGE(p_module || '.' || p_location || ': ' || v_errmsg);
-- NOTE: MESSAGE called twice intentionally - Oracle Forms requires
-- two calls to ensure message displays on the status bar
```

**Issue:** The global error handler duplicates a call as a workaround, and the repository contains no automated verification of any kind — so every mismatch in this report can only be found by reading the code or by production failure.

**Impact:** No regression safety net for a system handling payroll and PII.

**Recommendation:** Add utPLSQL with a compile-and-test CI job (schema deploy + unit tests on the pure functions first: tax, business days, validation), and replace the doubled `MESSAGE` with `SYNCHRONIZE`-based handling.

---

## Data integrity findings

### DI-01 — `TRG_EMP_BEFORE_UPDATE` inserts `EMPLOYEE_HISTORY` columns that do not exist — CRITICAL [confirmed]

**Files:** `plsql/triggers/trg_employees.sql:76-110`; `schema/tables/01_core_tables.sql:152-177`; `plsql/packages/PKG_EMPLOYEE.pkb:157-169`

```sql
-- trigger
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (
    SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'DEPARTMENT_CHANGE', SYSDATE, ...
```

```sql
-- actual DDL
CREATE TABLE HRMS.EMPLOYEE_HISTORY (
    HIST_ID NUMBER(15) NOT NULL, EMP_ID NUMBER(10) NOT NULL,
    CHANGE_TYPE VARCHAR2(30) NOT NULL, EFFECTIVE_DATE DATE NOT NULL,
    OLD_DEPT_ID ..., NEW_DEPT_ID ..., OLD_SALARY ..., NEW_SALARY ...,
    REASON_CODE VARCHAR2(30), COMMENTS VARCHAR2(4000),
    CREATED_BY VARCHAR2(30) NOT NULL, CREATED_DATE DATE ...,
    CONSTRAINT CHK_CHANGE_TYPE CHECK (CHANGE_TYPE IN (
        'HIRE','TRANSFER','PROMOTION','DEMOTION','SALARY_CHANGE',
        'TERMINATION','REHIRE','LEAVE_START','LEAVE_END','STATUS_CHANGE'))
);
```

**Issue:** Six of the eight columns the trigger writes (`HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON`) do not exist, and `CREATED_BY`/`CREATED_DATE` (`NOT NULL`) are never supplied. The trigger therefore fails to compile, so on a real deployment **every `UPDATE` on `EMPLOYEES` fails with `ORA-04098`** (invalid trigger). Even with the column names fixed, two of the three change types it writes — `'DEPARTMENT_CHANGE'` and `'JOB_CHANGE'` — violate `CHK_CHANGE_TYPE`. `PKG_EMPLOYEE.log_history` (lines 157-169) writes the same table **correctly**, which is how the mismatch went unnoticed: the package path works, the trigger path never could.

**Impact:** Employee maintenance is broken at the database level, or (if the trigger was never deployed) status/department/job changes made outside `PKG_EMPLOYEE` are unaudited. Both the trigger and the package log history, so fixing the trigger naively would double-write.

**Recommendation:** Delete the history inserts from the trigger and rely on `PKG_EMPLOYEE.log_history` (single writer), or rewrite them against the real DDL with allowed `CHANGE_TYPE` values. Add a deployment gate that fails on any invalid object in `USER_OBJECTS`.

### DI-02 — Leave audit rows are silently rejected and discarded — CRITICAL [confirmed]

**Files:** `plsql/triggers/trg_audit.sql:47-59`; `schema/tables/04_performance_tables.sql:92-105`; `plsql/packages/PKG_AUDIT.pkb:6-31`

```sql
-- trigger passes a 13-character action
PKG_AUDIT.log_action('LEAVE_REQUESTS', :NEW.REQUEST_ID, 'STATUS_CHANGE', ...);
-- target column
ACTION_TYPE VARCHAR2(10) NOT NULL,
CONSTRAINT CHK_AUDIT_ACTION CHECK (ACTION_TYPE IN ('INSERT', 'UPDATE', 'DELETE'))
-- and the writer swallows the failure
EXCEPTION WHEN OTHERS THEN ROLLBACK;
```

**Issue:** `'STATUS_CHANGE'` exceeds `VARCHAR2(10)` **and** violates `CHK_AUDIT_ACTION`. Because `PKG_AUDIT.log_action` is an autonomous transaction with a bare `WHEN OTHERS THEN ROLLBACK`, the insert fails with no error, no log entry and no signal to the caller. Every leave approval/rejection/cancellation is therefore unaudited, while the surrounding business transaction succeeds.

**Impact:** A permanent, silent gap in the compliance audit trail for the entire leave module — the one place where approvals must be provable.

**Recommendation:** Use `'UPDATE'` (with the status delta in `OLD_VALUES`/`NEW_VALUES`) or widen the column and extend the check constraint; and replace the swallowing handler with a write to a fallback error table plus alerting.

### DI-03 — Run control totals exclude benefit deductions that payslips include — HIGH [confirmed]

**Files:** `plsql/packages/PKG_PAYROLL.pkb:329-344`, `771-796`, `849-860`; `schema/views/hrms_views.sql:109-129`

```sql
TOTAL_DEDUCTIONS = (SELECT NVL(SUM(ABS(AMOUNT)), 0) FROM PAYROLL_DETAILS
                    WHERE RUN_ID = p_run_id AND ELEMENT_TYPE IN ('DEDUCTION', 'TAX') ...),
TOTAL_NET = (SELECT NVL(SUM(CASE WHEN ELEMENT_TYPE = 'EARNING' THEN AMOUNT
                                 WHEN ELEMENT_TYPE IN ('DEDUCTION', 'TAX') THEN -ABS(AMOUNT)
                                 ELSE 0 END), 0) ...)
```

**Issue:** `calculate_employee_pay` writes benefit deductions with `ELEMENT_TYPE = 'BENEFIT'` (line 537, sourced from `PAY_ELEMENTS` where the cursor at 502-514 selects `'DEDUCTION','BENEFIT'`). The run-total rollup counts only `DEDUCTION` and `TAX`, mapping `BENEFIT` to `0` — while `get_payslip` (777-779), `generate_pay_register` (858-860) and `VW_PAYROLL_LATEST` (115-116) all include `BENEFIT` and compute net as `SUM(AMOUNT)`.

**Impact:** `PAYROLL_RUNS.TOTAL_NET`/`TOTAL_DEDUCTIONS` overstate net pay by the benefit total, so the run's control figures do not reconcile with payslips, the pay register, or the GL feed derived from the details.

**Recommendation:** Define net once — `SUM(AMOUNT)` over non-error details — and use it in the rollup, the views and the file writers. Add a post-run assertion that the rollup equals the sum of per-employee nets.

### DI-04 — YTD figures include the period being calculated — HIGH [confirmed]

**File:** `plsql/packages/PKG_PAYROLL.pkb:404-414`, `713-760`, `802-819`

```sql
INSERT INTO PAYROLL_DETAILS (... ELEMENT_ID, ELEMENT_TYPE, AMOUNT, STATUS ...)
VALUES (..., 1, 'EARNING', v_period_gross, 'CALCULATED', ...);

-- Get YTD gross for tax calculations
v_ytd_gross := get_ytd_earnings(p_emp_id, EXTRACT(YEAR FROM v_period_end));
```

**Issue:** The current period's earning row is inserted (line 405-411) *before* YTD is queried (line 414), and `get_ytd_earnings` counts every `CALCULATED` earning row for the year — including the one just written. `calculate_fica` and `calculate_medicare` then add `p_gross_pay` to that YTD again when testing the wage base and the additional-Medicare threshold.

**Impact:** The Social Security wage base and the additional Medicare threshold are reached roughly one period early, producing incorrect statutory withholding. `get_ytd_earnings` also ignores run status, so details from `ERROR`-status runs and recalculated runs accumulate.

**Recommendation:** Compute YTD before writing any detail rows for the run (excluding the current run explicitly), and restrict the aggregate to approved/paid runs.

### DI-05 — `PRETAX_FLAG` is fetched and never applied — HIGH [confirmed]

**File:** `plsql/packages/PKG_PAYROLL.pkb:436-437`, `502-514`

```sql
v_taxable_income := v_period_gross; -- Simplified; should subtract pretax deductions
...
SELECT epe.ELEMENT_ID, ..., pe.PRETAX_FLAG
FROM EMPLOYEE_PAY_ELEMENTS epe JOIN PAY_ELEMENTS pe ...
```

**Issue:** Taxable income is set to gross pay before deductions are processed, and although the deduction cursor selects `PRETAX_FLAG`, the flag is never referenced in the loop body (516-542). 401(k) and pretax benefit contributions therefore do not reduce taxable wages.

**Impact:** Systematic over-withholding of federal and state tax for every employee with pretax deductions, and incorrect taxable-wage figures for statutory reporting.

**Recommendation:** Process deductions first, accumulate the pretax total, and compute `v_taxable_income := v_period_gross - v_pretax_total` before the tax calls. Add a unit test asserting the reduction.

### DI-06 — `VW_LEAVE_SUMMARY.AVAILABLE` omits `PENDING` — HIGH [confirmed]

**Files:** `schema/views/hrms_views.sql:86-103`; `schema/tables/03_leave_tables.sql:37-58`; `plsql/packages/PKG_LEAVE.pkb:369-387`; `forms/xml-exports/HRMS_LEAVE.xml:180-189`

```sql
-- view
lb.PENDING,
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,
-- table (generated column)
AVAILABLE NUMBER(6,2) GENERATED ALWAYS AS
  (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL,
-- package
SELECT OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING INTO v_balance ...
```

**Issue:** The view displays `PENDING` as a separate column and then omits it from `AVAILABLE`, contradicting both the table's generated column and the function used for enforcement. `UTILIZATION_PCT` likewise ignores `ADJUSTMENT`.

**Impact:** Reports and any Forms/report consumer of the view over-report available days by the pending amount, so employees see balances the enforcement layer will refuse.

**Recommendation:** Select the table's generated `AVAILABLE` column in the view rather than recomputing it, and add a test comparing view output with `get_leave_balance`.

### DI-07 — `expire_carryover` subtracts carryover that was already used — MEDIUM [confirmed]

**File:** `plsql/packages/PKG_LEAVE.pkb:605-623`

```sql
-- BUG: If run twice on same day, can double-subtract
UPDATE LEAVE_BALANCES SET
    ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
    CARRYOVER_FROM_PREV = 0, ...
WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE) AND CARRYOVER_FROM_PREV > 0;
```

**Issue:** The header comment's claim is **not reproducible**: the predicate requires `CARRYOVER_FROM_PREV > 0` and the same statement zeroes it, so a second run matches no rows. The real defect is different — the full original carryover is deducted regardless of how much of it the employee already took, because usage is tracked in `USED` and never netted against `CARRYOVER_FROM_PREV`. An employee who used all 5 carryover days loses another 5 days at expiry.

**Impact:** Employees who use their carryover before expiry are penalized twice; balances can go negative.

**Recommendation:** Track carryover consumption explicitly (e.g. a `CARRYOVER_USED` column) and expire only the unused remainder; correct the misleading comment.

### DI-08 — `process_carryover` overwrites opening balance and leaves the source year intact — MEDIUM [confirmed]

**File:** `plsql/packages/PKG_LEAVE.pkb:558-603`

```sql
UPDATE LEAVE_BALANCES SET
    CARRYOVER_FROM_PREV = v_carryover,
    OPENING_BALANCE = v_carryover, ...
WHERE ... AND CALENDAR_YEAR = v_next_year;
```

**Issue:** `OPENING_BALANCE` is assigned (not added), so any pre-existing opening balance for the new year is discarded. The prior year's row is left with its full remaining balance, so the same days exist in both calendar years; combined with the 5-day backdating window (lines 120-126), an early-January request can consume them again.

**Impact:** Lost or duplicated entitlement at year end, depending on execution order.

**Recommendation:** Increment rather than assign, zero out (or close) the source-year remainder in the same transaction, and make the whole procedure idempotent per `(emp, type, year)`.

### DI-09 — Soft-delete trigger contradicts the Forms delete workflow — MEDIUM [confirmed]

**Files:** `plsql/triggers/trg_employees.sql:114-129`; `forms/xml-exports/HRMS_EMPLOYEE.xml:110-117`, `533-536`

```sql
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
BEFORE DELETE ON HRMS.EMPLOYEES
FOR EACH ROW
BEGIN
    -- BUG: This actually prevents deletion, but Forms expects DELETE to succeed.
    RAISE_APPLICATION_ERROR(-20504,
        'Direct deletion not allowed. Use termination process or set ACTIVE_FLAG to N.');
END;
```

**Issue:** The name and header comment describe an INSTEAD OF trigger that converts `DELETE` to a soft delete; the implementation is a `BEFORE DELETE` blocker. The employee block still has delete enabled and a confirmation alert, so the user confirms a deletion that always fails.

**Impact:** A guaranteed error path in a primary maintenance screen, and no actual soft-delete conversion anywhere.

**Recommendation:** Disable delete on the Forms block (or route it to the termination procedure), rename the trigger to match its behavior, and document the soft-delete convention (`ACTIVE_FLAG`/`EMPLOYMENT_STATUS`) in one place.

### DI-10 — `VW_PAYROLL_LATEST` picks the highest `RUN_ID`, not the latest period — MEDIUM [confirmed]

**File:** `schema/views/hrms_views.sql:105-129`

```sql
WHERE pr.RUN_ID = (SELECT MAX(pr2.RUN_ID) FROM PAYROLL_RUNS pr2 WHERE pr2.STATUS = 'APPROVED')
```

**Issue:** The subquery is global and status-only: it ignores `PERIOD_ID`, `RUN_TYPE` and `PAY_DATE`, so an off-cycle or bonus run approved after the regular run becomes "latest" for everyone, and employees absent from that run disappear from the view entirely. Runs in `PAID` status are excluded.

**Impact:** "Latest pay" screens and reports show off-cycle amounts as the current payslip, or nothing at all.

**Recommendation:** Rank per employee (`ROW_NUMBER() OVER (PARTITION BY EMP_ID ORDER BY pp.PERIOD_END_DATE DESC, pr.RUN_ID DESC)`) over regular runs in approved/paid status.

### DI-11 — Compensation view joins salary history without date bounds — MEDIUM [confirmed]

**File:** `schema/views/hrms_views.sql:59-80`, compare `32-35`

```sql
JOIN SALARY_RECORDS sr ON e.EMP_ID = sr.EMP_ID AND sr.ACTIVE_FLAG = 'Y'
...
ROUND(sr.BASE_SALARY / ((g.MIN_SALARY + g.MAX_SALARY) / 2) * 100, 1) AS COMPA_RATIO,
```

**Issue:** `VW_ACTIVE_EMPLOYEES` filters salary rows by `EFFECTIVE_DATE <= SYSDATE AND (END_DATE IS NULL OR END_DATE > SYSDATE)`; `VW_EMPLOYEE_COMPENSATION` filters only on `ACTIVE_FLAG`, so any employee with more than one active salary row is duplicated and a future-dated raise is reported as current. `COMPA_RATIO` divides by the grade midpoint with no `NULLIF`, and neither view filters `ACTIVE_FLAG` on `EMPLOYEES`.

**Impact:** Two "current salary" views that disagree; duplicated rows inflate headcount and total-compensation reporting; `ORA-01476` if a grade has zero min and max.

**Recommendation:** Apply identical effective-dating in both views (or build one shared `VW_CURRENT_SALARY`), wrap the divisor in `NULLIF`, and add `ACTIVE_FLAG = 'Y'` consistently.

### DI-12 — Insert trigger asserts an e-mail unique constraint that does not exist — MEDIUM [confirmed]

**Files:** `plsql/triggers/trg_employees.sql:40-54`; `schema/tables/01_core_tables.sql:134-142`

```sql
-- Validate email uniqueness (also enforced by unique constraint, but
-- this trigger provides a better error message)
SELECT COUNT(*) INTO v_count FROM EMPLOYEES
WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL) AND ACTIVE_FLAG = 'Y';
```

**Issue:** No unique constraint or index on `EMAIL` exists in the DDL, so the trigger is the only guard — and a row-level trigger querying its own table is unreliable: it works for single-row `INSERT ... VALUES` but raises `ORA-04091` (mutating table) for multi-row `INSERT ... SELECT` used by data loads. It is also inherently race-prone under concurrency, which is how duplicates reach the login path (SEC-10).

**Impact:** Duplicate active e-mails are possible; bulk employee loads fail with a mutating-table error.

**Recommendation:** Add a unique functional index on active e-mail and delete the trigger check (keeping a friendly message by trapping `DUP_VAL_ON_INDEX` in the package layer).

### DI-13 — Org hierarchy view leaks inactive managers into paths and has no cycle guard — LOW [confirmed]

**File:** `schema/views/hrms_views.sql:42-57`

**Issue:** The `WHERE EMPLOYMENT_STATUS = 'ACTIVE'` predicate is applied after the hierarchy is generated, so a terminated manager is removed from the result while their name remains inside `SYS_CONNECT_BY_PATH` for every subordinate, and subordinates are re-parented to nothing. `ACTIVE_FLAG` is not filtered at all, and there is no `NOCYCLE` despite the self-referencing FK permitting loops.

**Impact:** Org charts show orphaned branches and terminated employees' names; a data-entry loop breaks the view for all consumers with `ORA-01436`.

**Recommendation:** Filter inside the hierarchy (`CONNECT BY ... AND EMPLOYMENT_STATUS = 'ACTIVE'`), add `ACTIVE_FLAG = 'Y'` and `NOCYCLE`, and validate manager chains on write (`PKG_EMPLOYEE.validate_manager` already detects cycles for updates).

### DI-14 — YTD earnings attributed by period start date and unfiltered by run status — MEDIUM [confirmed]

**File:** `plsql/packages/PKG_PAYROLL.pkb:802-819`

```sql
WHERE pd.EMP_ID = p_emp_id AND pd.ELEMENT_TYPE = 'EARNING'
AND pd.STATUS = 'CALCULATED'
AND EXTRACT(YEAR FROM pp.PERIOD_START_DATE) = p_tax_year;
```

**Issue:** Tax-year attribution uses `PERIOD_START_DATE`, not `PAY_DATE`, so a period spanning 31 Dec-13 Jan is credited to the earlier year regardless of when it is paid (US withholding follows the pay date). The filter also accepts details from runs that were never approved and excludes `PAID` detail statuses if they are ever set.

**Impact:** Incorrect YTD across the year boundary, affecting wage-base caps and any W-2-style reporting built on this function.

**Recommendation:** Attribute by `PAY_DATE`, and restrict to runs in approved/paid status.

---

## Severity summary

| ID | Severity | Category | Location | Summary |
|---|---|---|---|---|
| SEC-01 | CRITICAL | Security | `PKG_SECURITY.pkb:30-80` | `authenticate` never checks the password |
| SEC-02 | CRITICAL | Security | `PKG_SECURITY.pkb:14-24` | MD5 password hashing |
| SEC-03 | CRITICAL | Security | `PKG_SECURITY.pkb:6-7,179-206` | Hard-coded, 30-byte AES-256 key |
| DI-01 | CRITICAL | Data integrity | `trg_employees.sql:76-110` | History insert uses nonexistent columns |
| DI-02 | CRITICAL | Data integrity | `trg_audit.sql:47-59` | Leave audit rows silently rejected |
| SEC-04 | HIGH | Security | `PKG_SECURITY.pkb:211-234` | `change_password` is a no-op |
| SEC-05 | HIGH | Security | `PKG_EMPLOYEE.pkb:445-499` | SQL injection in dynamic search |
| SEC-06 | HIGH | Security | `HRMS_LOGIN.xml:10-101` | Cleartext credential handling |
| SEC-07 | HIGH | Security | `PKG_SECURITY.pkb:26-80` | No lockout / attempt tracking |
| SEC-08 | HIGH | Security | `PKG_SECURITY.pkb:134-174` | Permissions keyed to surrogate `GRADE_ID` |
| RC-01 | HIGH | Race | `PKG_EMPLOYEE.pkb:34-55` | `MAX()+1` employee numbers |
| RC-02 | HIGH | Race | `PKG_LEAVE.pkb:146-182` | Unlocked balance check-then-write |
| PERF-01 | HIGH | Performance | `PKG_LEAVE.pkb:12-40` | Query per day in business-day loop |
| PERF-03 | HIGH | Performance | `PKG_NOTIFICATION.pkb:78-135` | SMTP connection per message |
| VAL-01 | HIGH | Validation | Forms/trigger/package | 90 vs 180 vs no hire-date limit |
| ARCH-02 | HIGH | Architecture | `PKG_AUDIT.pkb:6-31` et al. | Autonomous transactions decouple audit from truth |
| ARCH-03 | HIGH | Architecture | `PKG_INTEGRATION.pkb` | Unacknowledged flat-file integration |
| ARCH-04 | HIGH | Architecture | `PKG_INTEGRATION.pkb:153-203` | Stubs that report success |
| DI-03 | HIGH | Data integrity | `PKG_PAYROLL.pkb:329-344` | `TOTAL_NET` excludes `BENEFIT` |
| DI-04 | HIGH | Data integrity | `PKG_PAYROLL.pkb:404-414` | YTD includes current period |
| DI-05 | HIGH | Data integrity | `PKG_PAYROLL.pkb:436-437` | `PRETAX_FLAG` ignored |
| DI-06 | HIGH | Data integrity | `hrms_views.sql:86-103` | View `AVAILABLE` omits `PENDING` |
| SEC-09 | MEDIUM | Security | `PKG_SECURITY.pkb:98-127` | Timeout from login; no revocation |
| SEC-10 | MEDIUM | Security | `PKG_SECURITY.pkb:40-57` | Enumeration; `MIN(EMP_ID)` identity |
| SEC-11 | MEDIUM | Security | `PKG_NOTIFICATION.pkb:6-10` | Hard-coded SMTP; cleartext integration creds |
| RC-03 | MEDIUM | Race | `PKG_PAYROLL.pkb:232-263` | Unlocked period status check |
| RC-04 | MEDIUM | Race | `PKG_PAYROLL.pkb:583-600` | Reversal without state guard |
| RC-05 | MEDIUM | Race | `PKG_LEAVE.pkb:176-182` | Balance updates hit zero rows |
| PERF-02 | MEDIUM | Performance | `PKG_COMMON.pkb:132-165` | Duplicate holiday-blind day loops |
| PERF-04 | MEDIUM | Performance | `PKG_PAYROLL.pkb:266-327` | Row-by-row payroll/accrual |
| PERF-05 | MEDIUM | Performance | `hrms_views.sql:42-57` | `CONNECT BY` org chart, no `NOCYCLE` |
| PERF-06 | MEDIUM | Performance | `hrms_sequences.sql:9-49` | `NOCACHE` sequences |
| VAL-02 | MEDIUM | Validation | PLL vs `PKG_COMMON` | E-mail rule drift |
| VAL-03 | MEDIUM | Validation | PLL:47-90 | Client SSN/phone accept letters |
| VAL-06 | MEDIUM | Validation | `PKG_LEAVE.pkb:128-138` | Half-day flag ignores range |
| ARCH-01 | MEDIUM | Architecture | `PKG_EMPLOYEE.pks:6-9` | Declared circular dependency |
| ARCH-05 | MEDIUM | Architecture | `PKG_PAYROLL.pkb:602-738` | Hard-coded 2024 tax constants |
| ARCH-06 | MEDIUM | Architecture | `PKG_PAYROLL.pkb:405-499` | Literal element IDs |
| ARCH-09 | MEDIUM | Architecture | `PKG_EMPLOYEE.pkb:737-739` | Termination TODOs |
| DI-07 | MEDIUM | Data integrity | `PKG_LEAVE.pkb:605-623` | Expiry over-subtracts used carryover |
| DI-08 | MEDIUM | Data integrity | `PKG_LEAVE.pkb:558-603` | Carryover overwrites opening balance |
| DI-09 | MEDIUM | Data integrity | `trg_employees.sql:114-129` | Delete blocked but enabled in Forms |
| DI-10 | MEDIUM | Data integrity | `hrms_views.sql:105-129` | "Latest" run is `MAX(RUN_ID)` |
| DI-11 | MEDIUM | Data integrity | `hrms_views.sql:59-80` | Salary join without effective dating |
| DI-12 | MEDIUM | Data integrity | `trg_employees.sql:40-54` | Nonexistent e-mail unique constraint |
| DI-14 | MEDIUM | Data integrity | `PKG_PAYROLL.pkb:802-819` | YTD attributed by period start |
| SEC-12 | LOW | Security | `PKG_SECURITY.pkb:203-205` | `WHEN OTHERS` masks crypto/audit errors |
| RC-06 | LOW | Race | `PKG_PAYROLL.pkb:322-326` | Non-atomic interim commits |
| PERF-07 | LOW | Performance | `PKG_PAYROLL.pkb:414` | Per-employee YTD aggregation |
| VAL-04 | LOW | Validation | PLL:101-135 | Cache comment contradicts code |
| VAL-05 | LOW | Validation | `PKG_VALIDATION.pkb:99-122` | Required-field check covers one table |
| VAL-07 | LOW | Validation | `PKG_LEAVE.pkb:45-60` | Overlap ignores half-days |
| ARCH-07 | LOW | Architecture | `PKG_COMMON.pkb:167-195` | Hard-coded fiscal calendar |
| ARCH-08 | LOW | Architecture | `trg_audit.sql:18-30` | Concatenated JSON payloads |
| ARCH-10 | LOW | Architecture | repository-wide | No tests, no build, folklore workarounds |
| DI-13 | LOW | Data integrity | `hrms_views.sql:42-57` | Hierarchy filter applied post-`CONNECT BY` |

---

## Evidence-based recommendations

1. **Treat SEC-01, DI-01 and DI-02 as incidents, not backlog.** Each is verifiable from source in minutes: no password comparison, six nonexistent column names, and an `ACTION_TYPE` value that cannot satisfy its own constraint. Nothing else on this list matters if authentication is bypassable.
2. **Add a deployment gate before any refactor.** A script that deploys `schema/` + `plsql/` into a scratch schema and fails on any row in `USER_ERRORS`/invalid `USER_OBJECTS` would have caught DI-01 and would catch the next one. This is the highest leverage change in the repository.
3. **Establish single sources of truth for the three quantities that appear in more than one place:** net pay (DI-03, DI-04, DI-05), leave availability (DI-06, DI-07, DI-08, RC-02, RC-05), and validation rules (VAL-01 through VAL-05). Each is currently computed 2-4 times with different formulas.
4. **Move configuration out of package bodies:** tax brackets to `TAX_BRACKETS` (ARCH-05), element identity to `ELEMENT_CODE` (ARCH-06), SMTP and fiscal calendar to `SYSTEM_PARAMETERS` (SEC-11, ARCH-07), keys to a wallet (SEC-03).
5. **Make silence impossible.** Bare `WHEN OTHERS` handlers in `PKG_AUDIT`, `PKG_SECURITY.decrypt_ssn` and `PKG_EMPLOYEE.log_history`, plus stubs that log success (ARCH-04), are what allowed most of these defects to persist unnoticed in a system with no tests.
6. **Sequence the performance work last.** PERF-01 through PERF-07 are real but bounded at ~200 users; correctness and security defects here have direct financial and compliance exposure.

---

## Migration roadmap

### Phase 1 — Critical security

Goal: the application can no longer be trivially impersonated, and secrets are not in source.

- SEC-01: implement real credential verification against a `USER_CREDENTIALS` store; fail closed.
- SEC-02: replace MD5 with PBKDF2 (or delegate to an external IdP) with per-user salts and an algorithm version marker.
- SEC-03: move the SSN key to a wallet/`DBMS_CREDENTIAL`, use a correct 32-byte key, rotate the exposed key, remove the `WHEN OTHERS` mask, and verify existing ciphertext is readable.
- SEC-04, SEC-05, SEC-07, SEC-08: implement `change_password`; bind all `search_employees` predicates; add failed-attempt tracking and lockout; re-key authorization to `GRADE_LEVEL`/roles.
- SEC-06, SEC-09: enforce TLS end to end; expire on idle and revoke sessions on termination.
- Exit criteria: authentication and authorization covered by utPLSQL tests, including a negative test that a wrong password is rejected and a new job grade confers no elevated rights.

### Phase 2 — Data integrity

Goal: every layer reports the same numbers, and the audit trail is complete.

- DI-01: remove history writes from `TRG_EMP_BEFORE_UPDATE` (single writer: `PKG_EMPLOYEE.log_history`); add the invalid-object deployment gate.
- DI-02, SEC-12, ARCH-02: fix `ACTION_TYPE` values, stop swallowing audit failures, and pull audit/history into the parent transaction.
- DI-03, DI-04, DI-05, DI-14: define net pay once; compute YTD before writing details and by pay date; apply `PRETAX_FLAG`. Reconcile a historical run and quantify any withholding correction needed.
- DI-06, DI-07, DI-08, RC-02, RC-05: make `LEAVE_BALANCES` the single source (use the generated `AVAILABLE`), lock before check-then-write, add `SQL%ROWCOUNT` handling, and make carryover/expiry idempotent and usage-aware.
- DI-09 through DI-13, DI-12, RC-03, RC-04, RC-01: align views with effective dating and hierarchy filtering; add the active-e-mail unique index; add state guards to payroll run/reversal; switch employee numbers to `SEQ_EMP_NUMBER`.
- Exit criteria: a reconciliation report showing `PAYROLL_RUNS` totals equal to the sum of payslips and the GL feed, and view-vs-function equality tests for leave balances.

### Phase 3 — Performance

Goal: remove the loop-shaped bottlenecks before user growth makes them visible.

- PERF-01, PERF-02: one set-based, holiday-aware business-day implementation shared by all callers.
- PERF-03: one SMTP connection per batch, with retry caps and rate limiting.
- PERF-04, PERF-07: set-based payroll element inserts and a single YTD pass per run; add the supporting `PAYROLL_DETAILS` index.
- PERF-05, DI-13: `NOCYCLE`, indexed `MANAGER_EMP_ID`, and a materialized hierarchy for read-heavy screens.
- PERF-06: `CACHE` on high-volume sequences.
- RC-06: restartable, idempotent batch jobs.
- Exit criteria: payroll run and accrual timings recorded before/after on a 200-employee data set.

### Phase 4 — Modernization

Goal: reduce the surface that keeps regenerating this debt.

- ARCH-10: utPLSQL suite plus CI (schema deploy, compile, unit tests, invalid-object gate); retire the doubled `MESSAGE` workaround.
- ARCH-01: break the `PKG_EMPLOYEE`/`PKG_PAYROLL` cycle by extracting shared primitives; correct the spec dependency headers.
- ARCH-03: replace `UTL_FILE` feeds with an acknowledged transport plus a transfer log and idempotency keys; proper CSV escaping in the interim.
- ARCH-04, ARCH-09: implement or explicitly fail the stubs (time import, org sync, payslip YTD, termination steps).
- ARCH-05, ARCH-06, ARCH-07, SEC-11: complete the configuration extraction started in Phase 1.
- ARCH-08: `JSON_OBJECT`/`JSON_SERIALIZE` for audit payloads.
- VAL-02 through VAL-07: delete client-side duplicates in the PLL libraries in favour of `PKG_VALIDATION` calls, then plan the Forms-to-APEX/web migration with validation already centralized server-side.
- Also worth scheduling here: author a `DATA_DICTIONARY.md` (absent today) generated from DDL comments, so future column-usage cross-referencing has a source to check against.

---

*Analysis is static: no Oracle instance was available, so runtime-dependent findings are labelled `[inferred]` and require validation against a live schema.*
