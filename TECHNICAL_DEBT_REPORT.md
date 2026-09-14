# Technical Debt Report — ts-plsql-oracle-forms-hrms

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Stack:** Oracle Forms 12c, Oracle Reports, Oracle Database 19c, PL/SQL
**Analysis basis:** static review of `main` at commit `1c33787` (all line numbers refer to that revision)
**Scope:** `plsql/packages`, `plsql/triggers`, `schema/`, `forms/`, `data/seed`, `README.md`

---

## 1. Executive Summary

The HRMS codebase is a classic Forms/PL-SQL monolith with business logic split between client-side PLL libraries and server-side packages. The review found **44 findings**. Nine are CRITICAL: the login routine never checks the password, the `EMPLOYEES` update trigger writes to columns that do not exist (so every status change, termination and rehire fails), the payroll error handler itself violates a foreign key, auto-approved leave types can never be submitted, the seed script references a non-existent column, and leave-status audit rows are silently discarded because of a check constraint.

### Severity counts

| Severity | Count |
|----------|-------|
| CRITICAL | 9 |
| HIGH | 15 |
| MEDIUM | 15 |
| LOW | 5 |
| **Total** | **44** |

### Category breakdown

| Category | CRITICAL | HIGH | MEDIUM | LOW | Total |
|----------|----------|------|--------|-----|-------|
| Security vulnerabilities (SEC) | 3 | 4 | 2 | 0 | 9 |
| Race conditions (RACE) | 0 | 4 | 1 | 0 | 5 |
| Performance issues (PERF) | 0 | 1 | 5 | 1 | 7 |
| Validation drift (VAL) | 0 | 1 | 3 | 1 | 5 |
| Circular dependencies (DEP) | 0 | 1 | 1 | 0 | 2 |
| Architectural anti-patterns (ARCH) | 0 | 1 | 3 | 3 | 7 |
| Data integrity risks (DATA) | 6 | 3 | 0 | 0 | 9 |
| **Total** | **9** | **15** | **15** | **5** | **44** |

### Top five items to fix first

1. **SEC-001** — `PKG_SECURITY.authenticate` never compares the supplied password; any active employee e-mail logs in.
2. **DATA-001 / DATA-002** — `TRG_EMP_BEFORE_UPDATE` inserts into `EMPLOYEE_HISTORY` columns that do not exist and uses `CHANGE_TYPE` values rejected by the check constraint; every status/department/job change on `EMPLOYEES` raises `ORA-00904`.
3. **DATA-003** — `PKG_PAYROLL.calculate_payroll` error handler inserts `ELEMENT_ID = 0`, which violates `FK_PD_ELEMENT`; a single employee failure aborts the whole run.
4. **DATA-004** — `PKG_LEAVE.submit_leave_request` inserts auto-approved requests as `APPROVED` and then calls `approve_leave_request`, which rejects any non-`PENDING` request.
5. **SEC-002 / SEC-003** — MD5 password hashing and a hard-coded AES key in source control.

---

## 2. Detailed Findings

Each finding lists: ID, severity, location, snippet, issue, impact, recommendation.

### 2.1 Security Vulnerabilities

#### SEC-001 — Authentication never verifies the password
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb` lines 30–80 (`authenticate`)
```sql
FUNCTION authenticate(p_username IN VARCHAR2, p_password IN VARCHAR2, ...) RETURN NUMBER IS
    ...
    SELECT EMP_ID INTO v_emp_id FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
    ...
    -- NOTE: In the real system, passwords are stored in a separate USER_CREDENTIALS table.
    SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
    INSERT INTO USER_SESSIONS (...) VALUES (...);
    RETURN v_session_id;
```
- **Issue:** `p_password`, `v_stored_hash` and `v_input_hash` are declared but never used. A session is created for any e-mail that matches an active employee. `hash_password` (lines 14–25) exists but is never called on the login path.
- **Impact:** Complete authentication bypass from the login form (`forms/xml-exports/HRMS_LOGIN.xml` lines 75–79 call this function directly).
- **Recommendation:** Introduce a `USER_CREDENTIALS` table (salted hash, algorithm tag, failed-attempt counter, lock timestamp). Compare hashes with a constant-time routine before creating the session. Until the table exists, the function must fail closed.

#### SEC-002 — Unsalted MD5 password hashing
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb` lines 14–25; `PKG_SECURITY.pks` line 10
```sql
RETURN RAWTOHEX(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(p_password), DBMS_CRYPTO.HASH_MD5));
```
- **Issue:** MD5 without salt or iteration count.
- **Impact:** Any leaked hash table is trivially reversible with rainbow tables; identical passwords produce identical hashes.
- **Recommendation:** Use `DBMS_CRYPTO.HASH_SH512` with a per-user random salt and iteration (PBKDF2-style) as an interim step, or delegate authentication to WebLogic/OAM/LDAP and drop database-managed passwords entirely.

#### SEC-003 — Hard-coded AES encryption key in source
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb` line 7 (used at lines 186–187 and 199–200)
```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```
- **Issue:** The key protecting `SSN_ENCRYPTED` (and by convention `ACCOUNT_NUMBER_ENC`) is a literal in a package body committed to Git. The string is 30 bytes yet declared `RAW(32)`, so key length depends on the literal rather than being validated.
- **Impact:** Anyone with repository or `DBA_SOURCE` read access can decrypt every SSN. Key rotation is impossible without redeploying code.
- **Recommendation:** Move to Oracle Transparent Data Encryption (column-level) or store the key in an Oracle Wallet / external KMS and load it at runtime with restricted privileges. Plan a re-encryption migration.

#### SEC-004 — SQL injection via string concatenation in employee search
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb` lines 445–495 (`search_employees`), especially 467, 471, 479, 483, 487–493
```sql
v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
...
v_sql := v_sql || 'AND e.EMPLOYMENT_STATUS = ''' || p_status || ''' ';
```
- **Issue:** Every optional filter is concatenated into dynamic SQL. Nothing sanitises input; the comment at line 442 acknowledges the problem and relies on Forms LOVs to pass "validated" values.
- **Impact:** Any caller (Forms, reports, ad-hoc) can read or alter data outside the intended query (`' OR 1=1 --`, UNION into `EMPLOYEES.SSN_ENCRYPTED`, etc.).
- **Recommendation:** Rewrite with bind variables (`USING`) or a static query using `(p_last_name IS NULL OR UPPER(LAST_NAME) LIKE UPPER(:b) || '%')` predicates. Use `DBMS_ASSERT` only for identifiers, never for values.

#### SEC-005 — No account lockout or brute-force throttling
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb` line 28 and `authenticate` body; `PKG_SECURITY.pks` line 11; `forms/xml-exports/HRMS_LOGIN.xml` lines 11–13
```sql
-- VULNERABILITY: No brute-force protection (no lockout after N failures)
```
- **Issue:** No failed-attempt counter, no lock, no delay. `SYSTEM_PARAMETERS` has no lockout parameter either.
- **Impact:** Unlimited online password guessing once SEC-001 is fixed; today it is moot because no password check exists.
- **Recommendation:** Add `FAILED_ATTEMPTS`, `LOCKED_UNTIL` to the credentials table; lock after N failures with exponential back-off; record attempts in `AUDIT_LOG`.

#### SEC-006 — User enumeration via distinct error paths and timing
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_SECURITY.pkb` lines 46–57
```sql
WHEN NO_DATA_FOUND THEN
    -- VULNERABILITY: Timing attack ...
    RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
WHEN TOO_MANY_ROWS THEN
    SELECT MIN(EMP_ID) INTO v_emp_id ...
```
- **Issue:** Unknown users short-circuit before any hash work; duplicate e-mails silently resolve to the lowest `EMP_ID`.
- **Impact:** Attackers can distinguish valid from invalid usernames; duplicate e-mails can let one employee log in as another.
- **Recommendation:** Always perform the hash comparison (against a dummy hash when the user is unknown); enforce a unique index on `UPPER(EMAIL)` for active employees and fail closed on `TOO_MANY_ROWS`.

#### SEC-007 — Password change is a stub; password policy lives in code, not `SYSTEM_PARAMETERS`
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb` lines 211–235
```sql
IF LENGTH(p_new_password) < 8 THEN ...
-- NOTE: Actual password update would go to USER_CREDENTIALS table
-- This is a stub for the legacy system model
PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
```
- **Issue:** `p_old_password` is never verified and nothing is stored, yet an audit row claims a credential update occurred. The minimum length `8` duplicates `SYSTEM_PARAMETERS.PASSWORD_MIN_LENGTH` (seed line 193).
- **Impact:** "Change Password" menu item (`HRMS_MENU.xml` line 166) is non-functional; audit trail is misleading.
- **Recommendation:** Implement against the credentials table; read policy values through `PKG_COMMON.get_param_number`.

#### SEC-008 — Hard-coded SMTP configuration
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb` lines 6–10
```sql
-- Hard-coded SMTP config (should be in SYSTEM_PARAMETERS)
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
```
- **Issue:** Duplicates `SYSTEM_PARAMETERS` rows `SMTP_HOST` and `FROM_ADDRESS` (seed lines 194–197) which are therefore dead configuration. Unauthenticated SMTP on port 25 with no TLS.
- **Impact:** Environment-specific redeploys; e-mail contents (leave, payroll notices) travel in cleartext.
- **Recommendation:** Read via `PKG_COMMON.get_param`; use `UTL_SMTP` with STARTTLS and credentials from a wallet, or hand off to an external mail relay.

#### SEC-009 — FTP credentials documented as cleartext in `SYSTEM_PARAMETERS`
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_INTEGRATION.pks` line 12
```sql
--   - FTP credentials stored in SYSTEM_PARAMETERS table (cleartext)
```
- **Issue:** `SYSTEM_PARAMETERS.PARAM_VALUE` is `VARCHAR2(4000)` with no encryption and is readable by any schema user with SELECT. No FTP code exists in the body, so this is documented intent for the production system that the repo does not model.
- **Impact:** Credential disclosure to any read-only reporting account.
- **Recommendation:** Never store secrets in `SYSTEM_PARAMETERS`; use Oracle Wallet / DBMS_CREDENTIAL or move file transfer to SFTP with key-based auth managed outside the database.

### 2.2 Race Conditions

#### RACE-001 — `MAX()+1` employee number generation despite an existing sequence
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb` lines 37–50; `schema/sequences/hrms_sequences.sql` lines 19–21
```sql
SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
INTO v_max_num
FROM EMPLOYEES
WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
```
- **Issue:** Two concurrent hires read the same maximum and generate the same `EMP_NUMBER`. `SEQ_EMP_NUMBER` was created for this purpose but is never referenced. The Forms module also calls this from a client trigger (`HRMS_EMPLOYEE.xml` line 327), widening the window between generation and commit.
- **Impact:** `UK_EMP_NUMBER` violation on commit, failed hires under load; full table scan on every hire.
- **Recommendation:** `RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0');` and generate the number server-side in `create_employee` / `TRG_EMP_BEFORE_INSERT`.

#### RACE-002 — Pay-period status read without lock before creating a payroll run
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_PAYROLL.pkb` lines 241–260 (`create_payroll_run`)
```sql
SELECT STATUS INTO v_status FROM PAY_PERIODS WHERE PERIOD_ID = p_period_id;
IF v_status = 'CLOSED' THEN RAISE_APPLICATION_ERROR(-20102, ...); END IF;
SELECT SEQ_PAYROLL_RUN.NEXTVAL INTO v_run_id FROM DUAL;
INSERT INTO PAYROLL_RUNS (...) VALUES (v_run_id, p_period_id, ..., 'PENDING', ...);
```
- **Issue:** No `FOR UPDATE` (contrast `close_period` line 196 and `approve_payroll` line 564, which do lock). Only `CLOSED` is rejected; `PROCESSING` and `REVERSED` are accepted, and nothing prevents two `REGULAR` runs for one period.
- **Impact:** Duplicate payroll runs, double payment, closed-period runs when a close happens between the read and the insert.
- **Recommendation:** `SELECT ... FOR UPDATE`, check `STATUS = 'OPEN'`, and add a unique index on `PAYROLL_RUNS (PERIOD_ID, RUN_TYPE)` where status is not `REVERSED`.

#### RACE-003 — Leave balance checked without lock; balance year differs from debit year
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_LEAVE.pkb` lines 147–154 and 176–182
```sql
v_balance := get_leave_balance(p_emp_id, p_leave_type_id);   -- defaults to current year
IF v_balance < v_total_days THEN RAISE_APPLICATION_ERROR(-20201, ...); END IF;
...
UPDATE LEAVE_BALANCES SET PENDING = PENDING + v_total_days
WHERE ... AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```
- **Issue:** Two simultaneous requests both pass the balance check. The check uses the *current* calendar year while the debit uses the *start-date* year; a request for next January is validated against this year's balance and the `UPDATE` may affect zero rows silently.
- **Impact:** Negative balances, requests that never reserve `PENDING` days.
- **Recommendation:** Lock the `LEAVE_BALANCES` row (`FOR UPDATE`) for `EXTRACT(YEAR FROM p_start_date)`, check the balance on the locked row, and raise if `SQL%ROWCOUNT = 0`.

#### RACE-004 — Monthly accrual is not idempotent
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_LEAVE.pkb` lines 459–552 (`run_monthly_accrual`)
```sql
UPDATE LEAVE_BALANCES SET ACCRUED = ACCRUED + v_accrued ...
INSERT INTO LEAVE_ACCRUAL_LOG (...) VALUES (SEQ_LEAVE_ACCRUAL.NEXTVAL, ..., p_accrual_date, v_accrued, ...);
IF MOD(v_total_employees, 100) = 0 THEN COMMIT; END IF;
```
- **Issue:** No check that an accrual already exists for `(EMP_ID, LEAVE_TYPE_ID, month)`; a re-run or overlapping scheduler execution double-accrues. Intermediate commits every 100 employees make a crash leave half the workforce accrued.
- **Impact:** Inflated leave balances that are hard to detect and unwind.
- **Recommendation:** Add a unique index on `LEAVE_ACCRUAL_LOG (EMP_ID, LEAVE_TYPE_ID, TRUNC(ACCRUAL_DATE,'MM'))`, use `MERGE`/set-based SQL, and run as a single transaction with a run-lock (`DBMS_LOCK` or a `RUN_ID` row).

#### RACE-005 — Payroll YTD includes the row just inserted
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_PAYROLL.pkb` lines 405–416 and 802–818
```sql
INSERT INTO PAYROLL_DETAILS (...) VALUES (..., 1, 'EARNING', v_period_gross, 'CALCULATED', ...);
v_ytd_gross := get_ytd_earnings(p_emp_id, EXTRACT(YEAR FROM v_period_end));
```
- **Issue:** `get_ytd_earnings` sums `STATUS = 'CALCULATED'` rows for the year, which now includes the current period, and excludes `APPROVED`/`PAID` history depending on how statuses are maintained. Social Security wage-base capping (lines 729–733) therefore uses an over-stated YTD.
- **Impact:** Incorrect FICA withholding near the wage base; non-deterministic if runs are re-calculated.
- **Recommendation:** Compute YTD from prior runs only (`pr.RUN_ID <> p_run_id AND pr.STATUS IN ('APPROVED','PAID')`) and persist `YTD_AMOUNT` on the detail row.

### 2.3 Performance Issues

#### PERF-001 — Day-by-day business-day loops (three copies)
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_COMMON.pkb` lines 139–145 and 158–165; `plsql/packages/PKG_LEAVE.pkb` lines 21–37
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count FROM HOLIDAYS WHERE HOLIDAY_DATE = v_date ...;
```
- **Issue:** O(days) iteration; the `PKG_LEAVE` copy issues one `HOLIDAYS` query per day (a context switch per iteration). `PKG_COMMON.business_days_between` ignores holidays entirely, so two definitions of "business day" coexist (see VAL-005).
- **Impact:** Leave requests spanning months and annual reports degrade linearly; SQL/PLSQL context switching dominates.
- **Recommendation:** Arithmetic weekday formula plus a single `SELECT COUNT(*) FROM HOLIDAYS WHERE HOLIDAY_DATE BETWEEN ...`, or a `CALENDAR_DAYS` dimension table. Consolidate on one implementation.

#### PERF-002 — `CONNECT BY` hierarchies in package and view
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb` lines 828–838 (`get_org_chart`); `schema/views/hrms_views.sql` lines 43–57 (`VW_ORG_HIERARCHY`)
```sql
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
ORDER SIBLINGS BY LAST_NAME;
```
- **Issue:** The view has no `START WITH` filter and materialises the entire company tree with `SYS_CONNECT_BY_PATH` on every reference; the header comment warns of degradation above 500 employees. `WHERE EMPLOYMENT_STATUS = 'ACTIVE'` is applied after the walk, so terminated managers break chains silently.
- **Impact:** Forms LOVs and reports built on `VW_ORG_HIERARCHY` become the slowest queries in the system.
- **Recommendation:** Recursive `WITH` (supports `CYCLE` detection), an index on `(MANAGER_EMP_ID, EMPLOYMENT_STATUS)`, or a materialised closure table refreshed on manager change.

#### PERF-003 — SMTP connection opened per message
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb` lines 78–135 (`process_queue`)
```sql
FOR notif_rec IN (SELECT ... FROM NOTIFICATION_QUEUE WHERE STATUS = 'PENDING' ...) LOOP
    v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
    UTL_SMTP.HELO(...); ... UTL_SMTP.QUIT(v_connection);
```
- **Issue:** Full TCP/SMTP handshake for each of up to 50 messages every 5 minutes; failures leave the connection dangling until the `WHEN OTHERS` quit attempt. Queue rows are not locked (`FOR UPDATE SKIP LOCKED`), so two scheduler instances can send duplicates.
- **Impact:** Slow queue drain, mail-server connection-rate limits, duplicate e-mails.
- **Recommendation:** One connection per batch, `FOR UPDATE SKIP LOCKED` on the queue, mark rows `PROCESSING` before sending.

#### PERF-004 — Almost every sequence is `NOCACHE`
- **Severity:** MEDIUM
- **Location:** `schema/sequences/hrms_sequences.sql` lines 9–49 (all except `SEQ_AUDIT` line 45)
```sql
CREATE SEQUENCE HRMS.SEQ_PAYROLL_DETAIL START WITH 1 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE HRMS.SEQ_NOTIFICATION START WITH 1 INCREMENT BY 1 NOCACHE;
```
- **Issue:** `NOCACHE` forces a `SEQ$` update and redo write per `NEXTVAL`. `SEQ_PAYROLL_DETAIL` is hit roughly six times per employee per run. The comment at line 19 wrongly implies `NOCACHE` prevents gaps; gaps occur regardless.
- **Impact:** Serialization on `SEQ$` row locks during payroll and accrual batches, especially in RAC.
- **Recommendation:** `CACHE 20`–`1000` for high-volume sequences; drop the gap-free assumption from the design.

#### PERF-005 — Row-by-row payroll with partial commits
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_PAYROLL.pkb` lines 271–346 (`calculate_payroll`), comment at 295, commits at 292 and 324–326
```sql
-- BUG: Cursor loop - should use BULK COLLECT + FORALL
FOR emp_rec IN (SELECT e.EMP_ID FROM EMPLOYEES e WHERE ...) LOOP
    calculate_employee_pay(p_run_id, emp_rec.EMP_ID, ...);
    ...
    IF MOD(v_emp_count, 50) = 0 THEN COMMIT; END IF;
```
- **Issue:** Each employee triggers ~8 single-row inserts plus tax lookups; commits every 50 employees leave the run half-calculated if the session dies, and the run status remains `CALCULATING`.
- **Impact:** Long payroll windows; no atomic rollback of a failed run; operators must manually clean `PAYROLL_DETAILS`.
- **Recommendation:** Set-based `INSERT ... SELECT` per pay element, or `BULK COLLECT`/`FORALL` with a single commit; reversal must be transactional.

#### PERF-006 — `TO_CHAR(date,'DY')` without NLS language in period generation
- **Severity:** LOW
- **Location:** `plsql/packages/PKG_PAYROLL.pkb` lines 151–153
```sql
WHILE TO_CHAR(v_start_date, 'DY') != 'FRI' LOOP
    v_start_date := v_start_date + 1;
END LOOP;
```
- **Issue:** Under a non-English `NLS_DATE_LANGUAGE` session the literal `'FRI'` never matches and the loop never terminates. `PKG_COMMON` correctly passes `'NLS_DATE_LANGUAGE=AMERICAN'`.
- **Impact:** Hung session and a CPU-bound loop when run by a scheduler job with a different NLS setting.
- **Recommendation:** Use `NEXT_DAY(v_start_date - 1, 'FRIDAY')` with explicit NLS, or compute `MOD(TRUNC(v_start_date) - DATE '1900-01-05', 7)`.

#### PERF-007 — Reporting refresh is a no-op placeholder
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_REPORTING.pkb` lines 196–204
```sql
-- Placeholder for nightly refresh of denormalized reporting tables
-- In production, this truncates and repopulates RPT_* tables
PKG_COMMON.log_info('PKG_REPORTING', 'refresh_reporting_tables', 'Reporting tables refreshed', p_user);
```
- **Issue:** `README.md` line 116 documents denormalised reporting tables refreshed nightly; no `RPT_*` tables exist in `schema/` and the procedure only writes a log line claiming success.
- **Impact:** Reports run against live OLTP views (`VW_ORG_HIERARCHY`, `VW_PAYROLL_LATEST`), and the log falsely reports completion.
- **Recommendation:** Either create and populate the reporting tables (materialised views with `REFRESH COMPLETE ON DEMAND`) or delete the procedure and the README claim.

### 2.4 Validation Drift (PLL vs server packages)

#### VAL-001 — E-mail validation differs between Forms library and server
- **Severity:** MEDIUM
- **Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql` lines 21–45; `plsql/packages/PKG_COMMON.pkb` line 267; `plsql/packages/PKG_VALIDATION.pkb` lines 50–55
```sql
-- PLL
v_dot_pos := INSTR(p_email, '.', v_at_pos);
IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN RETURN FALSE;
-- BUG: Only checks for one dot after @, rejects valid subdomains
-- Server
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```
- **Issue:** The PLL performs positional `INSTR` checks (accepts `a@b.c` with a one-character TLD, spaces, or multiple `@`); the server uses a regex. `HRMS_EMPLOYEE.xml` line 377 calls the *server* function while other forms attach the PLL, so behaviour depends on which form the user is in.
- **Impact:** Records accepted on one screen and rejected on another; the login lookup (`UPPER(EMAIL)`) depends on e-mail quality.
- **Recommendation:** Delete `HRMS_VALIDATION_LIB.validate_email` and have the PLL delegate to `PKG_VALIDATION.validate_email_format`.

#### VAL-002 — Date-range rules differ across layers
- **Severity:** MEDIUM
- **Location:** `HRMS_VALIDATION_LIB.pll.sql` lines 96–99 (`validate_date_not_future`); `PKG_VALIDATION.pkb` lines 6–15 (`validate_date_range`) and 71–76 (`is_future_date`); `HRMS_EMPLOYEE.xml` lines 381–384; `PKG_LEAVE.pkb` lines 116–126
```sql
-- Form trigger
IF :EMPLOYEE.HIRE_DATE > SYSDATE + 90 THEN MESSAGE('Hire date cannot be more than 90 days in the future');
-- PLL
RETURN p_date IS NULL OR TRUNC(p_date) <= TRUNC(SYSDATE);
-- PKG_LEAVE
IF TRUNC(SYSDATE) - p_start_date > 5 THEN RAISE_APPLICATION_ERROR(-20211, ...);
```
- **Issue:** Hire date: form allows +90 days, PLL forbids any future date, server has no hire-date rule at all. Leave: 5-day back-dating limit exists only in `PKG_LEAVE`, not in the PLL or `PKG_VALIDATION`. `SYSDATE` (server) vs Forms client date may differ across time zones.
- **Impact:** Users receive different answers depending on entry path; direct API callers bypass the 90-day rule entirely.
- **Recommendation:** Define each rule once in `PKG_VALIDATION`, parameterise limits via `SYSTEM_PARAMETERS`, and have Forms call the server function.

#### VAL-003 — Salary-range validation: duplicated logic, misleading "cache" comment, different NULL semantics
- **Severity:** HIGH
- **Location:** `HRMS_VALIDATION_LIB.pll.sql` lines 103–135 (`validate_salary_range`); `PKG_VALIDATION.pkb` lines 17–48 (`validate_salary_for_grade`)
```sql
-- PLL comment: "Checks salary against grade range using cached local data"
-- PLL body:
IF p_salary IS NULL OR p_grade_id IS NULL THEN RETURN NULL; END IF;   -- treated as VALID
SELECT MIN_SALARY, MAX_SALARY INTO v_min, v_max FROM JOB_GRADES WHERE GRADE_ID = p_grade_id;
-- Server body:
RETURN 'Salary and grade are required';                                  -- treated as INVALID
```
- **Issue:** The PLL header describes a startup cache, but the body performs a live query (the code itself notes the contradiction at line 120). A NULL salary passes on the client and fails on the server. Messages differ (`Below minimum ($x)` vs `Salary $x is below grade minimum ...`).
- **Impact:** Inconsistent user experience; maintainers trusting the comment may "fix" a caching bug that does not exist.
- **Recommendation:** Remove the PLL implementation and call `PKG_VALIDATION.validate_salary_for_grade`; treat NULL inputs consistently.

#### VAL-004 — Phone/SSN validation duplicated with different rules
- **Severity:** LOW
- **Location:** `HRMS_VALIDATION_LIB.pll.sql` lines 47–93; `PKG_COMMON.pkb` lines 270–281; `PKG_VALIDATION.pkb` lines 57–62
- **Issue:** PLL accepts 10- or 11-digit phones and applies SSN area/group/serial zero checks; the server accepts `^\d{9}$` SSNs with no structural checks and delegates phone format elsewhere.
- **Impact:** Invalid SSNs (e.g. `000-12-3456`) can be stored via server APIs.
- **Recommendation:** Single server-side implementation with the stricter rule set.

#### VAL-005 — Two definitions of "business day"
- **Severity:** MEDIUM
- **Location:** `PKG_COMMON.pkb` lines 132–166; `PKG_LEAVE.pkb` lines 12–40; `PKG_VALIDATION.pkb` lines 78–97 (`is_business_day`)
- **Issue:** `PKG_COMMON.business_days_between` excludes weekends only; `PKG_LEAVE.calculate_business_days` also excludes `HOLIDAYS` but not observed holidays (its own comment, line 9). `PKG_VALIDATION.is_business_day` is a third implementation.
- **Impact:** Payroll day counts and leave day counts disagree for any range containing a holiday.
- **Recommendation:** One calendar function in `PKG_COMMON` backed by `HOLIDAYS` (with an `OBSERVED_DATE` column).

### 2.5 Circular Dependencies

#### DEP-001 — `PKG_EMPLOYEE` ⇄ `PKG_PAYROLL` (declared) and `PKG_SECURITY` ⇄ `PKG_EMPLOYEE` (partially realised)
- **Severity:** HIGH
- **Location:** `PKG_EMPLOYEE.pks` line 9; `PKG_PAYROLL.pks` line 9; `PKG_EMPLOYEE.pkb` lines 273–275, 617, 778 (calls `PKG_PAYROLL.create_salary_record`); `PKG_SECURITY.pkb` line 75 (calls `PKG_EMPLOYEE.set_session_context`); `PKG_EMPLOYEE.pkb` line 738 (`TODO: Revoke system access via PKG_SECURITY`); `README.md` line 127
```sql
-- PKG_EMPLOYEE.pks:  - Circular dependency with PKG_PAYROLL (salary validation)
-- PKG_PAYROLL.pks:   - Circular dependency with PKG_EMPLOYEE (is_active check)
-- PKG_EMPLOYEE.pkb:  -- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
```
- **Issue:** In the committed bodies, `PKG_PAYROLL` does not actually call `PKG_EMPLOYEE` (its only cross-package calls are to `PKG_AUDIT` and `PKG_COMMON`), so the `EMPLOYEE↔PAYROLL` cycle exists in specs, comments and README but is one-directional in code today. The `SECURITY→EMPLOYEE→(TODO)SECURITY` cycle will become real when the termination TODO is implemented.
- **Impact:** Any body change that completes either cycle produces `ORA-04068`/`ORA-06508` invalidation storms during deployment and forces the packages to be compiled together; documentation is out of sync with code.
- **Recommendation:** Extract `create_salary_record`/salary validation into `PKG_COMPENSATION` (depended on by both), move `set_session_context` into `PKG_SECURITY` or `PKG_COMMON`, and update the spec comments.

#### DEP-002 — Utility/logging packages depend on domain tables
- **Severity:** MEDIUM
- **Location:** `PKG_NOTIFICATION.pkb` lines 31–35 (queries `EMPLOYEES`); `PKG_COMMON.pkb` lines 16–33 (writes `AUDIT_LOG`); `PKG_AUDIT.pkb` lines 6–31
- **Issue:** `PKG_COMMON` (lowest layer) writes to the audit table owned by `PKG_AUDIT`; `PKG_NOTIFICATION` reads `EMPLOYEES`. Dependency direction is bottom-up and top-down at once.
- **Impact:** Schema changes to `AUDIT_LOG` or `EMPLOYEES` invalidate every package.
- **Recommendation:** Give `PKG_COMMON` its own `APP_LOG` table; pass the recipient e-mail into `send_notification` instead of resolving it inside the notification layer.

### 2.6 Architectural Anti-Patterns

#### ARCH-001 — Autonomous transactions used for business events
- **Severity:** MEDIUM
- **Location:** `PKG_EMPLOYEE.pkb` line 155 (`log_history`); `PKG_COMMON.pkb` lines 16, 46; `PKG_AUDIT.pkb` line 14; `PKG_NOTIFICATION.pkb` line 27
```sql
PROCEDURE log_history(...) IS
    PRAGMA AUTONOMOUS_TRANSACTION;
```
- **Issue:** Employee history rows and notifications are committed even when the parent hire/transfer rolls back; conversely `send_notification` swallows all errors (`WHEN OTHERS ... ROLLBACK`).
- **Impact:** Orphan history rows referencing changes that never happened; e-mails sent for rolled-back leave requests; silent loss of notifications.
- **Recommendation:** Reserve autonomous transactions for diagnostic logging only; write history/notifications in the caller's transaction (or via a queue table drained after commit).

#### ARCH-002 — Flat-file integration via `UTL_FILE`
- **Severity:** MEDIUM
- **Location:** `PKG_INTEGRATION.pkb` lines 7–9, 27, 99, 162; `PKG_PAYROLL.pkb` line 842
```sql
v_file := UTL_FILE.FOPEN(c_gl_output_dir, v_filename, 'W', 32767);
UTL_FILE.PUT_LINE(v_file, 'D|' || rec.COST_CENTER || '|' || rec.GL_ACCOUNT_CODE || ...);
```
- **Issue:** GL journal, ADP benefits feed, time import and pay register are hand-rolled pipe/fixed-width files on database directory objects. No checksum, no idempotency (filename is date-based so a rerun overwrites), no encryption of PII (DOB, dependants) in the benefits feed. Both GL lines are emitted as record type `D` (lines 56 and 61) despite the comment describing debits vs credits.
- **Impact:** Fragile integrations; PII on disk; GL feed may be unbalanced.
- **Recommendation:** Publish through a REST/ORDS endpoint or a staging table consumed by an integration layer; if files remain, generate them from an external job with proper controls.

#### ARCH-003 — Stub and TODO implementations shipped as production code
- **Severity:** HIGH
- **Location:** `PKG_INTEGRATION.pkb` lines 166–172 (`import_time_attendance`: `-- TODO: Implement actual parsing`), 196–203 (`sync_org_structure` placeholder); `PKG_REPORTING.pkb` lines 196–204; `PKG_SECURITY.pkb` lines 230–233; `PKG_EMPLOYEE.pkb` lines 737–739 (COBRA, access revocation, final pay); `PKG_PAYROLL.pkb` lines 784–785 (`0 AS YTD_GROSS -- Placeholder`)
- **Issue:** Procedures return success and write "completed" log entries without doing the work. Payslips display YTD figures of zero. Terminated employees keep system access (there is also no password to revoke — see SEC-001).
- **Impact:** Operational processes believe imports/syncs ran; compliance exposure on termination.
- **Recommendation:** Either implement or make the stubs raise `-20999 'Not implemented'`; track each as a backlog item.

#### ARCH-004 — Hard-coded fiscal year and tax constants duplicating configuration tables
- **Severity:** MEDIUM
- **Location:** `PKG_COMMON.pkb` lines 170–182 (`get_fiscal_year`), 184–198; `PKG_PAYROLL.pkb` lines 7–13 and 640–700 (`calculate_federal_tax`), 729–733; `data/seed/01_reference_data.sql` line 189 (`FISCAL_YEAR_START = '10'`); `schema/tables/02_payroll_tables.sql` lines 159–173 (`TAX_BRACKETS`)
```sql
IF EXTRACT(MONTH FROM p_date) >= 10 THEN RETURN EXTRACT(YEAR FROM p_date) + 1;
c_ss_wage_base_2024   CONSTANT NUMBER := 168600;
IF v_taxable <= 11600 THEN v_tax := v_taxable * 0.10; ...
```
- **Issue:** `SYSTEM_PARAMETERS.FISCAL_YEAR_START` and the `TAX_BRACKETS` table exist but are never read; October start and 2024 federal brackets/deductions are compiled in.
- **Impact:** Every tax year requires a code deployment; multi-year recalculation (corrections for a prior year) is impossible.
- **Recommendation:** Read fiscal parameters through `get_param_number`; drive tax from `TAX_BRACKETS` keyed by `TAX_YEAR`/`FILING_STATUS`; add a `PAYROLL_CONSTANTS` table for wage bases and rates.

#### ARCH-005 — Hand-built JSON strings in audit payloads
- **Severity:** LOW
- **Location:** `plsql/triggers/trg_audit.sql` lines 20–29, 56–57; `PKG_COMMON.pkb` lines 23–26, 53–55
```sql
'","message":"' || REPLACE(SUBSTR(p_message, 1, 3000), '"', '\"') || '"}'
```
- **Issue:** Manual concatenation; `\"` is not valid JSON escaping for the PL/SQL string (produces `\"` only if the source contains `"`; other control characters are unescaped). 19c ships `JSON_OBJECT`.
- **Impact:** Unparseable audit payloads under `JSON_TABLE`/downstream SIEM.
- **Recommendation:** Use `JSON_OBJECT(KEY 'package' VALUE p_package, ...)` and add an `IS JSON` check constraint on `OLD_VALUES`/`NEW_VALUES`.

#### ARCH-006 — Magic pay-element IDs
- **Severity:** LOW
- **Location:** `PKG_PAYROLL.pkb` lines 409, 448, 462–467, 478, 492, 780–783, 854–857
```sql
SEQ_PAYROLL_DETAIL.NEXTVAL, p_run_id, p_emp_id, 1, 'EARNING', ...
SUM(CASE WHEN pd.ELEMENT_ID = 100 THEN ABS(pd.AMOUNT) ELSE 0 END) AS FEDERAL_TAX,
```
- **Issue:** Element IDs 1, 100–103 are hard-coded although `PAY_ELEMENTS.ELEMENT_CODE` (`BASE_PAY`, `FED_TAX`, …) exists.
- **Impact:** Re-seeding or adding a tax element breaks payroll silently.
- **Recommendation:** Resolve IDs by `ELEMENT_CODE` at package initialisation or join on code.

#### ARCH-007 — Audit table used as application log
- **Severity:** LOW
- **Location:** `PKG_COMMON.pkb` lines 18–28 and 48–57
```sql
INSERT INTO AUDIT_LOG (AUDIT_ID, TABLE_NAME, RECORD_ID, ACTION_TYPE, ...)
VALUES (SEQ_AUDIT.NEXTVAL, 'ERROR_LOG', 0, 'INSERT', ...);
```
- **Issue:** Error and info messages are stored as fake `INSERT` audit rows with `TABLE_NAME` `'ERROR_LOG'`/`'INFO_LOG'` and `RECORD_ID = 0`.
- **Impact:** Pollutes compliance audit trail; `purge_old_records` deletes errors and audits together.
- **Recommendation:** Dedicated `APPLICATION_LOG` table with its own retention.

### 2.7 Data Integrity Risks

#### DATA-001 — `TRG_EMP_BEFORE_UPDATE` inserts into non-existent `EMPLOYEE_HISTORY` columns
- **Severity:** CRITICAL
- **Location:** `plsql/triggers/trg_employees.sql` lines 78–86, 90–98, 102–110; `schema/tables/01_core_tables.sql` lines 152–178
```sql
-- Trigger
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'STATUS_CHANGE', SYSDATE, ...);
-- DDL (actual columns)
HIST_ID, EMP_ID, CHANGE_TYPE, EFFECTIVE_DATE, OLD_DEPT_ID, NEW_DEPT_ID, OLD_JOB_ID, NEW_JOB_ID,
OLD_MANAGER_ID, NEW_MANAGER_ID, OLD_SALARY, NEW_SALARY, OLD_LOCATION, NEW_LOCATION,
REASON_CODE, COMMENTS, CREATED_BY, CREATED_DATE
```
- **Issue:** Six of eight column names (`HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON`) do not exist. The trigger cannot compile against this DDL (`ORA-00904`), or if it was compiled against an older table it is now `INVALID` and fires `ORA-04098`.
- **Impact:** Every `UPDATE EMPLOYEES` that changes `EMPLOYMENT_STATUS`, `DEPT_ID` or `JOB_ID` fails — this includes `terminate_employee`, `rehire_employee`, `transfer_employee`, and `PKG_EMPLOYEE.log_history` paths. Alternatively, if the trigger is disabled in production to work around it, all status history is lost.
- **Recommendation:** Rewrite the trigger to the real column list (`HIST_ID, EMP_ID, CHANGE_TYPE, EFFECTIVE_DATE, OLD_DEPT_ID/NEW_DEPT_ID, ..., COMMENTS, CREATED_BY, CREATED_DATE`) or remove it in favour of `PKG_EMPLOYEE.log_history`, which already targets the correct columns. Add a compile-all step (`UTL_RECOMP`) plus `DBA_OBJECTS STATUS='INVALID'` gate to CI.

#### DATA-002 — Trigger `CHANGE_TYPE` values violate `CHK_CHANGE_TYPE`
- **Severity:** CRITICAL
- **Location:** `plsql/triggers/trg_employees.sql` lines 94 and 106; `schema/tables/01_core_tables.sql` lines 173–176
```sql
SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'DEPARTMENT_CHANGE', SYSDATE, ...
SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'JOB_CHANGE', SYSDATE, ...
-- DDL
CHECK (CHANGE_TYPE IN ('HIRE','TRANSFER','PROMOTION','DEMOTION','SALARY_CHANGE',
                       'TERMINATION','REHIRE','LEAVE_START','LEAVE_END','STATUS_CHANGE'))
```
- **Issue:** Even after DATA-001 is fixed, `'DEPARTMENT_CHANGE'` and `'JOB_CHANGE'` are not permitted values.
- **Impact:** Department transfers and job changes via direct update raise `ORA-02290`.
- **Recommendation:** Use `'TRANSFER'`/`'PROMOTION'` or extend the check constraint; add a unit test that inserts each trigger payload.

#### DATA-003 — Payroll error handler violates `FK_PD_ELEMENT`
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_PAYROLL.pkb` lines 311–319; `schema/tables/02_payroll_tables.sql` line 153; `data/seed/01_reference_data.sql` lines 122–153
```sql
INSERT INTO PAYROLL_DETAILS (DETAIL_ID, RUN_ID, EMP_ID, ELEMENT_ID, ELEMENT_TYPE, AMOUNT, STATUS, ERROR_MESSAGE, ...)
VALUES (SEQ_PAYROLL_DETAIL.NEXTVAL, p_run_id, emp_rec.EMP_ID, 0, 'ERROR', 0, 'ERROR', SUBSTR(SQLERRM,1,4000), ...);
```
- **Issue:** No `PAY_ELEMENTS` row with `ELEMENT_ID = 0` is seeded (IDs are 1, 100–103, 200–205). The insert inside `WHEN OTHERS` raises `ORA-02291`, which propagates out of the loop.
- **Impact:** The first employee without an active salary record (or any other per-employee error) aborts the entire payroll run and leaves `PAYROLL_RUNS.STATUS = 'CALCULATING'` with partially committed details (PERF-005).
- **Recommendation:** Record errors in a `PAYROLL_ERRORS` table (no FK to elements) or make `ELEMENT_ID` nullable for `STATUS = 'ERROR'` rows.

#### DATA-004 — Auto-approved leave types can never be submitted
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_LEAVE.pkb` lines 162–173 and 199–202, 212–228
```sql
CASE WHEN v_leave_type.REQUIRES_APPROVAL = 'Y' THEN 'PENDING' ELSE 'APPROVED' END,
...
IF v_leave_type.REQUIRES_APPROVAL = 'N' THEN
    approve_leave_request(v_request_id, NULL, 'Auto-approved', p_user);
END IF;
-- approve_leave_request:
IF v_request.STATUS != 'PENDING' THEN RAISE_APPLICATION_ERROR(-20204, 'Cannot approve request in status: ' || v_request.STATUS);
```
- **Issue:** The request is inserted already `APPROVED`, then `approve_leave_request` rejects it because it is not `PENDING`. Additionally `PENDING` balance was incremented at line 176 and would never be moved to `USED`.
- **Impact:** Any leave type with `REQUIRES_APPROVAL = 'N'` raises `-20204` on every submission.
- **Recommendation:** Insert as `PENDING` and let `approve_leave_request` transition it, or perform the approval bookkeeping inline and skip the call.

#### DATA-005 — Seed script references a column that does not exist
- **Severity:** CRITICAL
- **Location:** `data/seed/01_reference_data.sql` lines 182–201; `schema/tables/04_performance_tables.sql` line 115
```sql
INSERT INTO SYSTEM_PARAMETERS (PARAM_ID, PARAM_GROUP, PARAM_CODE, PARAM_VALUE, DESCRIPTION, EDITABLE_FLAG, ...)
-- DDL column is PARAM_DESCRIPTION
```
- **Issue:** Ten inserts use `DESCRIPTION`; the table defines `PARAM_DESCRIPTION`.
- **Impact:** `ORA-00904` — no system parameters are loaded, so `PKG_COMMON.get_param` returns NULL everywhere (`get_integration_status`, session timeout, fiscal year once ARCH-004 is fixed).
- **Recommendation:** Fix the column name and add a CI step that runs the schema + seed scripts against a disposable Oracle XE container.

#### DATA-006 — Leave-request audit trigger writes an action rejected by the check constraint
- **Severity:** CRITICAL
- **Location:** `plsql/triggers/trg_audit.sql` lines 47–59; `schema/tables/04_performance_tables.sql` line 104; `PKG_AUDIT.pkb` lines 27–31
```sql
PKG_AUDIT.log_action('LEAVE_REQUESTS', :NEW.REQUEST_ID, 'STATUS_CHANGE', ...);
-- AUDIT_LOG: CONSTRAINT CHK_AUDIT_ACTION CHECK (ACTION_TYPE IN ('INSERT','UPDATE','DELETE'))
-- log_action: WHEN OTHERS THEN ROLLBACK;   -- swallows the ORA-02290
```
- **Issue:** `'STATUS_CHANGE'` is not an allowed `ACTION_TYPE`; `log_action` swallows the error, so the trigger appears to succeed.
- **Impact:** No audit trail for leave approvals/rejections/cancellations despite a trigger that claims to provide one — a compliance gap that is invisible at runtime.
- **Recommendation:** Extend the check constraint (or map to `'UPDATE'`), and make `log_action` at least write to `DBMS_OUTPUT`/an error table instead of a bare `ROLLBACK`.

#### DATA-007 — Soft-delete contract is contradictory
- **Severity:** HIGH
- **Location:** `plsql/triggers/trg_employees.sql` lines 118–130; `PKG_EMPLOYEE.pkb` lines 670–690; `README.md` line 114; `schema/views/hrms_views.sql` lines 36–37, 54, 80
```sql
-- Named INSTEAD_OF but is a BEFORE DELETE trigger
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE BEFORE DELETE ON HRMS.EMPLOYEES
-- BUG: This actually prevents deletion, but Forms expects DELETE to succeed.
RAISE_APPLICATION_ERROR(-20504, 'Direct deletion not allowed. Use termination process or set ACTIVE_FLAG to N.');
```
- **Issue:** The trigger name says "instead of" but it raises rather than converting to a soft delete; Forms `DELETE_RECORD` therefore fails. Two soft-delete indicators exist (`ACTIVE_FLAG` and `EMPLOYMENT_STATUS`): `VW_ACTIVE_EMPLOYEES` filters on both, `VW_ORG_HIERARCHY` and `VW_EMPLOYEE_COMPENSATION` on status only, `run_monthly_accrual` on both, `authenticate` on status only. `terminate_employee` cancels `PENDING` leave requests (lines 674–682) without releasing `LEAVE_BALANCES.PENDING`.
- **Impact:** A row with `ACTIVE_FLAG='N'` but `EMPLOYMENT_STATUS='ACTIVE'` (the workaround described in the trigger comment) can still log in and appears in some views but not others; terminated employees keep phantom pending balances.
- **Recommendation:** Make the trigger actually perform the soft delete (`UPDATE EMPLOYEES SET ACTIVE_FLAG='N', EMPLOYMENT_STATUS='TERMINATED' ...` via a compound trigger or Forms `ON-DELETE`), define `ACTIVE_FLAG` as derived from status (virtual column), and release pending balances on termination.

#### DATA-008 — `VW_LEAVE_SUMMARY.AVAILABLE` disagrees with the table's own `AVAILABLE` column
- **Severity:** HIGH
- **Location:** `schema/views/hrms_views.sql` line 96; `schema/tables/03_leave_tables.sql` line 47; `PKG_LEAVE.pkb` lines 376, 567
```sql
-- View
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,
-- Table virtual column
AVAILABLE GENERATED ALWAYS AS (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL
-- process_carryover REMAINING also omits PENDING; expire_carryover subtracts the full carryover even if already used
```
- **Issue:** The view (used by Reports) omits `- PENDING`; `get_leave_balance` includes it; `process_carryover` carries pending days over into next year's opening balance; `expire_carryover` (lines 614–620) deducts the entire `CARRYOVER_FROM_PREV` regardless of how much has already been used, producing negative balances.
- **Impact:** Managers see more days available than employees can request; year-end carryover and expiry can both over-credit and over-debit.
- **Recommendation:** Reference the virtual column everywhere; compute expiry as `LEAST(CARRYOVER_FROM_PREV, remaining)`; never carry pending days.

#### DATA-009 — `VW_PAYROLL_LATEST` and `VW_EMPLOYEE_COMPENSATION` do not match their documented behaviour
- **Severity:** HIGH
- **Location:** `schema/views/hrms_views.sql` lines 59–80 and 105–129
```sql
-- "Latest payroll run details per employee"
WHERE pr.RUN_ID = (SELECT MAX(pr2.RUN_ID) FROM PAYROLL_RUNS pr2 WHERE pr2.STATUS = 'APPROVED')
-- "Current compensation details"
JOIN SALARY_RECORDS sr ON e.EMP_ID = sr.EMP_ID AND sr.ACTIVE_FLAG = 'Y'
```
- **Issue:** `VW_PAYROLL_LATEST` picks one global run (highest `RUN_ID` in `APPROVED`), not the latest per employee, and ignores `PAID` runs — once a run is marked paid the view jumps back to an older run or returns nothing. `VW_EMPLOYEE_COMPENSATION` has no effective-date filter; any employee with two `ACTIVE_FLAG='Y'` salary rows (e.g. a future-dated raise) duplicates. `NET_PAY = SUM(pd.AMOUNT)` relies on the sign convention that taxes/deductions are stored negative, which the `ABS()` in the same view suggests is not trusted.
- **Impact:** Payslip and compensation reports show wrong or duplicated figures.
- **Recommendation:** Use `ROW_NUMBER() OVER (PARTITION BY EMP_ID ORDER BY RUN_DATE DESC)` with `STATUS IN ('APPROVED','PAID')`; apply the same effective-date predicate used in `VW_ACTIVE_EMPLOYEES`.

---

## 3. Cross-Reference Checks Performed

| Check | Result |
|-------|--------|
| Trigger column lists vs table DDL | `TRG_EMP_BEFORE_UPDATE` → `EMPLOYEE_HISTORY`: 6 of 8 columns missing (DATA-001); `CHANGE_TYPE` values outside check constraint (DATA-002). `TRG_EMP_BEFORE_INSERT`, `TRG_SALARY_AUDIT`, `TRG_DEPARTMENT_AUDIT`: columns match. `TRG_LEAVE_REQUEST_AUDIT`: action value violates `CHK_AUDIT_ACTION` (DATA-006). |
| Package INSERT column lists vs DDL | `PKG_SECURITY`→`USER_SESSIONS`, `PKG_NOTIFICATION`→`NOTIFICATION_QUEUE`, `PKG_AUDIT`/`PKG_COMMON`→`AUDIT_LOG`, `PKG_LEAVE`→`LEAVE_*`, `PKG_PAYROLL`→`PAYROLL_*`: names match. FK violation on `PAYROLL_DETAILS.ELEMENT_ID = 0` (DATA-003). |
| Seed data vs DDL | `SYSTEM_PARAMETERS.DESCRIPTION` does not exist (DATA-005). |
| `DATA_DICTIONARY.md` | Not present in the repository; column-description cross-check could not be performed. Recommend generating one from `COMMENT ON COLUMN` statements as part of Phase 4. |
| View definitions vs documented behaviour | `VW_LEAVE_SUMMARY`, `VW_PAYROLL_LATEST`, `VW_EMPLOYEE_COMPENSATION` deviate (DATA-008, DATA-009). `VW_ACTIVE_EMPLOYEES`, `VW_PENDING_APPROVALS` consistent. |
| README claims vs code | "Denormalized reporting tables refreshed nightly" — no such tables (PERF-007). "Circular package dependencies between PKG_EMPLOYEE and PKG_PAYROLL" — only one direction exists in bodies (DEP-001). |

---

## 4. Prioritised Migration Roadmap

### Phase 1 — Critical Security (immediate)
| Item | Findings | Outcome |
|------|----------|---------|
| Create `USER_CREDENTIALS` (salted SHA-512/PBKDF2, failed-attempt counter, lock fields); implement real password verification and lockout | SEC-001, SEC-002, SEC-005, SEC-007 | Login actually authenticates |
| Move the AES key to Oracle Wallet/TDE and re-encrypt `SSN_ENCRYPTED`, `ACCOUNT_NUMBER_ENC` | SEC-003 | Key no longer in source control |
| Rewrite `search_employees` with bind variables | SEC-004 | SQL injection closed |
| Constant-time user lookup; unique index on active `UPPER(EMAIL)` | SEC-006 | No enumeration / identity confusion |
| Externalise SMTP config, add TLS; remove any secrets from `SYSTEM_PARAMETERS` | SEC-008, SEC-009 | No cleartext credentials |

### Phase 2 — Data Integrity (next release)
| Item | Findings | Outcome |
|------|----------|---------|
| Fix or remove `TRG_EMP_BEFORE_UPDATE`; align `CHANGE_TYPE` values; add invalid-object gate to CI | DATA-001, DATA-002 | Terminations/transfers work; history captured |
| Fix seed column name; run schema+seed in CI against Oracle XE | DATA-005 | Parameters load |
| Payroll error rows without FK; single-transaction runs; lock pay period; unique run per period | DATA-003, RACE-002, PERF-005 | Payroll runs are atomic and cannot duplicate |
| Fix auto-approve path; lock balance row; use start-date year; idempotent accrual; release pending on termination | DATA-004, RACE-003, RACE-004, DATA-007 | Leave balances stay consistent |
| Extend `CHK_AUDIT_ACTION`; stop swallowing audit errors | DATA-006 | Compliance audit trail complete |
| Use sequence for `EMP_NUMBER` | RACE-001 | No duplicate employee numbers |
| Correct `VW_LEAVE_SUMMARY`, `VW_PAYROLL_LATEST`, `VW_EMPLOYEE_COMPENSATION`; fix carryover/expiry math | DATA-008, DATA-009 | Reports match transactions |
| Prior-run-only YTD | RACE-005 | Correct FICA capping |

### Phase 3 — Performance
| Item | Findings | Outcome |
|------|----------|---------|
| Set-based payroll (`INSERT ... SELECT` / `FORALL`) | PERF-005 | Payroll window shrinks by an order of magnitude |
| Arithmetic business-day function with single holiday lookup; one implementation | PERF-001, VAL-005 | Consistent, O(1) day counts |
| Recursive `WITH` + closure table for org hierarchy | PERF-002 | Org chart scales past 500 employees |
| One SMTP connection per batch; `SKIP LOCKED` queue | PERF-003 | Faster, duplicate-free notifications |
| `CACHE` on high-volume sequences | PERF-004 | Removes `SEQ$` contention |
| NLS-safe date logic | PERF-006 | No hung period generation |
| Real reporting refresh or remove claim | PERF-007 | Reports off OLTP path |

### Phase 4 — Modernisation
| Item | Findings | Outcome |
|------|----------|---------|
| Single validation layer: PLL delegates to `PKG_VALIDATION`; rules parameterised | VAL-001 – VAL-004 | One source of truth for validation |
| Break package cycles (`PKG_COMPENSATION`, move `set_session_context`); separate `APP_LOG` | DEP-001, DEP-002, ARCH-007 | Clean layered dependency graph |
| Replace autonomous business writes with in-transaction writes/queues | ARCH-001 | No orphan history or phantom notifications |
| Replace `UTL_FILE` feeds with ORDS/REST or staging tables; implement or retire stubs | ARCH-002, ARCH-003 | Reliable, observable integrations |
| Drive fiscal year and tax from tables; resolve pay elements by code | ARCH-004, ARCH-006 | Year-end changes without deployment |
| `JSON_OBJECT` + `IS JSON` constraints | ARCH-005 | Machine-readable audit payloads |
| Generate `DATA_DICTIONARY.md` from column comments; add utPLSQL suite | — | Documentation and regression safety for the Forms-to-web migration |

---

*Report regenerated by static analysis; no database runtime was available, so compile-time errors (DATA-001, DATA-002, DATA-005) are inferred from DDL comparison rather than observed.*
