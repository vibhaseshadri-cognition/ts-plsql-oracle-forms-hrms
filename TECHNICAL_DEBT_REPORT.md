# Technical Debt Report — Oracle Forms / PL/SQL HRMS

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Commit analysed:** `1c33787` (Initial commit: Oracle Forms 11g/12c legacy HRMS codebase)
**Date:** 2026-08-03
**Scope:** All PL/SQL packages (`plsql/packages`), database triggers (`plsql/triggers`), schema DDL, views and sequences (`schema/`), Oracle Forms XML exports and PLL libraries (`forms/`), and seed data (`data/seed`).
**Method:** Static source review, cross-referencing every trigger/package DML statement against the actual table DDL, plus `sqlfluff lint --dialect oracle .` and `xmllint --noout` over the Forms XML exports.

---

## 1. Executive Summary

The codebase is a self-consistent Oracle Forms 12c / Oracle Database 19c HRMS with 12 PL/SQL packages, 5 triggers, 4 DDL scripts, 6 views and 6 Forms XML exports. It carries the debt profile typical of a 20-year-old Forms application, but it also contains defects that go beyond "legacy style": **two database objects cannot work at all as written**, and **authentication does not verify passwords**.

The three findings that dominate risk:

1. **`PKG_SECURITY.authenticate` never compares the supplied password to anything** — it looks up an e-mail address, creates a session and returns it. Any known e-mail address is a valid login (`SEC-001`).
2. **`TRG_EMP_BEFORE_UPDATE` inserts into `EMPLOYEE_HISTORY` using six column names that do not exist** in the table DDL. The trigger cannot compile, so *every* `UPDATE` on `EMPLOYEES` that changes status, department or job fails (`DATA-001`).
3. **`TRG_EMP_BEFORE_INSERT` queries `EMPLOYEES` from a row-level trigger on `EMPLOYEES`** — a mutating-table read that raises ORA-04091 on every insert (`DATA-002`).

Beyond those, the recurring structural themes are: security logic that is decorative rather than enforcing (`SEC-006`, `SEC-008`, `DATA-009`), unguarded read-then-write sequences (`RACE-001`…`RACE-006`), row-at-a-time batch processing with intermediate commits (`PERF-001`, `PERF-004`), the same business rule implemented three times with three different answers (`VAL-001`…`VAL-004`, `ARCH-007`), and audit/history writes that are pushed into autonomous transactions where their failures are silently discarded (`ARCH-001`, `DATA-004`).

### Severity counts

| Severity | Count |
|----------|-------|
| CRITICAL | 6 |
| HIGH | 20 |
| MEDIUM | 21 |
| LOW | 5 |
| **Total** | **52** |

### Category breakdown

| ID prefix | Category | CRITICAL | HIGH | MEDIUM | LOW | Total |
|-----------|----------|----------|------|--------|-----|-------|
| `SEC` | Security vulnerabilities | 4 | 5 | 2 | 0 | 11 |
| `RACE` | Race conditions | 0 | 3 | 3 | 0 | 6 |
| `PERF` | Performance issues | 0 | 3 | 3 | 1 | 7 |
| `VAL` | Validation drift | 0 | 2 | 3 | 1 | 6 |
| `DEP` | Circular dependencies | 0 | 1 | 2 | 0 | 3 |
| `ARCH` | Architectural anti-patterns | 0 | 3 | 4 | 2 | 9 |
| `DATA` | Data-integrity risks | 2 | 3 | 4 | 1 | 10 |

### Validation status

| Check | Command | Result |
|-------|---------|--------|
| SQL lint | `sqlfluff lint --dialect oracle .` | Fails: 18 files with violations, ~2,986 violations, dominated by `CP02` (1,099 identifier casing), `LT01` (812 spacing), `LT02` (470 indent), `CP03` (268 function-name casing), `LT05` (130 long lines). One parse (`PRS`) error only: `schema/tables/03_leave_tables.sql:37`, the known SQLFluff limitation with `GENERATED ALWAYS AS … VIRTUAL`. No source change was made to appease the linter. |
| Forms XML | `find forms/xml-exports -name '*.xml' -exec xmllint --noout {} +` | Passes: all 6 exports are well-formed. |

> `DATA_DICTIONARY.md` does not exist in this repository, so documented column semantics were cross-referenced against the `COMMENT ON COLUMN` statements in `schema/tables/*.sql` and the header comments in each package spec instead.

---

## 2. Security Vulnerabilities

### SEC-001 — `authenticate` never verifies the password (authentication bypass)
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb:30-80`

```sql
    v_stored_hash VARCHAR2(200);
    v_input_hash  VARCHAR2(200);
BEGIN
    SELECT EMP_ID INTO v_emp_id FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
    ...
    -- NOTE: In the real system, passwords are stored in a separate
    -- USER_CREDENTIALS table. ...
    INSERT INTO USER_SESSIONS (...) VALUES (v_session_id, v_emp_id, p_username, ...);
    RETURN v_session_id;
```

- **Issue:** `p_password` is accepted but never used; `v_stored_hash` and `v_input_hash` are declared and never assigned or compared. The function issues a valid session for any e-mail address belonging to an active employee.
- **Impact:** Complete authentication bypass. `forms/xml-exports/HRMS_LOGIN.xml:74-93` treats a returned session id as a successful login and opens `HRMS_MENU`, so knowing any employee e-mail grants that employee's access, including HR and payroll modules.
- **Recommendation:** Introduce the `USER_CREDENTIALS` table the comment refers to, store a per-user salt plus a modern KDF digest, and make `authenticate` fail closed when no credential row exists. Until credentials exist, the function must raise instead of returning a session.

### SEC-002 — Passwords hashed with MD5
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb:14-24`

```sql
    RETURN RAWTOHEX(
        DBMS_CRYPTO.HASH(
            UTL_RAW.CAST_TO_RAW(p_password),
            DBMS_CRYPTO.HASH_MD5
        )
    );
```

- **Issue:** Unsalted MD5. MD5 is collision-broken and GPU-crackable at billions of guesses per second; identical passwords produce identical digests, so the hash list is directly rainbow-table attackable.
- **Impact:** Any leak of stored digests yields plaintext passwords for most users, which are commonly reused against other corporate systems.
- **Recommendation:** Replace with PBKDF2 (`DBMS_CRYPTO.PBKDF2` on 19c) or delegate authentication to the database/IdM layer. Store algorithm, iteration count and per-user salt alongside the digest so hashes can be upgraded in place on next login.

### SEC-003 — Encryption key hard-coded in package body
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb:7`

```sql
    -- VULNERABILITY: Encryption key hard-coded in source
    c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```

- **Issue:** The AES-256 key for SSN encryption lives in version-controlled source and in `ALL_SOURCE` for anyone with `SELECT` on the data dictionary. It is also not a `CONSTANT`, so it is writable by any code in the package. Separately, the literal is 30 bytes while `ENCRYPT_AES256` requires a 32-byte key, so `encrypt_ssn`/`decrypt_ssn` would raise ORA-28234 at runtime.
- **Impact:** Encryption of SSNs provides no protection against anyone who can read the schema source or the repository; simultaneously the encryption path is non-functional, so the "encrypted at rest" control is doubly illusory.
- **Recommendation:** Move key material out of source — Oracle Wallet + TDE column encryption for `SSN_ENCRYPTED`, or `DBMS_CRYPTO` with keys fetched from a wallet/HSM. Rotate the exposed key and re-encrypt any data produced with it.

### SEC-004 — SSN encryption is deterministic and decryption failures are masked
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb:179-206`

```sql
    v_raw := DBMS_CRYPTO.ENCRYPT(
        src => UTL_RAW.CAST_TO_RAW(p_ssn),
        typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
        key => c_encryption_key
    );
    ...
    EXCEPTION
        WHEN OTHERS THEN
            RETURN '***DECRYPT_ERROR***';
```

- **Issue:** CBC mode is used with no IV argument, so every call uses the same implicit zero IV: identical SSNs always produce identical ciphertext, allowing equality matching and duplicate detection over "encrypted" data. `decrypt_ssn` swallows every exception and returns a sentinel string, hiding key mismatch, truncation and data corruption.
- **Impact:** Ciphertext leaks equality relationships across employees and dependents; silent decrypt failures turn data-loss incidents into cosmetic display issues that nobody investigates.
- **Recommendation:** Generate a random IV per value with `DBMS_CRYPTO.RANDOMBYTES` and store it with the ciphertext (or use TDE). Let decryption failures propagate to the caller after logging.

### SEC-005 — SQL injection in `search_employees`
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:445-499`

```sql
    IF p_last_name IS NOT NULL THEN
        v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
    END IF;
    ...
        v_sql := v_sql || 'AND e.EMPLOYMENT_STATUS = ''' || p_status || ''' ';
    ...
    OPEN p_cursor FOR v_sql;
```

- **Issue:** Every search parameter is concatenated into the statement text with no binding and no quoting. All are `VARCHAR2`/`NUMBER` values that arrive from Forms search fields.
- **Impact:** A crafted last-name or status value (`x'' OR 1=1 --`) exposes arbitrary rows from any table the schema owner can read — salaries, SSN ciphertext, audit history — and can be extended to subqueries. This is the highest-impact remotely reachable vulnerability after `SEC-001`.
- **Recommendation:** Convert to a fixed statement with bind variables and `NVL`-style optional predicates, or build the text with numbered bind placeholders and `OPEN … USING`. Never interpolate caller-supplied values.

### SEC-006 — Authorization compares a surrogate key to a seniority threshold
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb:134-174`; `schema/sequences/hrms_sequences.sql:11`

```sql
    SELECT e.DEPT_ID, j.GRADE_ID INTO v_dept_id, v_grade_id
    FROM EMPLOYEES e JOIN JOB_TITLES j ON e.JOB_ID = j.JOB_ID
    WHERE e.EMP_ID = p_emp_id;
    ...
    IF v_grade_id >= 8 THEN
        RETURN TRUE;  -- Senior management - full access
```

- **Issue:** `JOB_GRADES.GRADE_ID` is a surrogate key generated by `SEQ_JOB_GRADE START WITH 100` (`schema/sequences/hrms_sequences.sql:11`), while `JOB_GRADES.GRADE_LEVEL` is the actual seniority attribute. The seed data happens to number grades 1-10 with hard-coded ids (`data/seed/01_reference_data.sql:23-41`), which masks the bug; any grade created through the sequence gets an id ≥ 100 and therefore unconditional full access. `v_dept_id` is fetched and never used, so the documented "edit own department" rule is not implemented at all.
- **Impact:** Privilege escalation the first time a grade is added through the normal path: every employee in that grade becomes an administrator of every module.
- **Recommendation:** Join on `GRADE_LEVEL` (or better, a `ROLES`/`PERMISSIONS` model as the header comment intends) and add a regression test that inserts a grade via the sequence.

### SEC-007 — No account lockout, no failed-attempt record, user enumeration
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb:26-57`; `forms/xml-exports/HRMS_LOGIN.xml:10-13`

```sql
    -- VULNERABILITY: No brute-force protection (no lockout after N failures)
    ...
        WHEN NO_DATA_FOUND THEN
            -- VULNERABILITY: Timing attack - different response time for
            -- invalid user vs invalid password
            RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
```

- **Issue:** There is no failed-attempt counter, no lockout, no delay and no record of failures anywhere (`USER_SESSIONS` only ever receives successful rows). Unknown users fail fast on a single indexed lookup while known users complete a longer path, which is an enumeration oracle.
- **Impact:** Unlimited online guessing against an MD5-backed credential store, with no detectable trail; combined with `SEC-001` there is not even a guess to make.
- **Recommendation:** Add a credential table with `FAILED_ATTEMPTS`/`LOCKED_UNTIL`, log every attempt (success and failure) to `AUDIT_LOG`, and return one uniform error after a constant-time path.

### SEC-008 — `change_password` validates complexity and stores nothing
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb:211-234`

```sql
    IF LENGTH(p_new_password) < 8 THEN
        RAISE_APPLICATION_ERROR(-20310, 'Password must be at least 8 characters');
    END IF;
    ...
    -- NOTE: Actual password update would go to USER_CREDENTIALS table
    -- This is a stub for the legacy system model
    PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
```

- **Issue:** `p_old_password` is never verified and the new password is never persisted; the procedure only writes an audit row claiming a credential update happened.
- **Impact:** Password rotation appears to succeed to users and to auditors while nothing changes — the audit trail actively misrepresents the system state, which is worse than a missing feature.
- **Recommendation:** Implement against the credential table, verify the old password, and until then raise `-20313 'not implemented'` rather than logging a false success.

### SEC-009 — Session identifiers are guessable and unbound from the caller
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb:64-72`, `98-127`; `forms/xml-exports/HRMS_EMPLOYEE.xml:30-38`

```sql
    SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
    ...
-- Forms side:
    v_session_id := TO_NUMBER(GET_APPLICATION_PROPERTY(USERNAME));
    IF NOT PKG_SECURITY.is_session_valid(v_session_id) THEN
```

- **Issue:** Sessions are identified by a small sequential integer supplied by the client, and `is_session_valid` checks only status and age — not that the session belongs to the calling user, database session or IP. `SEQ_USER_SESSION` is `NOCACHE START WITH 1` (`schema/sequences/hrms_sequences.sql:47`), so ids are trivially enumerable.
- **Impact:** Any client can present another user's session id and pass every form-level session check, inheriting that user's identity for `:GLOBAL.current_user`-driven auditing.
- **Recommendation:** Use an unguessable token (`DBMS_CRYPTO.RANDOMBYTES` → `RAW`), bind it to `SYS_CONTEXT('USERENV','SESSIONID')`/IP at creation, and verify that binding on every validation.

### SEC-010 — SMTP configuration hard-coded despite a configuration table
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:6-10`

```sql
    -- Hard-coded SMTP config (should be in SYSTEM_PARAMETERS)
    c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
    c_smtp_port    CONSTANT NUMBER := 25;
    c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
```

- **Issue:** Mail relay, port and sender identity are compile-time constants even though `SYSTEM_PARAMETERS` and `PKG_COMMON.get_param` exist for exactly this. Port 25 with no `STARTTLS` and no authentication means employee notification content crosses the network in cleartext.
- **Impact:** Environment promotion requires recompiling the package (and risks a non-production instance mailing real employees); notification bodies containing leave and performance details are sniffable.
- **Recommendation:** Read host/port/sender from `SYSTEM_PARAMETERS` at call time, add `UTL_SMTP.STARTTLS` and credentials from a wallet, and default non-production to a sink relay.

### SEC-011 — Integration file paths and formats fixed in source; import path unauthenticated
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_INTEGRATION.pkb:6-9`, `153-186`

```sql
    c_gl_output_dir       CONSTANT VARCHAR2(30) := 'GL_FEED_OUT';
    c_benefits_output_dir CONSTANT VARCHAR2(30) := 'BENEFITS_FEED_OUT';
    c_time_input_dir      CONSTANT VARCHAR2(30) := 'TIME_ATTENDANCE_IN';
    ...
    v_file := UTL_FILE.FOPEN(c_time_input_dir, p_file_name, 'R', 32767);
```

- **Issue:** `export_benefits_feed` writes employee and dependent names, dates of birth and marital status as plaintext fixed-width files to a shared directory object with no encryption and no retention control (`PKG_INTEGRATION.pkb:101-134`). `import_time_attendance` opens a caller-supplied file name from a directory object with no allow-list, checksum or provenance check.
- **Impact:** PII sits unencrypted on an application-server filesystem; anyone able to drop a file into the inbound directory feeds arbitrary content to payroll input processing.
- **Recommendation:** Encrypt or sign outbound feeds and delete them after transfer; validate inbound file names against a manifest, verify a checksum, and move processed files to an archive directory.

---

## 3. Race Conditions

### RACE-001 — Employee number generated with `MAX()+1`
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:37-55`; unused `SEQ_EMP_NUMBER` at `schema/sequences/hrms_sequences.sql:21`

```sql
    -- BUG: race condition under concurrent inserts - no SELECT FOR UPDATE
    SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
    INTO v_max_num
    FROM EMPLOYEES
    WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
```

- **Issue:** Two concurrent hires read the same maximum and generate the same `EMP-nnnnnn`. `UK_EMP_NUMBER` turns the race into a `DUP_VAL_ON_INDEX`, which the `WHEN OTHERS` handler converts into a *different* number space by falling back to `SEQ_EMPLOYEE.NEXTVAL` — mixing employee-id values into employee numbers. A dedicated `SEQ_EMP_NUMBER` exists and is never used anywhere in the codebase.
- **Impact:** Failed or duplicated hires during concurrent HR data entry, plus permanently inconsistent employee-number ranges. The full-table `MAX` also scans `EMPLOYEES` on every hire.
- **Recommendation:** `SELECT 'EMP-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0') INTO …` and delete the fallback handler so genuine errors surface.

### RACE-002 — Leave balance checked, then updated, without locking
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_LEAVE.pkb:146-185`

```sql
        v_balance := get_leave_balance(p_emp_id, p_leave_type_id);
        IF v_balance < v_total_days THEN
            RAISE_APPLICATION_ERROR(-20201, 'Insufficient leave balance. ...');
        END IF;
    ...
    UPDATE LEAVE_BALANCES
    SET PENDING = PENDING + v_total_days, ...
    WHERE EMP_ID = p_emp_id AND LEAVE_TYPE_ID = p_leave_type_id
    AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```

- **Issue:** `get_leave_balance` (`:369-387`) reads without `FOR UPDATE`, and the balance row is not locked until the later `UPDATE`. Two concurrent requests each see the full balance and both succeed. `check_leave_overlap` (`:146`) has the same read-then-insert exposure.
- **Impact:** Employees can overdraw leave balances and create overlapping approved absences by submitting requests concurrently — a direct payroll and staffing liability.
- **Recommendation:** Lock the balance row (`SELECT … FOR UPDATE`) before validating, keep the check and the update in one transaction, and add a `CHECK`/deferred constraint that `PENDING + USED` cannot exceed entitlement.

### RACE-003 — Payroll run created after an unlocked period-status read
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:231-263` (vs. the locking read at `:193-196`)

```sql
        SELECT STATUS INTO v_status
        FROM PAY_PERIODS
        WHERE PERIOD_ID = p_period_id;      -- no FOR UPDATE
    ...
        INSERT INTO PAYROLL_RUNS (...) VALUES (v_run_id, p_period_id, ..., 'DRAFT', ...);
```

- **Issue:** `close_pay_period` locks the period with `FOR UPDATE` before closing it, but `create_payroll_run` reads the same status unlocked. A run can be created against a period that is being closed concurrently, and two operators can create two runs for the same period.
- **Impact:** Duplicate or orphaned payroll runs against a closed period; downstream `VW_PAYROLL_LATEST` picks whichever run id is highest, so employees can be paid from the wrong run.
- **Recommendation:** Read the period `FOR UPDATE` inside `create_payroll_run` and add a unique constraint on `(PERIOD_ID)` for non-cancelled runs.

### RACE-004 — Salary record closed and re-inserted without locking or an overlap constraint
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:17-58`
- **Issue:** The procedure `UPDATE`s the current active row's `END_DATE`/`ACTIVE_FLAG` and then `INSERT`s the new row, with no lock on the employee's salary set and no constraint preventing two rows with `ACTIVE_FLAG = 'Y'` and overlapping effective ranges.
- **Impact:** Concurrent promotions/adjustments leave two active salary rows. Because `VW_ACTIVE_EMPLOYEES` and `VW_EMPLOYEE_COMPENSATION` join on `ACTIVE_FLAG = 'Y'` alone, one employee then appears twice in headcount and compensation reporting (see `DATA-007`).
- **Recommendation:** Lock the employee's salary rows `FOR UPDATE`, then enforce single-active with a function-based unique index on `(EMP_ID, CASE WHEN ACTIVE_FLAG='Y' THEN 1 END)`.

### RACE-005 — Session expiry read-then-update
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_SECURITY.pkb:104-121`
- **Issue:** `is_session_valid` selects `SESSION_STATUS, LOGIN_TIME` unlocked and then updates the row to `EXPIRED`. Concurrent form calls race on the same row, and the function neither commits nor rolls back the update it performs — it leaves an uncommitted change inside whatever transaction the caller happens to be running.
- **Impact:** Session expiry can be lost or rolled back with unrelated business work; a read-only validation function silently mutates the caller's transaction.
- **Recommendation:** Split the mutation out of the predicate: expire sessions in a separate autonomous `expire_sessions` job (or lock the row), and keep `is_session_valid` side-effect free.

### RACE-006 — `adjust_leave_balance` relies on update-then-create retry
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_LEAVE.pkb:392-422`
- **Issue:** The procedure `UPDATE`s the balance row, and when `SQL%ROWCOUNT = 0` calls `initialize_balances` and retries. `initialize_balances` (`:428-452`) catches `DUP_VAL_ON_INDEX` and continues, so two concurrent adjustments can interleave between the failed update and the initialize.
- **Impact:** Lost adjustments (one branch's increment overwritten) and duplicate-key noise under concurrency; balances silently diverge from the accrual log.
- **Recommendation:** Replace with a single `MERGE` on `UK_LEAVE_BAL`, or lock the row and let the unique constraint arbitrate without swallowing the exception.

---

## 4. Performance Issues

### PERF-001 — Day-by-day loops with a query per day
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_LEAVE.pkb:12-40`; also `plsql/packages/PKG_COMMON.pkb:132-165`

```sql
    WHILE v_date <= TRUNC(p_end_date) LOOP
        IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
            SELECT COUNT(*) INTO v_holiday_count
            FROM HOLIDAYS
            WHERE HOLIDAY_DATE = v_date
            AND ACTIVE_FLAG = 'Y'
            AND (LOCATION_CODE IS NULL OR LOCATION_CODE = p_location_code);
            ...
        v_date := v_date + 1;
    END LOOP;
```

- **Issue:** One context switch and one `HOLIDAYS` query per calendar day. A one-year sabbatical request performs ~260 round trips inside an interactive Forms transaction. `PKG_COMMON.business_days_between` and `add_business_days` iterate day-by-day as well.
- **Impact:** Leave submission latency scales linearly with request length; the accrual batch (`run_monthly_accrual`) multiplies this by the employee count.
- **Recommendation:** Compute weekdays arithmetically from the date difference and subtract holidays with a single set-based `COUNT(*) … BETWEEN` query; cache the holiday calendar in a PL/SQL collection for batch runs.

### PERF-002 — A new SMTP connection per notification
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:78-107`

```sql
    ) LOOP
        BEGIN
            -- Open SMTP connection
            v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
            UTL_SMTP.HELO(v_connection, c_smtp_host);
            ...
            UTL_SMTP.QUIT(v_connection);
```

- **Issue:** TCP connect + `HELO` + `QUIT` inside the loop body, once per queued message, with the whole batch's DML committed only at the end (`:137`).
- **Impact:** Batch runtime is dominated by connection setup (typically 50-200 ms each) and the relay sees a connection storm it may rate-limit as abuse; a mid-batch failure leaves the queue rows uncommitted.
- **Recommendation:** Open one connection before the loop, send all recipients over it, `QUIT` in a cleanup block, and commit incrementally per message so delivery state is durable.

### PERF-003 — Row-by-row payroll calculation with commits every 50 employees
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:271-347`, `353-550`

```sql
            IF MOD(v_emp_count, 50) = 0 THEN
                COMMIT;
            END IF;
```

- **Issue:** `calculate_payroll` loops over employees calling `calculate_employee_pay`, which itself issues multiple scalar queries and inserts per employee. Intermediate commits mean a failure at employee 300 leaves 250 employees paid and the rest not, with no run-level restart marker.
- **Impact:** Long payroll windows and an unrecoverable partial state on error — the run cannot be rolled back and re-running double-inserts `PAYROLL_DETAILS` for already-processed employees.
- **Recommendation:** Set-based calculation (or `BULK COLLECT`/`FORALL` in bounded chunks) with a single commit per run, plus a `LAST_PROCESSED_EMP_ID` checkpoint on `PAYROLL_RUNS` so restarts are idempotent.

### PERF-004 — `CONNECT BY` hierarchy in the org-chart path
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:822-839`; `schema/views/hrms_views.sql:42-57`

```sql
-- WARNING: Performance degrades significantly with >500 employees
...
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
ORDER SIBLINGS BY LAST_NAME
```

- **Issue:** `VW_ORG_HIERARCHY` walks the entire active population with `SYS_CONNECT_BY_PATH` and no depth bound; `PKG_EMPLOYEE.get_org_chart` accepts `p_max_depth` and applies it as a filter after the walk rather than pruning it. The package spec documents "times out for deep hierarchies" (`plsql/packages/PKG_EMPLOYEE.pks:10`).
- **Impact:** Org-chart screens degrade superlinearly with headcount; a data error that creates a reporting cycle produces ORA-01436 rather than a bounded result.
- **Recommendation:** Rewrite as a recursive `WITH` clause with an explicit depth predicate and `CYCLE` detection, and materialize the path for reporting consumers.

### PERF-005 — Every business sequence is `NOCACHE`
- **Severity:** MEDIUM
- **Location:** `schema/sequences/hrms_sequences.sql:9-49` (all except `SEQ_AUDIT`, line 45)

```sql
CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
...
CREATE SEQUENCE HRMS.SEQ_AUDIT START WITH 1 INCREMENT BY 1 CACHE 100;
```

- **Issue:** `NOCACHE` forces a recursive `SEQ$` update and redo write for every `NEXTVAL`. 24 of 25 sequences are `NOCACHE`, including the high-volume `SEQ_PAYROLL_DETAIL`, `SEQ_LEAVE_ACCRUAL` and `SEQ_NOTIFICATION` used inside batch loops. The file's own comment (`:19-20`) mistakenly presents gap avoidance as the reason, which is not a business requirement anywhere in the code.
- **Impact:** Row-lock contention on the sequence dictionary row during batch runs — a measurable ceiling on payroll and accrual throughput with no compensating benefit.
- **Recommendation:** `CACHE 100` (or higher for batch sequences), matching `SEQ_AUDIT`. Gaps are acceptable for surrogate keys.

### PERF-006 — Per-employee scalar queries inside `calculate_employee_pay`
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:353-550`
- **Issue:** For each employee the procedure re-queries salary, period, YTD totals and then opens a cursor over `EMPLOYEE_PAY_ELEMENTS`, inserting `PAYROLL_DETAILS` one row at a time. None of the lookups are hoisted out of the caller's loop.
- **Impact:** Thousands of avoidable SQL executions per run; YTD recomputed repeatedly for the same employee.
- **Recommendation:** Pre-aggregate salaries, deductions and YTD into a single driving query joined to the employee cursor, and insert details with `FORALL`.

### PERF-007 — Reporting views join without date bounds or aggregation guards
- **Severity:** LOW
- **Location:** `schema/views/hrms_views.sql:63-80`, `109-129`
- **Issue:** `VW_EMPLOYEE_COMPENSATION` joins `SALARY_RECORDS` on `ACTIVE_FLAG = 'Y'` with no effective-date predicate (unlike `VW_ACTIVE_EMPLOYEES`, `:32-35`), and divides by `(MIN_SALARY + MAX_SALARY) / 2` with no `NULLIF` guard. `VW_PAYROLL_LATEST` correlates to `MAX(RUN_ID)` over all approved runs rather than per period.
- **Impact:** Full scans of `SALARY_RECORDS`/`PAYROLL_DETAILS` for interactive report screens, ORA-01476 when a grade has zero-sum bounds, and "latest payroll" figures that silently mix periods.
- **Recommendation:** Add effective-date predicates, wrap divisors in `NULLIF`, and parameterize "latest run" per period via a pipelined function or a period-scoped view.

---

## 5. Validation Drift

### VAL-001 — Three different future-hire-date rules; the package has none
- **Severity:** HIGH
- **Locations:**
  - `forms/xml-exports/HRMS_EMPLOYEE.xml:382-386` — client rejects `> SYSDATE + 90`
  - `plsql/triggers/trg_employees.sql:34-38` — database rejects `> SYSDATE + 180`
  - `plsql/packages/PKG_EMPLOYEE.pkb:201-240` — `create_employee` performs no hire-date check at all

```sql
    ELSIF v_item = 'EMPLOYEE.HIRE_DATE' THEN
        IF :EMPLOYEE.HIRE_DATE > SYSDATE + 90 THEN
            MESSAGE('Hire date cannot be more than 90 days in the future');
```

```sql
    IF :NEW.HIRE_DATE > SYSDATE + 180 THEN
        RAISE_APPLICATION_ERROR(-20501,
            'Hire date cannot be more than 180 days in the future');
```

- **Issue:** The same business rule has three answers depending on entry path. Batch and API callers of `create_employee` are bounded only by the 180-day trigger; Forms users are bounded at 90 days; nothing documents which is correct.
- **Impact:** Identical data is accepted or rejected depending on which channel it arrives through, and future-dated hires between 91 and 180 days exist only when created outside the form — corrupting headcount-as-of reporting.
- **Recommendation:** Pick one limit, express it as a `SYSTEM_PARAMETERS` value, enforce it in `PKG_VALIDATION`, and have both the Forms trigger and the database trigger call that single function.

### VAL-002 — Three incompatible e-mail validators
- **Severity:** HIGH
- **Locations:**
  - `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41` — hand-rolled `INSTR` check, NULL treated as valid
  - `plsql/packages/PKG_COMMON.pkb:265-268` — `REGEXP_LIKE('^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')`
  - `plsql/packages/PKG_VALIDATION.pkb:50-55` — delegates to `PKG_COMMON`

```sql
    v_dot_pos := INSTR(p_email, '.', v_at_pos);
    IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN
        RETURN FALSE;
    END IF;
    -- BUG: Only checks for one dot after @, rejects valid subdomains
```

- **Issue:** The PLL implementation rejects addresses the server accepts (documented at `:17-19`), and the Forms `WHEN-VALIDATE-ITEM` trigger calls the *server* function (`HRMS_EMPLOYEE.xml:375-380`) while other PLL consumers call the client one — so the effective rule depends on which code path fires.
- **Impact:** Legitimate `user@mail.company.com` addresses are rejected in some screens and accepted in others; data quality depends on entry path, and `PKG_SECURITY.authenticate` keys on `EMAIL`, so malformed or duplicated addresses become login problems.
- **Recommendation:** Delete `HRMS_VALIDATION_LIB.validate_email` and make the PLL a thin wrapper over `PKG_VALIDATION.validate_email_format`, so client and server cannot diverge again.

### VAL-003 — Salary range: client blocks, server warns
- **Severity:** MEDIUM
- **Locations:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:108-135`; `plsql/packages/PKG_VALIDATION.pkb:17-48`; `plsql/packages/PKG_EMPLOYEE.pkb:220-241`

```sql
                IF p_base_salary < v_min OR p_base_salary > v_max THEN
                    -- NOTE: This is a soft warning, not an error
                    -- Forms trigger WHEN-VALIDATE-ITEM shows warning dialog
                    -- but allows override with manager approval
                    IF g_debug_mode THEN
                        DBMS_OUTPUT.PUT_LINE('WARNING: Salary ' || p_base_salary || ...
```

- **Issue:** Three implementations of one rule with three behaviours and three message formats: the PLL returns `'Below minimum ($999,999)'`, `PKG_VALIDATION` returns a longer sentence naming the grade, and `PKG_EMPLOYEE.create_employee` only writes to `DBMS_OUTPUT` when `g_debug_mode` is on — i.e. out-of-band salaries are accepted silently. No "manager approval" mechanism exists anywhere in the codebase despite the comment.
- **Impact:** Compensation guardrails are unenforced on every non-Forms path, and the audit trail contains no record that an override happened.
- **Recommendation:** Have all three paths call `PKG_VALIDATION.validate_salary_for_grade`, and if overrides are legitimate, model them explicitly (`OVERRIDE_BY`, `OVERRIDE_REASON` columns) instead of a debug-only message.

### VAL-004 — Comments describe a cache that does not exist
- **Severity:** MEDIUM
- **Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:100-124`

```sql
-- Checks salary against grade range using cached local data
-- BUG: Uses a hard-coded cache that's populated at form startup
-- and never refreshed. ...
    -- Direct DB query (not cached - contradicts the comment above)
    SELECT MIN_SALARY, MAX_SALARY INTO v_min, v_max
    FROM JOB_GRADES WHERE GRADE_ID = p_grade_id;
```

- **Issue:** The header comment claims a stale client cache; the body performs a direct query. Two adjacent comments contradict each other and the code.
- **Impact:** Maintainers reason about performance and staleness from documentation that is wrong in both directions — the recurring pattern in this codebase where comments must be distrusted (see also `DATA-006`, `DATA-008`).
- **Recommendation:** Delete the stale comments as part of consolidating the validator (`VAL-002`); every remaining comment in the PLL should be verified against its body.

### VAL-005 — `validate_date_range` conflates NULL with invalid
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_VALIDATION.pkb:6-15`

```sql
        IF p_start_date IS NULL OR p_end_date IS NULL THEN
            RETURN FALSE;
        END IF;
        RETURN p_end_date >= p_start_date;
```

- **Issue:** NULL means "invalid range" here, while the PLL e-mail validator returns `TRUE` for NULL ("not a required check"). The two libraries use opposite NULL conventions, and callers cannot distinguish "missing" from "inverted".
- **Impact:** Optional date ranges are rejected as invalid, or required ones pass, depending on which validator a screen happens to use.
- **Recommendation:** Standardize on "NULL is not a range violation; requiredness is a separate check", and add explicit `validate_required` calls where a value is mandatory.

### VAL-006 — `validate_required_fields` is hard-coded to `EMPLOYEES`
- **Severity:** LOW
- **Location:** `plsql/packages/PKG_VALIDATION.pkb:99-122`
- **Issue:** The procedure is parameterized by table name but only implements the `EMPLOYEES` field list, silently passing for every other table.
- **Impact:** Callers validating leave, payroll or performance records receive a successful result from a check that did nothing.
- **Recommendation:** Drive the rules from a metadata table (or `ALL_TAB_COLUMNS` `NULLABLE`), and raise for unknown table names rather than returning success.

---

## 6. Circular Dependencies

### DEP-001 — `PKG_EMPLOYEE` ↔ `PKG_PAYROLL`
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:271-280`; `plsql/packages/PKG_EMPLOYEE.pks:6-9`; `plsql/packages/PKG_PAYROLL.pks:6-9`

```sql
            -- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
            -- which in turn may call PKG_EMPLOYEE.is_active for validation
            PKG_PAYROLL.create_salary_record(
                p_emp_id => v_emp_id, ...
```

- **Issue:** Both package specs document the cycle as a known issue. `PKG_EMPLOYEE.create_employee` calls into payroll to create the salary record, and payroll calls back into `PKG_EMPLOYEE.is_active` for validation.
- **Impact:** Recompiling either package invalidates the other, so any change forces a coordinated redeploy and can leave dependent objects `INVALID` in production. It also makes the hire transaction span two modules with interleaved validation, which is why the salary-range rule ended up implemented three times (`VAL-003`).
- **Recommendation:** Extract the shared employment-status predicate into `PKG_COMMON` (or a view), and invert the dependency so the hire orchestration lives in one place and calls downward only.

### DEP-002 — `PKG_SECURITY` → `PKG_EMPLOYEE` while all modules call `PKG_SECURITY`
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_SECURITY.pkb:75`; `forms/libraries/HRMS_COMMON_LIB.pll.sql:127-138`

```sql
        PKG_EMPLOYEE.set_session_context(p_username, v_emp_id);
```

- **Issue:** Authentication writes into `PKG_EMPLOYEE`'s package-level session globals (`PKG_EMPLOYEE.pks:14-16`), while `PKG_EMPLOYEE`'s own callers and every form depend on `PKG_SECURITY` for session and permission checks — a second dependency loop, this one undocumented.
- **Impact:** Session state lives in a business package's package variables, so it is per-database-session mutable global state that any code can overwrite; the loop compounds the recompilation fragility from `DEP-001`.
- **Recommendation:** Hold session context in a secure application context (`DBMS_SESSION.SET_CONTEXT` with a trusted package) and have both `PKG_SECURITY` and `PKG_EMPLOYEE` read from it.

### DEP-003 — Every module depends on autonomous-commit utility packages
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_COMMON.pkb:10-61`; `plsql/packages/PKG_AUDIT.pkb:6-31`; call sites across `PKG_EMPLOYEE`, `PKG_LEAVE`, `PKG_PAYROLL`, `PKG_PERFORMANCE`, `PKG_INTEGRATION`, `PKG_SECURITY`, `trg_audit.sql`
- **Issue:** `PKG_COMMON` and `PKG_AUDIT` are leaf dependencies of everything, including row-level triggers, and both commit independently. Combined with `DEP-001`/`DEP-002` the dependency graph has no acyclic layering: triggers → packages → triggers.
- **Impact:** A change to logging signatures invalidates the entire schema; trigger-invoked autonomous commits make transaction boundaries unpredictable (see `ARCH-001`).
- **Recommendation:** Freeze the utility package interfaces, and route trigger-side audit writes through a queue table written in the caller's transaction rather than an autonomous commit.

---

## 7. Architectural Anti-Patterns

### ARCH-001 — Autonomous transactions used for audit, history and notifications
- **Severity:** HIGH
- **Locations:** `plsql/packages/PKG_AUDIT.pkb:14`; `plsql/packages/PKG_COMMON.pkb:16`, `:46`; `plsql/packages/PKG_EMPLOYEE.pkb:155`; `plsql/packages/PKG_NOTIFICATION.pkb:27`

```sql
    ) IS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        INSERT INTO AUDIT_LOG (...) VALUES (...);
        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            -- Audit logging must never fail the calling transaction
            ROLLBACK;
```

- **Issue:** Five separate autonomous-transaction sites commit independently of the business transaction, and all of them swallow `WHEN OTHERS`. `PKG_EMPLOYEE.log_history` (`:137-179`) does the same for `EMPLOYEE_HISTORY`, and `PKG_NOTIFICATION.send_notification` commits the queue row before the triggering business change is durable.
- **Impact:** Audit rows, history rows and outbound notifications persist for business transactions that later roll back — the audit trail records events that never happened, and employees receive e-mail about approvals that were reversed. Because failures are swallowed, missing audit rows are undetectable (`DATA-004` is exactly this failure mode).
- **Recommendation:** Write audit/history in the caller's transaction so it commits atomically with the change; if isolation from rollback is genuinely required, use a transactional queue (`DBMS_AQ`) drained after commit. Never combine an autonomous commit with a silent `WHEN OTHERS`.

### ARCH-002 — Hard-coded 2024 tax constants alongside an unused `TAX_BRACKETS` table
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:7-14`, `603-686`, `688-718`

```sql
    c_ss_wage_base_2024   CONSTANT NUMBER := 168600;   -- Social Security wage base
...
    -- NOTE: Hard-coded 2024 brackets - should read from TAX_BRACKETS table
    -- TODO: Read from TAX_BRACKETS table instead of hard-coding
        -- 2024 Federal tax brackets (Single)
```

- **Issue:** Federal brackets, the Social Security wage base and state rates are compile-time constants for tax year 2024; `calculate_state_tax` defaults any unrecognized state to a flat 5%. A `TAX_BRACKETS` table and `SEQ_TAX_BRACKET` (`schema/sequences/hrms_sequences.sql:30`) exist and are never read. The package spec documents this (`PKG_PAYROLL.pks:10`).
- **Impact:** Payroll under-withholds or over-withholds for every year after 2024 and for every state not in the hard-coded list — a compliance and restatement exposure that requires a code release (not a data change) to fix, every January.
- **Recommendation:** Load brackets, wage bases and state rates from `TAX_BRACKETS` keyed by effective date and filing status; fail loudly on a missing jurisdiction rather than defaulting to 5%.

### ARCH-003 — Stub implementations that report success
- **Severity:** HIGH
- **Locations:** `plsql/packages/PKG_INTEGRATION.pkb:164-186`, `196-203`; `plsql/packages/PKG_REPORTING.pkb:196-204`

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

- **Issue:** `import_time_attendance` counts lines and logs "Imported: n" without parsing or storing anything. `sync_org_structure` and `refresh_reporting_tables` log "completed"/"refreshed" while doing nothing at all.
- **Impact:** Operators and monitoring see successful integration runs while time-and-attendance data never reaches payroll (so overtime is silently unpaid) and reporting tables are never refreshed. False success signals are worse than failures because nobody investigates them.
- **Recommendation:** Implement or remove. Any retained stub must raise `-20xxx 'not implemented'`; success must never be logged by a procedure that performed no work.

### ARCH-004 — Forms performs direct DML on `EMPLOYEES`, bypassing the business package
- **Severity:** MEDIUM
- **Location:** `forms/xml-exports/HRMS_EMPLOYEE.xml:110-117`, `322-343`

```xml
  <Block Name="EMPLOYEE" QueryDataSourceType="Table"
         QueryDataSourceName="HRMS.EMPLOYEES"
         DMLDataTargetType="Table" DMLDataTargetName="HRMS.EMPLOYEES"
```

```sql
BEGIN
    :EMPLOYEE.EMP_ID := SEQ_EMPLOYEE.NEXTVAL;
    :EMPLOYEE.EMP_NUMBER := PKG_EMPLOYEE.generate_emp_number;
```

- **Issue:** The block writes straight to the base table, so `PKG_EMPLOYEE.create_employee` — with its department/manager/job validation, history logging and payroll integration — is never invoked for interactive hires. Only the (broken) database triggers stand between the form and the table.
- **Impact:** Interactive hires skip validation, history and salary-record creation entirely; the same operation has two implementations that diverge over time. This is the root cause of the drift catalogued in `VAL-001`/`VAL-003`.
- **Recommendation:** Convert the block to `QueryDataSourceType="Procedure"` (or transactional triggers `ON-INSERT`/`ON-UPDATE`/`ON-DELETE`) delegating to `PKG_EMPLOYEE`, so there is exactly one write path.

### ARCH-005 — Flat-file integration via `UTL_FILE`
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_INTEGRATION.pkb:16-83`, `90-147`
- **Issue:** GL journals and the ADP benefits feed are produced as pipe-delimited and fixed-width files written by `UTL_FILE` from inside the database, with formats hard-coded in PL/SQL string concatenation and no schema, header versioning or acknowledgement.
- **Impact:** Format changes require package recompiles; the database owns filesystem concerns and fails on directory/permission drift; there is no delivery confirmation, so a lost file is invisible.
- **Recommendation:** Move file production to an integration layer (or Oracle external tables/`DBMS_CLOUD` for inbound) and define the interchange format in a versioned artefact shared with the counterparty.

### ARCH-006 — Fiscal-year and calendar-year semantics mixed
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_COMMON.pkb:167-195`; `schema/tables/03_leave_tables.sql:41`; `schema/views/hrms_views.sql:102`

```sql
    -- get_fiscal_year (fiscal year starts Oct 1)
    IF EXTRACT(MONTH FROM p_date) >= 10 THEN
        RETURN EXTRACT(YEAR FROM p_date) + 1;
```

- **Issue:** An October-start fiscal year is hard-coded in `PKG_COMMON`, while leave balances (`CALENDAR_YEAR`), the leave views (`EXTRACT(YEAR FROM SYSDATE)`) and payroll YTD all use calendar years. Nothing reconciles the two, and the fiscal boundary is not configurable.
- **Impact:** Any report combining fiscal and calendar aggregates is off by a quarter; a company with a different fiscal start needs a code change.
- **Recommendation:** Store the fiscal-year start month in `SYSTEM_PARAMETERS`, and label every year-bearing column and API explicitly as fiscal or calendar.

### ARCH-007 — Errors logged into `AUDIT_LOG` as hand-built JSON; no error table
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_COMMON.pkb:10-61`

```sql
        INSERT INTO AUDIT_LOG (
            AUDIT_ID, TABLE_NAME, RECORD_ID, ACTION_TYPE, ...
        ) VALUES (
            SEQ_AUDIT.NEXTVAL, 'ERROR_LOG', 0, 'INSERT',
            NULL,
            '{"package":"' || p_package || '","procedure":"' || p_procedure ||
            '","message":"' || REPLACE(SUBSTR(p_message, 1, 3000), '"', '\"') || '"}',
```

- **Issue:** There is no `ERROR_LOG` table; errors are written as pseudo-rows into `AUDIT_LOG` with `TABLE_NAME = 'ERROR_LOG'`, `RECORD_ID = 0` and a JSON string assembled by concatenation (escaping only double quotes, not backslashes or control characters). The fallback is `DBMS_OUTPUT`, which nothing captures in a Forms deployment.
- **Impact:** Error diagnostics are unqueryable by severity or component, pollute the compliance audit trail, and can be malformed JSON; when logging itself fails the diagnostic is lost entirely.
- **Recommendation:** Add a dedicated `ERROR_LOG` table (severity, package, procedure, `SQLCODE`, backtrace, context) and build payloads with `JSON_OBJECT` instead of string concatenation.

### ARCH-008 — `get_payslip` returns placeholder YTD figures
- **Severity:** LOW
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:763-797`

```sql
                   0 AS YTD_GROSS,  -- Placeholder
                   0 AS YTD_NET     -- Placeholder
```

- **Issue:** The payslip cursor returns literal zeros for the `ytd_gross`/`ytd_net` fields declared in `t_payslip_rec` (`PKG_PAYROLL.pks:37-38`), even though `calculate_employee_pay` computes YTD gross internally (`:413`).
- **Impact:** Every payslip shows $0 year-to-date, which employees read as a system error and payroll must explain manually.
- **Recommendation:** Aggregate YTD from `PAYROLL_DETAILS` for the calendar year in the same query, or persist YTD on the detail rows.

### ARCH-009 — Duplicated `MESSAGE` call justified by an incorrect comment
- **Severity:** LOW
- **Location:** `forms/libraries/HRMS_COMMON_LIB.pll.sql:16-38`

```sql
    MESSAGE(p_module || '.' || p_location || ': ' || v_errmsg);
    MESSAGE(p_module || '.' || p_location || ': ' || v_errmsg);
    -- NOTE: MESSAGE called twice intentionally - Oracle Forms requires
    -- two calls to ensure message displays on the status bar
```

- **Issue:** The duplicate call is a cargo-culted workaround; the actual Forms idiom for suppressing the "press any key" acknowledgement is `MESSAGE(text, NO_ACKNOWLEDGE)`. The comment presents folklore as a platform requirement.
- **Impact:** Users see every error twice; the pattern is copied into new code because the comment asserts it is mandatory.
- **Recommendation:** Single `MESSAGE(..., NO_ACKNOWLEDGE)` call and remove the comment.

---

## 8. Data-Integrity Risks

### DATA-001 — Trigger inserts `EMPLOYEE_HISTORY` columns that do not exist
- **Severity:** CRITICAL
- **Location:** `plsql/triggers/trg_employees.sql:76-110` vs. `schema/tables/01_core_tables.sql:152-177`

```sql
        INSERT INTO EMPLOYEE_HISTORY (
            HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
            OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
        ) VALUES (
            SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'STATUS_CHANGE', SYSDATE, ...
```

```sql
CREATE TABLE HRMS.EMPLOYEE_HISTORY (
    HIST_ID              NUMBER(15)      NOT NULL,
    EMP_ID               NUMBER(10)      NOT NULL,
    CHANGE_TYPE          VARCHAR2(30)    NOT NULL,
    EFFECTIVE_DATE       DATE            NOT NULL,
    OLD_DEPT_ID          NUMBER(10),  NEW_DEPT_ID  NUMBER(10),
    ... REASON_CODE, COMMENTS, CREATED_BY, CREATED_DATE
```

- **Issue:** Six of the eight columns the trigger writes (`HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON`) do not exist. The table uses `HIST_ID`, `EFFECTIVE_DATE`, typed old/new pairs, `REASON_CODE`, `COMMENTS` and `CREATED_BY` — exactly the names `PKG_EMPLOYEE.log_history` uses correctly (`PKG_EMPLOYEE.pkb:157-165`). Three `INSERT` statements are affected (`:78`, `:90`, `:102`).
- **Impact:** `TRG_EMP_BEFORE_UPDATE` fails to compile with ORA-00904, so it is created `INVALID` and every `UPDATE` on `EMPLOYEES` that changes status, department or job raises ORA-04098/ORA-00904. Employee transfers, terminations and status changes are impossible through any path — including `PKG_EMPLOYEE.transfer_employee` and the Forms block. Employment history is not recorded.
- **Recommendation:** Rewrite the trigger against the real DDL (or delete it and rely on `PKG_EMPLOYEE.log_history`, which is already correct — preferable, since duplicating history writes in both a trigger and a package produces double rows). Add a deployment gate that compiles all triggers and fails the build on `INVALID` objects.

### DATA-002 — Row trigger queries its own table (mutating table)
- **Severity:** CRITICAL
- **Location:** `plsql/triggers/trg_employees.sql:40-54`

```sql
    DECLARE
        v_count NUMBER;
    BEGIN
        SELECT COUNT(*) INTO v_count
        FROM EMPLOYEES
        WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL)
        AND ACTIVE_FLAG = 'Y';
```

- **Issue:** A `FOR EACH ROW` trigger on `EMPLOYEES` reads `EMPLOYEES`. Oracle raises ORA-04091 (table is mutating) for a row trigger querying its own table.
- **Impact:** Every insert into `EMPLOYEES` fails at runtime — the Forms hire path (`ARCH-004`), `PKG_EMPLOYEE.create_employee` and the seed script in `data/seed/02_employee_data.sql` all break. Combined with `DATA-001`, the employee table is effectively read-only as shipped.
- **Recommendation:** Delete the check and enforce uniqueness declaratively with a unique index on `UPPER(EMAIL)` (see `DATA-005`), which also gives the "better error message" via a named constraint. If a friendlier message is required, do the lookup in `PKG_EMPLOYEE` before the DML, not in a row trigger.

### DATA-003 — Trigger writes `CHANGE_TYPE` values the check constraint forbids
- **Severity:** HIGH
- **Location:** `plsql/triggers/trg_employees.sql:94`, `:106` vs. `schema/tables/01_core_tables.sql:173-176`

```sql
            SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'DEPARTMENT_CHANGE', SYSDATE,
...
            SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'JOB_CHANGE', SYSDATE,
```

```sql
    CONSTRAINT CHK_CHANGE_TYPE CHECK (CHANGE_TYPE IN (
        'HIRE', 'TRANSFER', 'PROMOTION', 'DEMOTION', 'SALARY_CHANGE',
        'TERMINATION', 'REHIRE', 'LEAVE_START', 'LEAVE_END', 'STATUS_CHANGE'
    ))
```

- **Issue:** `DEPARTMENT_CHANGE` and `JOB_CHANGE` are not in the allowed list (the DDL's vocabulary is `TRANSFER`/`PROMOTION`). Even after the column names in `DATA-001` are fixed, these two inserts violate `CHK_CHANGE_TYPE`.
- **Impact:** Department and job changes would still fail with ORA-02290 — a second, independent blocker on the same code path, easy to miss when fixing only the column names.
- **Recommendation:** Map to the constrained vocabulary (`TRANSFER` for department, `PROMOTION`/`DEMOTION` for job) and add the mapping to the same regression test that covers `DATA-001`.

### DATA-004 — Audit trigger passes an action the constraint rejects, and the failure is swallowed
- **Severity:** HIGH
- **Location:** `plsql/triggers/trg_audit.sql:47-59`; `schema/tables/04_performance_tables.sql:96`, `:104`; `plsql/packages/PKG_AUDIT.pkb:27-31`

```sql
    PKG_AUDIT.log_action(
        'LEAVE_REQUESTS',
        :NEW.REQUEST_ID,
        'STATUS_CHANGE',
```

```sql
    ACTION_TYPE          VARCHAR2(10)    NOT NULL,
...
    CONSTRAINT CHK_AUDIT_ACTION CHECK (ACTION_TYPE IN ('INSERT', 'UPDATE', 'DELETE'))
```

- **Issue:** `'STATUS_CHANGE'` is 13 characters against a `VARCHAR2(10)` column and is not in `CHK_AUDIT_ACTION`, so the insert fails twice over (ORA-12899, then ORA-02290). `PKG_AUDIT.log_action` catches `WHEN OTHERS` and rolls back its autonomous transaction, so nothing surfaces.
- **Impact:** Leave approvals, rejections and cancellations are never audited, and nothing anywhere reports the loss — the compliance trail has a hole that no monitoring can detect. `TRG_SALARY_AUDIT` (`:10-40`) and `TRG_DEPARTMENT_AUDIT` (`:66-83`) pass valid actions but depend on the same silent-failure path, so their audit rows disappear on any future constraint violation too.
- **Recommendation:** Use `'UPDATE'` (or widen the constraint deliberately), and change `log_action` to log to an out-of-band channel and re-raise on constraint violations instead of discarding them.

### DATA-005 — E-mail uniqueness documented but never enforced
- **Severity:** HIGH
- **Location:** `plsql/triggers/trg_employees.sql:40-41`; `schema/tables/01_core_tables.sql:109`, `:134-142`; `plsql/packages/PKG_SECURITY.pkb:51-56`

```sql
    -- Validate email uniqueness (also enforced by unique constraint, but
    -- this trigger provides a better error message)
```

- **Issue:** There is no unique constraint or index on `EMPLOYEES.EMAIL` — the table has only `PK_EMPLOYEES` and `UK_EMP_NUMBER`. The comment is wrong, and the trigger that was supposed to compensate cannot run (`DATA-002`). `PKG_SECURITY.authenticate` explicitly handles `TOO_MANY_ROWS` by picking `MIN(EMP_ID)`, confirming duplicates are expected in practice.
- **Impact:** Duplicate e-mail addresses are accepted, and since `EMAIL` is the login identifier, a duplicate silently maps a login to whichever employee has the lowest id — authenticating one person as another. Notifications are delivered to the wrong employee for the same reason.
- **Recommendation:** Add `CREATE UNIQUE INDEX UK_EMP_EMAIL ON EMPLOYEES (UPPER(EMAIL))` after de-duplicating existing data, and remove the `TOO_MANY_ROWS` handler so the impossible case raises.

### DATA-006 — Soft-delete story contradicts itself across three layers
- **Severity:** MEDIUM
- **Location:** `plsql/triggers/trg_employees.sql:114-129`; `forms/xml-exports/HRMS_EMPLOYEE.xml:116`; `forms/libraries/HRMS_COMMON_LIB.pll.sql:88-91`

```sql
-- TRG_EMP_AFTER_DELETE
-- Soft delete: instead of actual deletion, marks record as inactive
...
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
BEFORE DELETE ON HRMS.EMPLOYEES
FOR EACH ROW
BEGIN
    -- BUG: This actually prevents deletion, but Forms expects DELETE to succeed.
    RAISE_APPLICATION_ERROR(-20504,
        'Direct deletion not allowed. ...');
```

- **Issue:** Four inconsistencies in one object: the header comment says `AFTER DELETE`, the name says `INSTEAD_OF`, the code is `BEFORE DELETE`, and the documented "soft delete" never sets `ACTIVE_FLAG` — it just raises. Meanwhile the Forms block is `DeleteAllowed="Yes"` and the shared toolbar wires a delete button straight to `DELETE_RECORD`.
- **Impact:** Users get raw ORA-20504 on a button the UI presents as available; the "workaround" is documented only in a code comment, so soft deletion depends on each developer remembering it. Deactivated employees are inconsistent because nothing enforces the `ACTIVE_FLAG` path.
- **Recommendation:** Set `DeleteAllowed="No"` on the block, remove the delete toolbar action for this form, and either implement soft delete in an `INSTEAD OF` trigger on an updatable view or expose only `PKG_EMPLOYEE.terminate_employee`. Rename the trigger to match its behaviour.

### DATA-007 — `VW_LEAVE_SUMMARY.AVAILABLE` omits `PENDING`
- **Severity:** MEDIUM
- **Location:** `schema/views/hrms_views.sql:96` vs. `schema/tables/03_leave_tables.sql:47` and `plsql/packages/PKG_LEAVE.pkb:376-381`

```sql
       lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,
```

```sql
    AVAILABLE  NUMBER(6,2) GENERATED ALWAYS AS
        (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL,
```

- **Issue:** The table's virtual column and `PKG_LEAVE.get_leave_balance` both subtract `PENDING`; the reporting view recomputes the same concept without it. `PKG_REPORTING.leave_utilization_report` (`plsql/packages/PKG_REPORTING.pkb:132-136`) repeats the view's incorrect formula for `AVG_REMAINING` and the utilization percentage.
- **Impact:** Self-service screens and reports show a higher available balance than the engine will authorize, so employees plan leave they cannot book and managers approve against inflated numbers. Three implementations of one formula guarantee future drift.
- **Recommendation:** Select the `AVAILABLE` virtual column directly in both the view and the report rather than recomputing it.

### DATA-008 — Leave balance year derived inconsistently; missing rows fail silently
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_LEAVE.pkb:146-148` vs. `:175-185`

```sql
            v_balance := get_leave_balance(p_emp_id, p_leave_type_id);   -- defaults to current year
    ...
    UPDATE LEAVE_BALANCES
    SET PENDING = PENDING + v_total_days, ...
    AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);                 -- year of the request
```

- **Issue:** The balance is validated against the *current* calendar year but the pending reservation is applied to the year of the leave start date, and `SQL%ROWCOUNT` is never checked — if no balance row exists for that year the update quietly affects zero rows.
- **Impact:** A December request for January leave is checked against the wrong year's balance and reserves nothing, so the same days can be booked repeatedly. Balances silently diverge from approved requests, and `expire_carryover`/`process_carryover` (documented as double-running at `PKG_LEAVE.pks:10`) compound the drift.
- **Recommendation:** Pass `EXTRACT(YEAR FROM p_start_date)` to `get_leave_balance`, `MERGE` the balance row so it is created when absent, and raise when the reservation affects zero rows.

### DATA-009 — SSN encryption is dead code; the column comment asserts otherwise
- **Severity:** MEDIUM
- **Location:** `schema/tables/01_core_tables.sql:146`; `plsql/packages/PKG_SECURITY.pkb:179-206`

```sql
COMMENT ON COLUMN HRMS.EMPLOYEES.SSN_ENCRYPTED IS 'AES-256 encrypted SSN - decrypted only in PKG_SECURITY';
```

- **Issue:** `encrypt_ssn` and `decrypt_ssn` have no callers anywhere in the repository (verified across `plsql/`, `forms/`, `schema/`, `data/`), and no code path ever writes `SSN_ENCRYPTED` — not `PKG_EMPLOYEE.create_employee`, not the Forms employee block, not the seed data. `EMPLOYEE_DEPENDENTS.SSN_ENCRYPTED` (`:189`) is equally unwritten.
- **Impact:** The documented data-protection control does not exist in the code; whatever populates the column in production does so outside this codebase, with unknown encryption. Auditors reading the comment (and `SEC-003`/`SEC-004`) would conclude SSNs are protected when nothing here protects them.
- **Recommendation:** Wire the hire/update paths through `encrypt_ssn` (after fixing key management per `SEC-003`), or drop the columns and the comment if SSNs are held elsewhere. Whichever is true must be documented accurately.

### DATA-010 — Tenure computed two ways
- **Severity:** LOW
- **Location:** `schema/views/hrms_views.sql:15` vs. `plsql/packages/PKG_EMPLOYEE.pkb:865-880`

```sql
       TRUNC(MONTHS_BETWEEN(SYSDATE, e.HIRE_DATE) / 12, 1) AS TENURE_YEARS,
```

```sql
        RETURN ROUND(MONTHS_BETWEEN(v_end_date, v_hire_date) / 12, 1);
```

- **Issue:** The view truncates to one decimal and always measures to `SYSDATE`; the package rounds and measures to `NVL(TERMINATION_DATE, SYSDATE)`. `PKG_REPORTING.headcount_report` (`:22`) uses a third variant (`ROUND(AVG(...))`).
- **Impact:** Tenure-based reports and screens disagree by up to 0.1 years, and terminated employees show growing tenure in the view — enough to affect service-award and vesting eligibility decisions.
- **Recommendation:** Expose one deterministic tenure function (or a virtual column) and have the views and reports call it.

---

## 9. Prioritized Migration Roadmap

Ordering is by risk-adjusted urgency: Phase 1 items are exploitable or already break production; Phase 2 restores correctness of the record of truth; Phase 3 makes the system scale; Phase 4 pays down structural debt in preparation for migration off Forms.

### Phase 1 — Critical security (immediate)
| Order | Findings | Work |
|-------|----------|------|
| 1 | `SEC-001`, `SEC-008` | Implement real credential storage and verification; `authenticate` and `change_password` must fail closed until it exists. |
| 2 | `SEC-005` | Convert `search_employees` to bind variables; audit every other `EXECUTE IMMEDIATE`/`OPEN … FOR` for concatenation. |
| 3 | `SEC-002`, `SEC-003`, `SEC-004` | Move key material to a wallet, rotate the exposed key, replace MD5 with PBKDF2, add per-value IVs, stop masking decrypt errors. |
| 4 | `SEC-006`, `SEC-009`, `SEC-007` | Fix the `GRADE_ID`/`GRADE_LEVEL` authorization bug, issue unguessable session tokens bound to the caller, add lockout plus failed-attempt auditing. |
| 5 | `SEC-010`, `SEC-011` | Externalize SMTP config with TLS; encrypt/expire PII feed files and validate inbound files. |

**Exit criteria:** no credential path returns a session without verification; no dynamic SQL concatenates caller input; no key material or endpoint config in source; failed logins are rate-limited and auditable.

### Phase 2 — Data integrity (next, and a prerequisite for any migration)
| Order | Findings | Work |
|-------|----------|------|
| 1 | `DATA-001`, `DATA-002`, `DATA-003` | Fix or remove the `EMPLOYEES` triggers so inserts and updates work; add a build gate that fails on `INVALID` objects. |
| 2 | `DATA-004`, `ARCH-001` | Make audit writes transactional and non-silent; correct the rejected `ACTION_TYPE`. |
| 3 | `DATA-005`, `RACE-004` | Add the unique index on `UPPER(EMAIL)` and the single-active-salary index; de-duplicate existing data first. |
| 4 | `DATA-007`, `DATA-008`, `DATA-010` | Single definition each for available leave, balance year and tenure; views and reports consume them. |
| 5 | `DATA-006`, `DATA-009` | Resolve the soft-delete contradiction; make SSN handling match its documentation. |
| 6 | `RACE-001`, `RACE-002`, `RACE-003`, `RACE-005`, `RACE-006` | Replace `MAX()+1` with the existing sequence; add `FOR UPDATE` (or `MERGE`) to every check-then-write path. |

**Exit criteria:** every trigger and package compiles `VALID`; every DML column list is verified against DDL by a test; concurrent-submission tests cannot overdraw a balance, duplicate an employee number or double-run a payroll period.

### Phase 3 — Performance (after correctness)
| Order | Findings | Work |
|-------|----------|------|
| 1 | `PERF-003`, `PERF-006` | Set-based/bulk payroll calculation with a single commit and a restart checkpoint. |
| 2 | `PERF-001` | Arithmetic business-day calculation with one holiday query. |
| 3 | `PERF-002` | One SMTP connection per batch, incremental commits. |
| 4 | `PERF-005` | `CACHE` the sequences. |
| 5 | `PERF-004`, `PERF-007` | Recursive `WITH` + `CYCLE` for hierarchy; add date predicates and `NULLIF` guards to views. |

**Exit criteria:** payroll and accrual runtimes scale sub-linearly with headcount and are restartable; no interactive path issues per-day or per-row round trips.

### Phase 4 — Modernization (structural, enables Forms exit)
| Order | Findings | Work |
|-------|----------|------|
| 1 | `VAL-001`…`VAL-006`, `ARCH-004` | Collapse client/server/trigger validation into `PKG_VALIDATION` as the single rule engine; route Forms DML through `PKG_EMPLOYEE` so there is one write path. |
| 2 | `DEP-001`, `DEP-002`, `DEP-003` | Break the package cycles; move session state to a secure application context; establish an acyclic layering (utilities → domain → orchestration). |
| 3 | `ARCH-002`, `ARCH-006` | Data-driven tax tables and configurable fiscal calendar — no year or jurisdiction constants in code. |
| 4 | `ARCH-003`, `ARCH-008` | Implement or remove the stubs; never log success for work not done. |
| 5 | `ARCH-005`, `ARCH-007`, `ARCH-009` | Replace `UTL_FILE` interchange with an integration layer; add a real `ERROR_LOG` with structured JSON; clean up the PLL folklore. |
| 6 | Cross-cutting | Adopt `sqlfluff` in CI with a per-directory rule baseline (see validation status) so the ~3k style violations are burned down without blocking delivery. |

**Exit criteria:** one implementation per business rule, an acyclic dependency graph, no fiscal/tax constants in code, and a lint/compile gate in CI — the preconditions for extracting business logic out of Forms into a service layer.
