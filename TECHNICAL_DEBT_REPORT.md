# Technical Debt Report — Oracle Forms HRMS

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Scope:** `plsql/packages/`, `plsql/triggers/`, `schema/`, `forms/`, `data/seed/`
**Method:** static review of every PL/SQL package spec/body, trigger, table/view/sequence DDL, Forms XML export, and PLL library in the repository. Every finding below cites a file and line range verified against the current tree.

---

## Executive Summary

The codebase is a representative Oracle Forms 11g/12c HRMS: 11 PL/SQL packages, 6 database triggers, 30 tables, 6 views, 29 sequences, 6 Forms XML exports and 2 PLL libraries. Review found **65 findings**.

Three classes of problem dominate:

1. **Authentication is effectively absent.** `PKG_SECURITY.authenticate` never compares any password to any stored value — it looks up the user by email and issues a session. `change_password` validates complexity and then discards the new password. The MD5 hashing and hard-coded AES key are real, but secondary to the fact that no credential check happens at all.
2. **The employee triggers cannot execute against this schema.** `TRG_EMP_BEFORE_UPDATE` inserts into `EMPLOYEE_HISTORY` using six column names that do not exist in the table DDL, and `TRG_EMP_BEFORE_INSERT` queries `EMPLOYEES` from a row-level trigger on `EMPLOYEES` (mutating table). Any status/department/job update and any insert would fail at runtime.
3. **Concurrency correctness is left to chance.** Employee numbers come from `MAX()+1`, leave balances and payroll runs are read-then-written without `FOR UPDATE`, and audit writes run in autonomous transactions whose exception handler discards failures silently.

### Severity counts

| Severity | Count |
|----------|-------|
| CRITICAL | 7 |
| HIGH | 18 |
| MEDIUM | 30 |
| LOW | 10 |
| **Total** | **65** |

### Category breakdown

| Category | ID prefix | Findings | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-----------|----------|----------|------|--------|-----|
| Security vulnerabilities | `SEC` | 14 | 4 | 4 | 5 | 1 |
| Race conditions | `RACE` | 8 | 1 | 4 | 3 | 0 |
| Performance | `PERF` | 9 | 0 | 2 | 5 | 2 |
| Validation drift | `VAL` | 7 | 0 | 2 | 3 | 2 |
| Circular / package dependencies | `DEP` | 3 | 0 | 0 | 2 | 1 |
| Architectural anti-patterns | `ARCH` | 9 | 0 | 2 | 5 | 2 |
| Data integrity | `DATA` | 15 | 2 | 4 | 7 | 2 |

> **Note on `DATA_DICTIONARY.md`:** the repository does not contain one. Column semantics were cross-referenced against `COMMENT ON` statements in `schema/tables/01_core_tables.sql` (only `DEPARTMENTS` and `EMPLOYEES` carry column comments) and against `README.md`. See `DATA-012` and `DATA-013`.

---

## 1. Security Vulnerabilities

### SEC-001 — `authenticate` issues a session without ever checking the password
**Severity:** CRITICAL
**Location:** `plsql/packages/PKG_SECURITY.pkb:30-80`

```sql
    v_stored_hash VARCHAR2(200);
    v_input_hash  VARCHAR2(200);
BEGIN
    SELECT EMP_ID INTO v_emp_id
    FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username)
    AND EMPLOYMENT_STATUS = 'ACTIVE';
    ...
    -- NOTE: In the real system, passwords are stored in a separate
    -- USER_CREDENTIALS table. ...
    INSERT INTO USER_SESSIONS (...) VALUES (v_session_id, v_emp_id, p_username, ...);
```

**Issue:** `v_stored_hash` and `v_input_hash` are declared and never assigned or compared. `p_password` is accepted and discarded. The function creates and returns an active session for any username that resolves to an active employee.
**Impact:** Complete authentication bypass. Knowing any employee's email address grants a valid HRMS session, which the login form then uses to open the menu (`forms/xml-exports/HRMS_LOGIN.xml:75-93`) and which `PKG_SECURITY.has_permission` treats as an authenticated principal. All payroll, SSN and compensation data is exposed.
**Recommendation:** Introduce the `USER_CREDENTIALS` table the comment refers to, store a per-user salted hash, and fail closed: compare the derived hash before any `INSERT INTO USER_SESSIONS`. Until that exists, the function must raise rather than return a session.

### SEC-002 — Unsalted MD5 password hashing
**Severity:** CRITICAL
**Location:** `plsql/packages/PKG_SECURITY.pkb:14-24`

```sql
    RETURN RAWTOHEX(
        DBMS_CRYPTO.HASH(
            UTL_RAW.CAST_TO_RAW(p_password),
            DBMS_CRYPTO.HASH_MD5
        )
    );
```

**Issue:** MD5 with no salt and no iteration count. Identical passwords produce identical digests, and MD5 is collision-broken and trivially reversible via rainbow tables.
**Impact:** Any leak of the (future) credential store is equivalent to leaking cleartext passwords, which are commonly reused against SSO and email.
**Recommendation:** Replace with a memory-hard KDF. Inside the database the practical option is `DBMS_CRYPTO.HASH(..., HASH_SH512)` over a per-user random salt with a stretching loop, or better, delegate authentication to the directory the org already runs (see `PKG_INTEGRATION.sync_org_structure`, `ARCH-003`).

### SEC-003 — AES key hard-coded in package body
**Severity:** CRITICAL
**Location:** `plsql/packages/PKG_SECURITY.pkb:6-7` (also documented at `plsql/packages/PKG_SECURITY.pks:12`)

```sql
    -- VULNERABILITY: Encryption key hard-coded in source
    c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```

**Issue:** The AES-256 key protecting `EMPLOYEES.SSN_ENCRYPTED` and `EMPLOYEE_BANK_ACCOUNTS.ACCOUNT_NUMBER_ENC` is a literal in version-controlled source, readable by anyone with `SELECT` on `ALL_SOURCE`.
**Impact:** The at-rest encryption provides no protection against database users, DBAs, or anyone with repository access. Rotation is impossible without re-encrypting every row and shipping a new package version.
**Recommendation:** Move key custody out of the database (Oracle Key Vault / wallet) and switch the columns to TDE column encryption, which removes the key from application code entirely.

### SEC-004 — SQL injection in `search_employees` dynamic SQL
**Severity:** CRITICAL
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:445-498`

```sql
        IF p_last_name IS NOT NULL THEN
            v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
        ...
            v_sql := v_sql || 'AND e.DEPT_ID = ' || p_dept_id || ' ';
        ...
        OPEN p_cursor FOR v_sql;
```

**Issue:** Seven parameters are concatenated into the statement text with no binding and no escaping; the file's own comment marks it. The cursor is opened over the assembled string.
**Impact:** Any caller that forwards user input (the employee search form passes free-text name filters) can terminate the predicate and append arbitrary SQL, including `UNION` reads of `EMPLOYEE_BANK_ACCOUNTS` or `AUDIT_LOG`. Runs with the privileges of the `HRMS` owner.
**Recommendation:** Keep the dynamic shape but bind every value: build `... LIKE UPPER(:p_last_name || '%')` and `OPEN p_cursor FOR v_sql USING ...`. Because the bind list must match the predicates, either always include all predicates with `(:p IS NULL OR col = :p)` or assemble the `USING` list alongside the SQL.

### SEC-005 — `change_password` silently discards the new password
**Severity:** HIGH
**Location:** `plsql/packages/PKG_SECURITY.pkb:208-234`

```sql
        -- NOTE: Actual password update would go to USER_CREDENTIALS table
        -- This is a stub for the legacy system model

        PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
    END change_password;
```

**Issue:** Complexity rules are enforced, an audit record claiming a successful update is written, and the password is never persisted anywhere.
**Impact:** Users and auditors are told a rotation happened when nothing changed. Forced-rotation and breach-response procedures are therefore ineffective, and the audit trail actively misleads.
**Recommendation:** Implement the credential write, or remove the procedure and the menu entry (`forms/xml-exports/HRMS_MENU.xml:166-167`) so the capability is not advertised.

### SEC-006 — No account lockout, throttling, or failed-attempt record
**Severity:** HIGH
**Location:** `plsql/packages/PKG_SECURITY.pkb:26-30`; `forms/xml-exports/HRMS_LOGIN.xml:10-13`

```sql
    -- authenticate
    -- VULNERABILITY: No brute-force protection (no lockout after N failures)
```

**Issue:** Nothing counts failures. `USER_SESSIONS` (`schema/tables/04_performance_tables.sql:153-169`) records only successful logins — there is no failed-attempt table or counter column anywhere in the schema.
**Impact:** Unlimited online guessing, and no forensic record of an attack. Combined with `SEC-001` there is not even a guess to make.
**Recommendation:** Add a `LOGIN_ATTEMPTS` table keyed by username with a rolling window, lock after N failures with exponential backoff, and log every failure with source IP.

### SEC-007 — Static key and no per-record IV for SSN/bank encryption
**Severity:** HIGH
**Location:** `plsql/packages/PKG_SECURITY.pkb:179-206`

```sql
        v_raw := DBMS_CRYPTO.ENCRYPT(
            src => UTL_RAW.CAST_TO_RAW(p_ssn),
            typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
            key => c_encryption_key
        );
```

**Issue:** CBC mode with a single fixed key and no explicit initialization vector: `DBMS_CRYPTO` defaults to a zero IV, so equal plaintexts encrypt to equal ciphertexts. `decrypt_ssn` additionally swallows every error and returns the literal `'***DECRYPT_ERROR***'` (`:200-205`), so corruption and key mismatch are indistinguishable from data.
**Impact:** Ciphertext equality leaks which employees and dependents share an SSN (`EMPLOYEE_DEPENDENTS.SSN_ENCRYPTED`), and supports chosen-plaintext confirmation of a guessed SSN. Silent decrypt failure can propagate the sentinel string into exports.
**Recommendation:** Use TDE (see `SEC-003`), or at minimum generate a random IV per row, store it alongside the ciphertext, and let decryption errors raise.

### SEC-008 — FTP credentials stored in cleartext configuration
**Severity:** HIGH
**Location:** `plsql/packages/PKG_INTEGRATION.pks:12`; `schema/tables/04_performance_tables.sql:110-127`

```sql
--   - FTP credentials stored in SYSTEM_PARAMETERS table (cleartext)
```

```sql
CREATE TABLE HRMS.SYSTEM_PARAMETERS (
    ...
    PARAM_VALUE          VARCHAR2(4000)  NOT NULL,
    ...
    EDITABLE_FLAG        CHAR(1)         DEFAULT 'Y',
```

**Issue:** The integration package documents that outbound FTP credentials live in `SYSTEM_PARAMETERS`. The table has no encryption, no sensitivity marker, and no restricted grant — `EDITABLE_FLAG` is the only access notion and it defaults to `'Y'`.
**Impact:** Any account with `SELECT` on the HRMS schema reads the credentials for the payroll/benefits file transfer channel. They are also copied into any schema export or refresh of a non-production environment.
**Recommendation:** Move transfer credentials to an Oracle wallet or credential object (`DBMS_CREDENTIAL`), and add a `SENSITIVE_FLAG` plus a restricted view for the remaining parameters.

### SEC-009 — Hard-coded SMTP endpoint, unauthenticated and unencrypted
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:6-10`, `:90-107`

```sql
    -- Hard-coded SMTP config (should be in SYSTEM_PARAMETERS)
    c_smtp_host CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
    c_smtp_port CONSTANT NUMBER := 25;
```

**Issue:** Host, port and sender identity are compile-time constants; the conversation uses `HELO` on port 25 with no `STARTTLS` and no `AUTH`.
**Impact:** HR notifications (leave, salary review, performance outcomes) traverse the network in cleartext, and the relay is addressed by name with no verification. Changing mail infrastructure requires a package recompile in every environment.
**Recommendation:** Read the endpoint from `SYSTEM_PARAMETERS`, negotiate `STARTTLS`, and authenticate with a wallet-held credential.

### SEC-010 — Username enumeration via divergent failure paths
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_SECURITY.pkb:46-50`

```sql
        WHEN NO_DATA_FOUND THEN
            -- VULNERABILITY: Timing attack - different response time for
            -- invalid user vs invalid password
            RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
```

**Issue:** An unknown user short-circuits immediately; a known user proceeds through session creation, an audit write and a context call. The work performed differs by orders of magnitude.
**Impact:** An attacker can enumerate valid corporate email addresses by response time, which feeds phishing and credential-stuffing campaigns.
**Recommendation:** Perform a constant amount of work on both paths (compute a dummy hash) and return an identical error.

### SEC-011 — Duplicate active emails resolved by `MIN(EMP_ID)`
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_SECURITY.pkb:51-57`

```sql
        WHEN TOO_MANY_ROWS THEN
            -- Multiple employees with same email - use first active one
            SELECT MIN(EMP_ID) INTO v_emp_id
            FROM EMPLOYEES
            WHERE UPPER(EMAIL) = UPPER(p_username)
            AND EMPLOYMENT_STATUS = 'ACTIVE';
```

**Issue:** Rather than treating an ambiguous login as an error, the code picks the lowest employee ID. `EMPLOYEES` has no unique constraint on `EMAIL` (`DATA-005`), so this path is reachable.
**Impact:** A user can be silently authenticated as a different employee — typically the older record, which for a rehire is the terminated-then-reactivated identity — and inherits that employee's department-based permissions.
**Recommendation:** Raise on ambiguity, and add the missing unique constraint so the condition cannot arise.

### SEC-012 — Password policy hard-coded and divergent from configuration
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_SECURITY.pkb:216-228`; `data/seed/01_reference_data.sql:193`

```sql
        IF LENGTH(p_new_password) < 8 THEN
            RAISE_APPLICATION_ERROR(-20310, 'Password must be at least 8 characters');
```

```sql
VALUES (6, 'SECURITY', 'PASSWORD_MIN_LENGTH', '8', 'Minimum password length', 'Y', 'SYSTEM', SYSDATE);
```

**Issue:** The configurable parameter exists and is seeded, but the code never reads it. The values agree today purely by coincidence.
**Impact:** Security teams tightening `PASSWORD_MIN_LENGTH` see no behaviour change, and believe a control is in force that is not.
**Recommendation:** Read the parameter (there is already `PKG_COMMON` infrastructure for lookups) or delete the parameter row so the policy has one home.

### SEC-013 — Session timeout hard-coded
**Severity:** LOW
**Location:** `plsql/packages/PKG_SECURITY.pkb:8`

```sql
    c_session_timeout_min CONSTANT NUMBER := 30;
```

**Issue:** The idle timeout is a package constant rather than a `SYSTEM_PARAMETERS` entry.
**Impact:** Adjusting it for a compliance requirement requires a code change and recompile across environments.
**Recommendation:** Source from `SYSTEM_PARAMETERS` with the constant as a fallback default.

### SEC-014 — Login form masks all errors and picks an arbitrary employee row
**Severity:** MEDIUM
**Location:** `forms/xml-exports/HRMS_LOGIN.xml:85-101`

```sql
        SELECT EMP_ID INTO :GLOBAL.current_emp_id
        FROM EMPLOYEES
        WHERE UPPER(EMAIL) = UPPER(:LOGIN.USERNAME)
        AND EMPLOYMENT_STATUS = 'ACTIVE'
        AND ROWNUM = 1;
    ...
    EXCEPTION
        WHEN OTHERS THEN
            :LOGIN.ERROR_MSG := 'Invalid username or password.';
```

**Issue:** `ROWNUM = 1` selects an unordered arbitrary row when emails collide — possibly a different employee than the one `PKG_SECURITY.authenticate` chose via `MIN(EMP_ID)`. The blanket handler reports every failure, including database outages and permission errors, as invalid credentials.
**Impact:** `:GLOBAL.current_emp_id` (used for every subsequent leave request and self-service action, e.g. `forms/xml-exports/HRMS_LEAVE.xml:153`) can point at the wrong person. Operational failures are invisible to users and to support.
**Recommendation:** Have `authenticate` return the resolved `EMP_ID` so the form does not re-derive it, and narrow the handler to the authentication exception declared at `PKG_SECURITY.pks:15-19`.

---

## 2. Race Conditions

### RACE-001 — Employee numbers generated with `MAX()+1`
**Severity:** CRITICAL
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:34-55`

```sql
    -- BUG: race condition under concurrent inserts - no SELECT FOR UPDATE
    FUNCTION generate_emp_number RETURN VARCHAR2 IS
    ...
        SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
        INTO v_max_num
        FROM EMPLOYEES
        WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';

        v_new_number := c_emp_number_prefix || '-' || LPAD(v_max_num, 6, '0');
    ...
    EXCEPTION
        WHEN OTHERS THEN
            RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMPLOYEE.NEXTVAL, 6, '0');
```

**Issue:** An uncommitted read of `MAX()` gives two concurrent hires the same number; `UK_EMP_NUMBER` (`schema/tables/01_core_tables.sql:135`) then rejects the second insert. The `WHEN OTHERS` fallback masks that by switching to `SEQ_EMPLOYEE` — a *different* number space starting at 10000 — so failures produce numbers that collide with nothing and match nothing. `SEQ_EMP_NUMBER` exists for exactly this purpose and is never used (`schema/sequences/hrms_sequences.sql:18-21`).
**Impact:** Intermittent hire failures under concurrent HR data entry (the form calls this in `PRE-INSERT`, `forms/xml-exports/HRMS_EMPLOYEE.xml:326-327`), and two incompatible numbering schemes in one column.
**Recommendation:** Use `SEQ_EMP_NUMBER.NEXTVAL` unconditionally and delete the fallback. Backfill is unnecessary — set the sequence start above the current maximum.

### RACE-002 — Payroll run created after an unlocked period-status read
**Severity:** HIGH
**Location:** `plsql/packages/PKG_PAYROLL.pkb:240-263`

```sql
        SELECT STATUS INTO v_status
        FROM PAY_PERIODS
        WHERE PERIOD_ID = p_period_id;

        IF v_status = 'CLOSED' THEN ...
        SELECT SEQ_PAYROLL_RUN.NEXTVAL INTO v_run_id FROM DUAL;
        INSERT INTO PAYROLL_RUNS (...)
```

**Issue:** No `FOR UPDATE` and no uniqueness on `(PERIOD_ID, RUN_TYPE)` in `PAYROLL_RUNS` (`schema/tables/02_payroll_tables.sql:107-131`). The sibling procedure at `:193-196` does take `FOR UPDATE`, so the omission is inconsistent rather than deliberate.
**Impact:** Two operators can create duplicate `REGULAR` runs for the same period, or a run can be created against a period being closed concurrently — producing double payment on approval.
**Recommendation:** `SELECT ... FOR UPDATE` on the period and add a unique constraint on `(PERIOD_ID, RUN_TYPE)` for non-reversed runs.

### RACE-003 — Leave balance checked and decremented without a lock
**Severity:** HIGH
**Location:** `plsql/packages/PKG_LEAVE.pkb:146-183`

```sql
        IF v_leave_type.ACCRUAL_FLAG = 'Y' THEN
            v_balance := get_leave_balance(p_emp_id, p_leave_type_id);
            IF v_balance < v_total_days THEN
                RAISE_APPLICATION_ERROR(-20201, 'Insufficient leave balance. ...');
        ...
        UPDATE LEAVE_BALANCES
        SET PENDING = PENDING + v_total_days, ...
```

**Issue:** `get_leave_balance` (`:376-387`) is a plain read. Between the check and the `UPDATE` another session can consume the same balance.
**Impact:** Employees can submit overlapping requests that jointly exceed entitlement; the balance goes negative with no constraint to stop it (`LEAVE_BALANCES` has no check on `AVAILABLE`).
**Recommendation:** `SELECT ... FOR UPDATE` the balance row before validating, and add `CHECK (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING >= 0)` as a backstop.

### RACE-004 — Leave overlap detection has no serialization or constraint
**Severity:** HIGH
**Location:** `plsql/packages/PKG_LEAVE.pkb:141-145`; `schema/tables/03_leave_tables.sql:63-91`

```sql
        IF check_leave_overlap(p_emp_id, p_start_date, p_end_date) THEN
            RAISE_APPLICATION_ERROR(-20202,
                'Leave request overlaps with an existing request');
        END IF;
```

**Issue:** The overlap query cannot see another session's uncommitted request, and `LEAVE_REQUESTS` carries no constraint or index enforcing non-overlap per employee.
**Impact:** Two simultaneous submissions both pass, producing overlapping approved leave — double-counted absence and incorrect payroll for unpaid types.
**Recommendation:** Lock the employee's balance row first (which also fixes `RACE-003`) so overlap checks for one employee serialize, and reconcile with a nightly detection report.

### RACE-005 — `adjust_balance` update-then-initialize retry
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_LEAVE.pkb:400-419`

```sql
        UPDATE LEAVE_BALANCES SET ADJUSTMENT = ADJUSTMENT + p_adjustment ...
        IF SQL%ROWCOUNT = 0 THEN
            initialize_balances(...);
            UPDATE LEAVE_BALANCES SET ...
        END IF;
```

**Issue:** Classic upsert race. Two sessions can both see zero rows and both call `initialize_balances`; `UK_LEAVE_BAL` (`schema/tables/03_leave_tables.sql:57`) makes the loser fail with `DUP_VAL_ON_INDEX` mid-adjustment.
**Impact:** Sporadic adjustment failures during year-open, when many balances are created concurrently.
**Recommendation:** Replace with a single `MERGE` on `(EMP_ID, LEAVE_TYPE_ID, CALENDAR_YEAR)`.

### RACE-006 — Transfer reads the old job/department without locking
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:592-614`

```sql
        SELECT JOB_ID INTO v_old_job_id
        FROM EMPLOYEES
        WHERE EMP_ID = p_emp_id;
        ...
        UPDATE EMPLOYEES SET JOB_ID = p_new_job_id, ... WHERE EMP_ID = p_emp_id;
```

**Issue:** No `FOR UPDATE`, unlike `update_employee` (`:520-524`) and `terminate_employee` (`:657-660`) which both lock. The captured "old" value is used to write the history row.
**Impact:** Concurrent transfers produce history entries whose `OLD_*` values never happened, corrupting the audit chain that compliance reporting depends on.
**Recommendation:** Add `FOR UPDATE NOWAIT`, matching the surrounding convention.

### RACE-007 — Session validation reads then expires without locking
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_SECURITY.pkb:104-121`

```sql
        SELECT SESSION_STATUS, LOGIN_TIME
        INTO v_status, v_login_time
        FROM USER_SESSIONS
        WHERE SESSION_ID = p_session_id;
        ...
            UPDATE USER_SESSIONS SET SESSION_STATUS = 'EXPIRED', LOGOUT_TIME = SYSDATE
            WHERE SESSION_ID = p_session_id;
```

**Issue:** The unconditional `UPDATE` can overwrite a concurrent `logout` (`:85-93`), rewriting `LOGOUT_TIME` and turning `CLOSED` into `EXPIRED`. Every form calls this on entry (`forms/xml-exports/HRMS_LEAVE.xml:25`), so the path is hot.
**Impact:** Session audit records misreport how sessions ended, and expiry writes contend on a hot row.
**Recommendation:** Make the update conditional — `WHERE SESSION_ID = :id AND SESSION_STATUS = 'ACTIVE'` — and derive validity from the returned row count.

### RACE-008 — Salary supersede allows two active rows
**Severity:** HIGH
**Location:** `plsql/packages/PKG_PAYROLL.pkb:28-58`

```sql
        UPDATE SALARY_RECORDS
        SET END_DATE = p_effective_date - 1, ACTIVE_FLAG = 'N', ...
        WHERE EMP_ID = p_emp_id AND ACTIVE_FLAG = 'Y' AND EFFECTIVE_DATE < p_effective_date;

        INSERT INTO SALARY_RECORDS (... ACTIVE_FLAG ...) VALUES (... 'Y' ...);
```

**Issue:** Nothing prevents two concurrent salary changes from each end-dating what they saw and both inserting an active row; the `EFFECTIVE_DATE < p_effective_date` predicate also leaves a same-day prior record active. `SALARY_RECORDS` has no partial unique index on active rows (`schema/tables/02_payroll_tables.sql:10-32`).
**Impact:** `VW_ACTIVE_EMPLOYEES` and `VW_EMPLOYEE_COMPENSATION` join `SALARY_RECORDS ... ACTIVE_FLAG = 'Y'` (`schema/views/hrms_views.sql:32-35`, `:79`) and silently duplicate employees; payroll may pick either salary. See `DATA-009`.
**Recommendation:** Lock the employee's salary rows before the update, change the predicate to `<=`, and add a function-based unique index on `(EMP_ID, CASE WHEN ACTIVE_FLAG='Y' THEN 1 END)`.

---

## 3. Performance Issues

### PERF-001 — Business-day calculation issues one query per calendar day
**Severity:** HIGH
**Location:** `plsql/packages/PKG_LEAVE.pkb:21-40`

```sql
        WHILE v_date <= TRUNC(p_end_date) LOOP
            IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
                SELECT COUNT(*) INTO v_holiday_count
                FROM HOLIDAYS
                WHERE HOLIDAY_DATE = v_date ...
```

**Issue:** One context switch and one query per day in the range. Called on every leave submission and once per employee per type during accrual.
**Impact:** A three-month sabbatical costs ~65 round trips for a single submission; batch accrual multiplies that by the workforce. This is the dominant cost in the leave module.
**Recommendation:** Compute in one statement — generate the range with `CONNECT BY LEVEL`, anti-join `HOLIDAYS`, and count — or cache the holiday calendar in a package-level associative array keyed by date.

### PERF-002 — Day-by-day loops in the shared date utilities
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_COMMON.pkb:139-145`, `:158-163`

```sql
        WHILE v_date <= TRUNC(p_end_date) LOOP
            IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
                v_count := v_count + 1;
            END IF;
            v_date := v_date + 1;
        END LOOP;
```

**Issue:** Pure PL/SQL iteration where arithmetic suffices, and — unlike the leave version — no holiday awareness at all, so the two "business day" definitions disagree.
**Impact:** Linear cost in range length, and inconsistent day counts between modules that use `PKG_COMMON` and those that use `PKG_LEAVE`.
**Recommendation:** Replace with a closed-form weekday calculation and have both modules call one holiday-aware implementation.

### PERF-003 — A new SMTP connection is opened per notification
**Severity:** HIGH
**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:78-107`

```sql
        FOR notif_rec IN ( ... FETCH FIRST p_batch_size ROWS ONLY ) LOOP
            BEGIN
                v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
                UTL_SMTP.HELO(v_connection, c_smtp_host);
```

**Issue:** Connection open, `HELO` and `QUIT` for every message, inside a job that runs every five minutes with a default batch of 50.
**Impact:** 50 TCP handshakes per cycle; relay rate-limiting or connection exhaustion turns into `FAILED` rows with incrementing `RETRY_COUNT` and no backoff. Batch throughput after a payroll or review cycle is poor.
**Recommendation:** Open one connection before the loop, send all recipients over it, and reconnect only on error.

### PERF-004 — `CONNECT BY` org traversal, documented as degrading past 500 employees
**Severity:** MEDIUM
**Location:** `schema/views/hrms_views.sql:47-57`; `plsql/packages/PKG_EMPLOYEE.pkb:819-837`

```sql
FROM EMPLOYEES
WHERE EMPLOYMENT_STATUS = 'ACTIVE'
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
```

**Issue:** In both the view and `PKG_EMPLOYEE.get_org_chart` (`:830-837`, rooted at `p_root_emp_id`) the status filter is applied as a `WHERE` predicate, so the whole tree is walked and then filtered rather than pruned during traversal. The view header records the >500-employee cliff.
**Impact:** Org-chart screens and the reporting hierarchy time out for the stated 200-concurrent-user, multi-office deployment.
**Recommendation:** Move the status filter into the `CONNECT BY` condition so inactive subtrees are pruned, index `MANAGER_EMP_ID`, and materialize the path if it is displayed frequently. See also `DATA-014`.

### PERF-005 — Effectively every sequence is `NOCACHE`
**Severity:** MEDIUM
**Location:** `schema/sequences/hrms_sequences.sql:9-49`

```sql
CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
...
CREATE SEQUENCE HRMS.SEQ_AUDIT START WITH 1 INCREMENT BY 1 CACHE 100;
```

**Issue:** 28 of 29 sequences are `NOCACHE`; only `SEQ_AUDIT` caches. Each `NEXTVAL` forces a recursive dictionary update and redo.
**Impact:** Row-source contention on high-volume inserts — `SEQ_PAYROLL_DETAIL` fires several times per employee per run, and `SEQ_NOTIFICATION` on every queued mail.
**Recommendation:** `ALTER SEQUENCE ... CACHE 100` (higher for payroll detail and notifications). Gaps are already tolerated by the design.

### PERF-006 — Payroll processed row-by-row with a commit every 50 employees
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_PAYROLL.pkb:294-327`

```sql
        FOR emp_rec IN ( SELECT e.EMP_ID FROM EMPLOYEES e WHERE ... ) LOOP
            ...
            IF MOD(v_emp_count, 50) = 0 THEN
                COMMIT;
            END IF;
        END LOOP;
```

**Issue:** Per-employee procedure calls with nested per-element queries, plus intermediate commits (the transactional consequence is `ARCH-006`).
**Impact:** Payroll runtime scales linearly with headcount and cannot use set-based optimization; a mid-run failure leaves a partially calculated, partially committed run.
**Recommendation:** Restructure the element calculation as set-based `INSERT ... SELECT` into `PAYROLL_DETAILS`, or at minimum `BULK COLLECT` with `FORALL` and a single commit.

### PERF-007 — Accrual batch nests employee and leave-type loops
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_LEAVE.pkb:455-548`

```sql
            -- Commit every 100 employees
            IF MOD(v_total_employees, 100) = 0 THEN
                COMMIT;
            END IF;
```

**Issue:** Employees × leave types, with a balance read, a balance update and an accrual-log insert per pair, and periodic commits.
**Impact:** The monthly accrual job's cost is the product of two dimensions; it is the longest-running scheduled job in the system.
**Recommendation:** Single `MERGE` against `LEAVE_BALANCES` driven by a join of active employees to accrual-eligible types, plus one `INSERT ... SELECT` into `LEAVE_ACCRUAL_LOG`.

### PERF-008 — Manager-cycle detection walks the chain one query per level
**Severity:** LOW
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:108-130`

```sql
            WHILE v_current_mgr IS NOT NULL AND v_depth < c_max_hierarchy_depth LOOP
                ...
                SELECT MANAGER_EMP_ID INTO v_current_mgr FROM EMPLOYEES WHERE EMP_ID = v_current_mgr;
```

**Issue:** Up to 15 single-row queries per validation, and the depth cap causes a silent false negative: a cycle deeper than 15 levels exits the loop and validates successfully.
**Impact:** Minor cost, but an undetected reporting cycle makes every `CONNECT BY` in the system loop until `ORA-01436`.
**Recommendation:** Replace with one `CONNECT BY ... NOCYCLE` check that returns whether `p_emp_id` appears in the prospective manager's chain.

### PERF-009 — Views re-derive expensive scalars on every row
**Severity:** LOW
**Location:** `schema/views/hrms_views.sql:32-35`, `:109-129`

```sql
WHERE pr.RUN_ID = (
    SELECT MAX(pr2.RUN_ID)
    FROM PAYROLL_RUNS pr2
    WHERE pr2.STATUS = 'APPROVED'
)
```

**Issue:** `VW_PAYROLL_LATEST` scans `PAYROLL_RUNS` for the global maximum approved run — which is also semantically wrong per employee, since an employee absent from the newest run simply disappears. `VW_ACTIVE_EMPLOYEES` outer-joins `SALARY_RECORDS` with three non-indexed predicates per row.
**Impact:** Reporting screens built on these views degrade as payroll history accumulates.
**Recommendation:** Use an analytic (`ROW_NUMBER() OVER (PARTITION BY EMP_ID ORDER BY RUN_ID DESC)`) for the latest run per employee, and index `SALARY_RECORDS (EMP_ID, ACTIVE_FLAG, EFFECTIVE_DATE)`.

---

## 4. Validation Drift (Forms PLL vs. server packages)

### VAL-001 — Three different email rules, one of them wrong and shipped
**Severity:** HIGH
**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:14-41`; `plsql/packages/PKG_VALIDATION.pkb:50-55`; `plsql/packages/PKG_COMMON.pkb:265-268`

```sql
-- Known drift: Server-side (PKG_VALIDATION) uses REGEXP_LIKE with a
-- more permissive pattern. This version rejects valid emails with subdomains
...
    v_dot_pos := INSTR(p_email, '.', v_at_pos);
    IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN
        RETURN FALSE;
```

```sql
    RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

**Issue:** The PLL implements `INSTR` parsing, `PKG_VALIDATION.validate_email_format` delegates to `PKG_COMMON.is_valid_email`'s regex, and the two disagree on subdomains. The employee form calls the *server* function (`forms/xml-exports/HRMS_EMPLOYEE.xml:376-379`), so the PLL routine is dead code that is nonetheless compiled into every form and available to callers.
**Impact:** Any form or future caller that uses the library rejects `user@mail.company.com` while the server accepts it — the archetypal Forms drift defect, kept alive by an unused-but-shipped duplicate.
**Recommendation:** Delete `HRMS_VALIDATION_LIB.validate_email` and have the PLL forward to `PKG_VALIDATION.validate_email_format`, leaving exactly one rule.

### VAL-002 — Salary-range violation is an error server-side and a debug message in the write path
**Severity:** HIGH
**Location:** `plsql/packages/PKG_VALIDATION.pkb:17-48`; `plsql/packages/PKG_EMPLOYEE.pkb:220-241`; `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:101-135`

```sql
                IF p_base_salary < v_min OR p_base_salary > v_max THEN
                    -- NOTE: This is a soft warning, not an error
                    -- Forms trigger WHEN-VALIDATE-ITEM shows warning dialog
                    -- but allows override with manager approval
                    IF g_debug_mode THEN
                        DBMS_OUTPUT.PUT_LINE('WARNING: Salary ' || p_base_salary || ...);
                    END IF;
                END IF;
```

**Issue:** `PKG_VALIDATION.validate_salary_for_grade` returns an error message and the PLL returns a user-facing message, but `PKG_EMPLOYEE.create_employee` — the only path that actually writes the salary — degrades the violation to a `DBMS_OUTPUT` line emitted only when `g_debug_mode` is on. The comment asserts a manager-approval override that exists nowhere in the codebase. No database constraint links `SALARY_RECORDS.BASE_SALARY` to `JOB_GRADES`.
**Impact:** Out-of-band salaries are persisted with no record of an override decision, defeating the compa-ratio governance that `VW_EMPLOYEE_COMPENSATION` is built to report on.
**Recommendation:** Call `PKG_VALIDATION.validate_salary_for_grade` from `create_employee` and reject, with an explicit `p_override_reason` argument recorded in `EMPLOYEE_HISTORY` when a deliberate exception is granted.

### VAL-003 — Future hire-date window differs between form and trigger
**Severity:** MEDIUM
**Location:** `forms/xml-exports/HRMS_EMPLOYEE.xml:382-386`; `plsql/triggers/trg_employees.sql:34-38`

```sql
    ELSIF v_item = 'EMPLOYEE.HIRE_DATE' THEN
        IF :EMPLOYEE.HIRE_DATE > SYSDATE + 90 THEN
            MESSAGE('Hire date cannot be more than 90 days in the future');
```

```sql
    IF :NEW.HIRE_DATE > SYSDATE + 180 THEN
        RAISE_APPLICATION_ERROR(-20501, 'Hire date cannot be more than 180 days in the future');
```

**Issue:** 90 days client-side, 180 days server-side.
**Impact:** Bulk loads and API callers can create hires 180 days out that the UI would have blocked; conversely recruiters are told 90 days is the limit when the real limit is different.
**Recommendation:** Put the window in `SYSTEM_PARAMETERS` and have both paths read it.

### VAL-004 — Central `validate_date_range` is weaker than every rule that matters
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_VALIDATION.pkb:6-15`; `plsql/packages/PKG_LEAVE.pkb:116-127`; `forms/xml-exports/HRMS_LEAVE.xml:143-150`

```sql
    RETURN p_end_date >= p_start_date;
```

```sql
        IF p_start_date < TRUNC(SYSDATE) THEN
            -- Allow backdated requests up to 5 days
            IF TRUNC(SYSDATE) - p_start_date > 5 THEN
                RAISE_APPLICATION_ERROR(-20211, 'Cannot submit leave requests more than 5 days in the past');
```

**Issue:** The "centralized" range check only tests ordering and nulls. The five-day backdating rule lives solely inside `PKG_LEAVE`, and the leave form validates only that the dates are non-null — no range check at all before calling the server.
**Impact:** Users discover the backdating rule as a server error after filling the whole form; other modules that use `validate_date_range` silently accept ranges the business would reject.
**Recommendation:** Add a `p_max_backdate_days` parameter to `validate_date_range` and call it from both the leave form and `PKG_LEAVE`.

### VAL-005 — Employee-number format rule contradicts the generator's fallback
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_VALIDATION.pkb:64-70`; `plsql/packages/PKG_EMPLOYEE.pkb:43-54`

```sql
        RETURN REGEXP_LIKE(p_emp_number, '^EMP-\d{6}$');
```

**Issue:** The validator demands exactly six digits, while `generate_emp_number` parses existing values with `TO_NUMBER(SUBSTR(EMP_NUMBER, 5))` — which raises on any non-conforming legacy value and is caught by the `WHEN OTHERS` fallback. `SEQ_EMPLOYEE` starts at 10000 and, once past 999999, produces seven-digit values the validator rejects.
**Impact:** Silent switch to the fallback numbering on the first malformed row, and a hard format break when the sequence crosses seven digits.
**Recommendation:** Generate from `SEQ_EMP_NUMBER` (`RACE-001`), widen or remove the digit-count assertion, and validate the format on write rather than inferring it on read.

### VAL-006 — Phone and SSN rules diverge and SSN has no server-side check
**Severity:** LOW
**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:43-90`; `plsql/packages/PKG_COMMON.pkb:270-279`

```sql
    v_digits := TRANSLATE(p_phone, '0123456789()-. +x', '0123456789');
    IF LENGTH(v_digits) NOT IN (10, 11) THEN
```

```sql
        v_digits := REGEXP_REPLACE(p_phone, '[^0-9]', '');
        RETURN LENGTH(v_digits) BETWEEN 10 AND 11;
```

**Issue:** Two implementations of the same rule (`TRANSLATE` strips only an enumerated punctuation set, so an unexpected character is *retained* and inflates the length, whereas the regex strips everything non-numeric). The PLL's structural SSN checks — rejecting all-zero groups — have no server-side counterpart; `PKG_COMMON` only checks for nine digits.
**Impact:** A phone number with an unlisted separator is rejected client-side and accepted server-side. Invalid SSNs entered outside the forms are stored and encrypted.
**Recommendation:** Delete the PLL copies and forward to `PKG_VALIDATION`; move the SSN group rules into `PKG_COMMON.is_valid_ssn`.

### VAL-007 — Comment describes a cache the code does not use
**Severity:** LOW
**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:101-123`

```sql
-- BUG: Uses a hard-coded cache that's populated at form startup
-- and never refreshed. ...
    -- Direct DB query (not cached - contradicts the comment above)
    SELECT MIN_SALARY, MAX_SALARY INTO v_min, v_max
    FROM JOB_GRADES WHERE GRADE_ID = p_grade_id;
```

**Issue:** The header documents a stale-cache defect; the body then documents that the comment is wrong. Both are shipped.
**Impact:** Maintainers investigate a caching bug that does not exist, and may "fix" it by adding the cache the comment describes.
**Recommendation:** Delete the misleading header.

---

## 5. Circular and Cross-Package Dependencies

### DEP-001 — Documented `PKG_EMPLOYEE` ↔ `PKG_PAYROLL` cycle does not exist in code
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_EMPLOYEE.pks:9`; `plsql/packages/PKG_PAYROLL.pks:9`; `README.md:127`; `plsql/packages/PKG_EMPLOYEE.pkb:272-281`

```sql
--   - Circular dependency with PKG_PAYROLL (salary validation)
```

```sql
--   - Circular dependency with PKG_EMPLOYEE (is_active check)
```

```sql
            -- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
            -- which in turn may call PKG_EMPLOYEE.is_active for validation
```

**Issue:** The dependency graph extracted from all eleven package bodies is acyclic. `PKG_EMPLOYEE` references `PKG_PAYROLL`, `PKG_NOTIFICATION`, `PKG_AUDIT` and `PKG_COMMON`; `PKG_PAYROLL` references only `PKG_AUDIT` and `PKG_COMMON` — it contains no `PKG_EMPLOYEE` reference and no `is_active` call. The cycle is asserted in three places and implemented in none.
**Impact:** Migration planning and compile-order tooling are built on a false constraint; conversely, engineers may treat the (real, one-way) coupling as pre-blessed and close the cycle for real. The one-way call is still a layering violation: employee creation reaching into payroll to write `SALARY_RECORDS`.
**Recommendation:** Correct the three comments, and move salary creation out of `create_employee` so the caller orchestrates both steps in one transaction.

### DEP-002 — `PKG_SECURITY` depends on `PKG_EMPLOYEE` for session context
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_SECURITY.pkb:74-77`; `plsql/packages/PKG_EMPLOYEE.pkb:948-963`

```sql
        -- Set session context
        PKG_EMPLOYEE.set_session_context(p_username, v_emp_id);
```

**Issue:** The authentication package calls into the business package to store session state in `PKG_EMPLOYEE` globals, giving the chain `PKG_SECURITY → PKG_EMPLOYEE → PKG_PAYROLL → PKG_AUDIT`. Any change to `PKG_EMPLOYEE`'s spec invalidates `PKG_SECURITY`.
**Impact:** Every employee-module deployment invalidates authentication, so logins fail until recompilation completes. Session state also lives in package globals, which are per-database-session and lost across Forms connection pooling.
**Recommendation:** Own session context in `PKG_SECURITY` (or a `SYS_CONTEXT` application context) and have `PKG_EMPLOYEE` read it, inverting the dependency.

### DEP-003 — "Centralized validation" is split across two packages
**Severity:** LOW
**Location:** `plsql/packages/PKG_VALIDATION.pks:1-8`; `plsql/packages/PKG_VALIDATION.pkb:50-62`

```sql
-- PKG_VALIDATION - Centralized Validation Package
...
    FUNCTION validate_email_format( p_email IN VARCHAR2 ) RETURN BOOLEAN IS
    BEGIN
        RETURN PKG_COMMON.is_valid_email(p_email);
```

**Issue:** Half the package is a pass-through to `PKG_COMMON`, so the actual rules live in a utility package while the package named for validation is a façade.
**Impact:** Callers reasonably grep `PKG_VALIDATION` for the rules, find delegation, and add new rules to whichever package they land in — which is how `VAL-001` and `VAL-006` arose.
**Recommendation:** Move the rule bodies into `PKG_VALIDATION` and leave `PKG_COMMON` for logging and date utilities.

---

## 6. Architectural Anti-Patterns

### ARCH-001 — Autonomous transactions that swallow their own failures
**Severity:** HIGH
**Location:** `plsql/packages/PKG_AUDIT.pkb:14`, `:26-31`; `plsql/packages/PKG_COMMON.pkb:16`, `:46`; `plsql/packages/PKG_NOTIFICATION.pkb:27`

```sql
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        INSERT INTO AUDIT_LOG (...);
        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            -- Audit logging must never fail the calling transaction
            ROLLBACK;
    END log_action;
```

**Issue:** Four autonomous transactions, each committing independently. `PKG_AUDIT.log_action` discards every error without re-raising or recording it anywhere — so a constraint violation, tablespace-full condition or privilege error produces no audit row and no signal. `DATA-004` is a live instance of exactly that.
**Impact:** The audit trail is best-effort while being relied upon for compliance; audit rows persist for business transactions that later roll back, and are absent for ones that succeed.
**Recommendation:** Keep the autonomous transaction, but on failure write to an alert table (or `DBMS_SYSTEM.KSDWRT`) so lost audit rows are detectable, and reconcile audit coverage nightly.

### ARCH-002 — 2024 tax constants and brackets hard-coded despite a `TAX_BRACKETS` table
**Severity:** HIGH
**Location:** `plsql/packages/PKG_PAYROLL.pkb:7-14`, `:643-677`; `schema/tables/02_payroll_tables.sql:159-173`

```sql
    c_ss_wage_base_2024 CONSTANT NUMBER := 168600;
    ...
    c_standard_deduction_single CONSTANT NUMBER := 14600;
```

```sql
        -- 2024 Federal tax brackets (Single)
        -- TODO: Read from TAX_BRACKETS table instead of hard-coding
        IF p_filing_status = 'SINGLE' OR p_filing_status = 'MARRIED_SEPARATE' THEN
            IF v_taxable <= 11600 THEN
```

**Issue:** Wage base, standard deductions, allowance value and every bracket boundary are compile-time constants for tax year 2024. `TAX_BRACKETS` — keyed by `TAX_YEAR`, `FILING_STATUS` and `STATE_CODE` — exists, is unused by the calculation, and `SINGLE` and `MARRIED_SEPARATE` are deliberately collapsed onto one bracket set even though they are distinct filing statuses.
**Impact:** Every payroll run after 2024 under-withholds against current IRS tables. Correcting it requires a code change and full regression rather than a data update, and `MARRIED_SEPARATE` employees are withheld incorrectly today.
**Recommendation:** Drive `calculate_federal_tax` from `TAX_BRACKETS` filtered on the period's tax year and the employee's filing status; keep the constants only as a seeded data row.

### ARCH-003 — Integrations that log success without doing anything
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_INTEGRATION.pkb:153-203`; `plsql/packages/PKG_REPORTING.pkb:196-204`

```sql
        -- TODO: Implement actual parsing and database update
```

```sql
        -- Placeholder for org structure sync with external directory (LDAP/AD)
```

```sql
        -- Placeholder for nightly refresh of denormalized reporting tables
        -- In production, this truncates and repopulates RPT_* tables
        PKG_COMMON.log_info('PKG_REPORTING', 'refresh_reporting_tables',
            'Reporting tables refreshed', p_user);
```

**Issue:** Three stubs. Time-and-attendance import counts input lines and updates nothing; org sync is empty; the reporting refresh logs "Reporting tables refreshed" having refreshed nothing.
**Impact:** Scheduled jobs report success in the application log while the data they own goes stale. Nobody is alerted, because the log says the work happened.
**Recommendation:** Make the stubs raise `-20999 'not implemented'` so the scheduler surfaces them, and remove the false success log lines.

### ARCH-004 — Flat-file integration with no delivery guarantees
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_INTEGRATION.pkb:16-147`; `plsql/packages/PKG_PAYROLL.pkb:826-893`

```sql
    v_file := UTL_FILE.FOPEN(c_gl_output_dir, v_filename, 'W', 32767);
    UTL_FILE.PUT_LINE(v_file, 'H|HRMS_PAYROLL|' || TO_CHAR(SYSDATE, 'YYYY-MM-DD') || '|' || p_run_id);
```

**Issue:** GL journals, the ADP benefits feed and the pay register are written with `UTL_FILE` to directory objects. File handles are closed correctly in the exception handlers, but there is no acknowledgement, no idempotency key, no schema version and no record of what was sent. Re-running a job silently overwrites (GL files include the run id; the benefits file is keyed only by date, so a same-day re-run destroys the prior file).
**Impact:** A failed downstream import cannot be detected or replayed from HRMS, and financial feeds have no audit of transmission.
**Recommendation:** Record each generated feed in a `FEED_LOG` table with run id, row count, checksum and status; include a sequence number in filenames; move to a queue or REST endpoint during modernization.

### ARCH-005 — Business rules duplicated across Forms, DB triggers and packages
**Severity:** MEDIUM
**Location:** `plsql/triggers/trg_employees.sql:1-6`; `forms/xml-exports/HRMS_EMPLOYEE.xml:324-332`; `plsql/packages/PKG_EMPLOYEE.pkb:34-55`

```sql
-- These triggers enforce business rules at the database level,
-- duplicating logic that also exists in PKG_EMPLOYEE and Forms triggers.
-- This is a common anti-pattern in legacy Oracle Forms applications.
```

```sql
    :EMPLOYEE.EMP_ID := SEQ_EMPLOYEE.NEXTVAL;
    :EMPLOYEE.EMP_NUMBER := PKG_EMPLOYEE.generate_emp_number;
    :EMPLOYEE.ACTIVE_FLAG := 'Y';
    :EMPLOYEE.CREATED_BY := :GLOBAL.current_user;
```

**Issue:** Defaulting of `ACTIVE_FLAG`, `EMPLOYMENT_STATUS` and the audit columns happens in the Forms `PRE-INSERT` trigger *and* in `TRG_EMP_BEFORE_INSERT` (`trg_employees.sql:16-32`). The form assigns `EMP_ID` from the sequence directly while `PKG_EMPLOYEE.get_next_emp_id` exists for the same purpose.
**Impact:** Three places to change for one rule; non-Forms callers get different defaults; the `CREATED_BY` written by the form (`:GLOBAL.current_user`, an email) differs in kind from the trigger's fallback (`USER`, a database schema name), so the audit column holds two incompatible identifier types.
**Recommendation:** Make the database trigger the single authority for defaults and audit columns; reduce the form trigger to setting the application user.

### ARCH-006 — Intermediate commits break batch atomicity
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_PAYROLL.pkb:322-325`; `plsql/packages/PKG_LEAVE.pkb:543-548`; `plsql/packages/PKG_PERFORMANCE.pkb:313-316`

```sql
            IF MOD(v_emp_count, 50) = 0 THEN
                COMMIT;
            END IF;
```

**Issue:** Long-running batches commit mid-loop, so there is no transaction boundary around a logical run and no restart marker recording where the last commit landed.
**Impact:** A failure at employee 731 of 900 leaves 700 employees' payroll committed and no supported way to resume or reverse — the run status remains mid-flight while its details are durable.
**Recommendation:** Either commit once per run, or make each batch idempotent and persist a checkpoint (last processed `EMP_ID`) so a restart is well-defined.

### ARCH-007 — Pay element identity hard-coded as magic numbers
**Severity:** LOW
**Location:** `plsql/packages/PKG_REPORTING.pkb:157-160`; `plsql/packages/PKG_PAYROLL.pkb:851-855`

```sql
                   SUM(CASE WHEN pd.ELEMENT_ID = 100 THEN ABS(pd.AMOUNT) ELSE 0 END) AS TOTAL_FED_TAX,
                   SUM(CASE WHEN pd.ELEMENT_ID = 101 THEN ABS(pd.AMOUNT) ELSE 0 END) AS TOTAL_STATE_TAX,
```

**Issue:** Surrogate keys of `PAY_ELEMENTS` rows are embedded in report and register SQL, although `PAY_ELEMENTS.ELEMENT_CODE` is the natural key and is uniquely constrained.
**Impact:** Reseeding reference data in a new environment silently produces zeroed tax columns.
**Recommendation:** Join on `ELEMENT_CODE`.

### ARCH-008 — `DBMS_OUTPUT` used as operational reporting
**Severity:** LOW
**Location:** `plsql/packages/PKG_AUDIT.pkb:45-46`; `plsql/packages/PKG_PERFORMANCE.pkb:316`; `plsql/packages/PKG_LEAVE.pkb:550`

```sql
        DBMS_OUTPUT.PUT_LINE('Purged ' || v_deleted || ' audit records older than ' ||
            p_days_to_keep || ' days');
```

**Issue:** Batch outcomes — records purged, reviews generated, accruals applied — are reported to `DBMS_OUTPUT`, which is discarded when the caller is `DBMS_SCHEDULER`.
**Impact:** No durable record of what scheduled maintenance did.
**Recommendation:** Use `PKG_COMMON.log_info`, which already writes to a table.

### ARCH-009 — `WHEN OTHERS THEN NULL` and blanket handlers hide failures
**Severity:** MEDIUM
**Location:** `forms/libraries/HRMS_COMMON_LIB.pll.sql:24-29`; `plsql/packages/PKG_NOTIFICATION.pkb:128-133`; `plsql/packages/PKG_EMPLOYEE.pkb:51-54`

```sql
                    BEGIN
                        UTL_SMTP.QUIT(v_connection);
                    EXCEPTION
                        WHEN OTHERS THEN NULL;
                    END;
```

**Issue:** Several handlers discard the exception entirely — including the Forms error logger, whose own failure to log is swallowed. `generate_emp_number`'s `WHEN OTHERS` changes behaviour rather than reporting (`RACE-001`).
**Impact:** Faults become invisible or, worse, silently alter behaviour; incident diagnosis has nothing to work from.
**Recommendation:** Catch named exceptions; where a blanket handler is genuinely required (cleanup paths), log before suppressing.

---

## 7. Data Integrity Risks

### DATA-001 — `TRG_EMP_BEFORE_UPDATE` inserts columns that do not exist in `EMPLOYEE_HISTORY`
**Severity:** CRITICAL
**Location:** `plsql/triggers/trg_employees.sql:76-110` vs. `schema/tables/01_core_tables.sql:152-177`

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
    OLD_DEPT_ID          NUMBER(10),
    ...
    CREATED_BY           VARCHAR2(30)    NOT NULL,
```

**Issue:** Six of the eight column names in each of the three `INSERT` statements are absent from the table: `HISTORY_ID` (actual `HIST_ID`), `CHANGE_DATE` (actual `EFFECTIVE_DATE`), `OLD_VALUE`/`NEW_VALUE` (actual typed `OLD_*`/`NEW_*` pairs), `CHANGED_BY` (actual `CREATED_BY`) and `CHANGE_REASON` (actual `REASON_CODE`/`COMMENTS`). The mandatory `CREATED_BY` is never supplied. `PKG_EMPLOYEE.log_history` (`plsql/packages/PKG_EMPLOYEE.pkb:137-179`) uses the correct column set, confirming the DDL is authoritative and the trigger is wrong.
**Impact:** The trigger fails to compile against this schema; if force-compiled it raises `ORA-00904` at runtime. Because it is a `BEFORE UPDATE` trigger on `EMPLOYEES`, **every** update that changes employment status, department or job fails — terminations, transfers and promotions are all blocked, from the forms and from `PKG_EMPLOYEE` alike.
**Recommendation:** Rewrite the three inserts against the real columns (`HIST_ID`, `EFFECTIVE_DATE`, `OLD_DEPT_ID`/`NEW_DEPT_ID`, `OLD_JOB_ID`/`NEW_JOB_ID`, `REASON_CODE`, `CREATED_BY`) — or delete them, since `PKG_EMPLOYEE.log_history` already records these transitions correctly and the trigger duplicates it.

### DATA-002 — `TRG_EMP_BEFORE_INSERT` queries its own mutating table
**Severity:** CRITICAL
**Location:** `plsql/triggers/trg_employees.sql:40-54`

```sql
    DECLARE
        v_count NUMBER;
    BEGIN
        SELECT COUNT(*) INTO v_count
        FROM EMPLOYEES
        WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL)
        AND ACTIVE_FLAG = 'Y';
```

**Issue:** A row-level `BEFORE INSERT` trigger on `EMPLOYEES` selects from `EMPLOYEES`. Oracle raises `ORA-04091: table HRMS.EMPLOYEES is mutating, trigger/function may not see it`.
**Impact:** Every employee insert fails at runtime. Combined with `DATA-001`, the two employee triggers block both insert and update of the system's core entity.
**Recommendation:** Remove the check and enforce email uniqueness with the constraint the comment already claims exists (`DATA-005`); a unique index gives the same guarantee without the mutating-table problem. If a friendlier message is required, catch `DUP_VAL_ON_INDEX` in `PKG_EMPLOYEE`.

### DATA-003 — Trigger writes `CHANGE_TYPE` values the check constraint forbids
**Severity:** HIGH
**Location:** `plsql/triggers/trg_employees.sql:88-109` vs. `schema/tables/01_core_tables.sql:173-176`

```sql
            SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'DEPARTMENT_CHANGE', SYSDATE,
```

```sql
    CONSTRAINT CHK_CHANGE_TYPE CHECK (CHANGE_TYPE IN (
        'HIRE', 'TRANSFER', 'PROMOTION', 'DEMOTION', 'SALARY_CHANGE',
        'TERMINATION', 'REHIRE', 'LEAVE_START', 'LEAVE_END', 'STATUS_CHANGE'
    ))
```

**Issue:** `'DEPARTMENT_CHANGE'` and `'JOB_CHANGE'` are not in the permitted list (the schema's equivalents are `'TRANSFER'` and `'PROMOTION'`/`'DEMOTION'`). Only `'STATUS_CHANGE'` is valid.
**Impact:** A second, independent failure lying behind `DATA-001` — fixing the column names alone would still raise `ORA-02290` on transfers and job changes.
**Recommendation:** Map to the constrained vocabulary when fixing `DATA-001`.

### DATA-004 — Leave audit trigger passes an action the audit constraint rejects, and the failure is swallowed
**Severity:** HIGH
**Location:** `plsql/triggers/trg_audit.sql:47-59`; `schema/tables/04_performance_tables.sql:92-105`; `plsql/packages/PKG_AUDIT.pkb:26-31`

```sql
    PKG_AUDIT.log_action(
        'LEAVE_REQUESTS',
        :NEW.REQUEST_ID,
        'STATUS_CHANGE',
```

```sql
    CONSTRAINT CHK_AUDIT_ACTION CHECK (ACTION_TYPE IN ('INSERT', 'UPDATE', 'DELETE'))
```

**Issue:** `'STATUS_CHANGE'` violates `CHK_AUDIT_ACTION`. `log_action` runs in an autonomous transaction whose handler rolls back and returns normally (`ARCH-001`), so the constraint violation is invisible.
**Impact:** No leave-approval action is ever audited, and nothing reports the gap. This is the most consequential audit trail in the system for HR disputes.
**Recommendation:** Pass `'UPDATE'` and record the semantic change in the JSON payload; add the alerting described in `ARCH-001` so future losses surface.

### DATA-005 — No unique constraint on `EMPLOYEES.EMAIL` despite code assuming one
**Severity:** HIGH
**Location:** `schema/tables/01_core_tables.sql:134-142`; `plsql/triggers/trg_employees.sql:40-41`; `plsql/packages/PKG_SECURITY.pkb:42-56`

```sql
    CONSTRAINT PK_EMPLOYEES PRIMARY KEY (EMP_ID),
    CONSTRAINT UK_EMP_NUMBER UNIQUE (EMP_NUMBER),
```

```sql
    -- Validate email uniqueness (also enforced by unique constraint, but
    -- this trigger provides a better error message)
```

**Issue:** The trigger comment asserts a unique constraint that the DDL does not contain — `EMP_NUMBER` is unique, `EMAIL` is not. The authentication code independently assumes duplicates are possible and handles `TOO_MANY_ROWS`.
**Impact:** Email is the login identifier (`PKG_SECURITY.authenticate`, `HRMS_LOGIN.xml:86-90`), so duplicates are an authentication-correctness problem (`SEC-011`), not merely a data-quality one.
**Recommendation:** Add a unique index on `UPPER(EMAIL)` (function-based, matching how every query compares it) after de-duplicating existing data.

### DATA-006 — Soft-delete design contradicted by the delete trigger
**Severity:** HIGH
**Location:** `plsql/triggers/trg_employees.sql:114-129`; `README.md:114`

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
        'Direct deletion not allowed. Use termination process or set ACTIVE_FLAG to N.');
```

**Issue:** Three names for one object (`AFTER_DELETE` in the comment, `INSTEAD_OF_DELETE` in the identifier, `BEFORE DELETE` in the definition) and none of them soft-delete: the trigger raises. `INSTEAD OF` is not even legal on a table. Forms' `DELETE_RECORD` therefore always errors, and the documented workaround is a manual `ACTIVE_FLAG` update plus `CLEAR_RECORD`.
**Impact:** The Forms delete path is permanently broken; users learn to set `ACTIVE_FLAG` by hand, which bypasses termination processing (no `EMPLOYEE_HISTORY` row, no final pay, no leave payout).
**Recommendation:** Keep the guard but rename it `TRG_EMP_PREVENT_DELETE`, disable delete on the employee block in the form, and route users to `PKG_EMPLOYEE.terminate_employee`.

### DATA-007 — Three different definitions of "available leave"
**Severity:** MEDIUM
**Location:** `schema/tables/03_leave_tables.sql:47`; `plsql/packages/PKG_LEAVE.pkb:376-387`; `schema/views/hrms_views.sql:96`

```sql
    AVAILABLE            NUMBER(6,2)     GENERATED ALWAYS AS (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL,
```

```sql
        SELECT OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING
        INTO v_balance
```

```sql
       lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,
```

**Issue:** The table already computes `AVAILABLE` as a virtual column. `PKG_LEAVE.get_leave_balance` re-implements the same arithmetic instead of selecting it, and `VW_LEAVE_SUMMARY` publishes an `AVAILABLE` that **omits `PENDING`** — so the view's figure is higher than the one enforced at submission time.
**Impact:** Employees see a balance on the summary screen that the system will refuse to honour, generating support load and disputes.
**Recommendation:** Select the virtual column everywhere; if the view intends "available excluding pending", rename that column accordingly.

### DATA-008 — Pending-balance update is unchecked and mis-keyed for cross-year leave
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_LEAVE.pkb:175-183`

```sql
        UPDATE LEAVE_BALANCES
        SET PENDING = PENDING + v_total_days, ...
        WHERE EMP_ID = p_emp_id
        AND LEAVE_TYPE_ID = p_leave_type_id
        AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```

**Issue:** No `SQL%ROWCOUNT` check, so when no balance row exists for that year the request is still inserted with the pending days unrecorded. Leave spanning a year boundary posts all days to the start year even though the balance for the following year is what will actually be consumed.
**Impact:** `PENDING` drifts from the sum of outstanding requests; December-to-January leave over-consumes the old year and under-consumes the new one.
**Recommendation:** Assert the row count (or `MERGE`), and split the day count across calendar years.

### DATA-009 — Multiple active salary rows are possible and views assume one
**Severity:** MEDIUM
**Location:** `schema/tables/02_payroll_tables.sql:10-32`; `schema/views/hrms_views.sql:32-35`, `:79`

```sql
LEFT JOIN SALARY_RECORDS sr ON e.EMP_ID = sr.EMP_ID
    AND sr.ACTIVE_FLAG = 'Y'
    AND sr.EFFECTIVE_DATE <= SYSDATE
    AND (sr.END_DATE IS NULL OR sr.END_DATE > SYSDATE)
```

**Issue:** No constraint limits an employee to one `ACTIVE_FLAG = 'Y'` salary row (see `RACE-008`), yet `VW_ACTIVE_EMPLOYEES` and `VW_EMPLOYEE_COMPENSATION` join as though exactly one exists — `VW_EMPLOYEE_COMPENSATION` uses an inner join with only `ACTIVE_FLAG = 'Y'`, not even the date predicates.
**Impact:** Duplicate employee rows in headcount and compensation reporting, inflating headcount and distorting average-salary and compa-ratio figures.
**Recommendation:** Add the partial unique index from `RACE-008`; until then, resolve the current row with an analytic function in both views.

### DATA-010 — Carryover expiry is not idempotent and leaves no record
**Severity:** MEDIUM
**Location:** `plsql/packages/PKG_LEAVE.pkb:605-623`

```sql
    -- BUG: If run twice on same day, can double-subtract
    PROCEDURE expire_carryover( ... )
    BEGIN
        UPDATE LEAVE_BALANCES SET
            ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
            CARRYOVER_FROM_PREV = 0, ...
        WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE)
        AND CARRYOVER_FROM_PREV > 0;
```

**Issue:** The `CARRYOVER_FROM_PREV > 0` predicate plus the reset to zero makes a plain re-run mostly safe, contrary to the comment — but the operation writes no `LEAVE_ACCRUAL_LOG` row and clears `CARRYOVER_FROM_PREV` without preserving the expired amount, so it cannot be verified or reversed. A partial failure mid-statement is not a risk, but a rollback after a subsequent error in the same session loses the work silently (the `COMMIT` is at the end).
**Impact:** Employees lose balance with no audit record explaining the deduction; disputes cannot be resolved from data.
**Recommendation:** Write a negative `LEAVE_ACCRUAL_LOG` entry per affected row and retain the expired amount in a dedicated column, then correct the stale comment.

### DATA-011 — `HOLIDAYS` permits duplicate and conflicting entries
**Severity:** LOW
**Location:** `schema/tables/03_leave_tables.sql:114-124`

```sql
CREATE TABLE HRMS.HOLIDAYS (
    HOLIDAY_ID           NUMBER(5)       NOT NULL,
    HOLIDAY_DATE         DATE            NOT NULL,
    ...
    CONSTRAINT PK_HOLIDAYS PRIMARY KEY (HOLIDAY_ID)
);
```

**Issue:** Only a surrogate primary key — nothing prevents two rows for the same `(HOLIDAY_DATE, LOCATION_CODE)`, nor an entry with a `LOCATION_CODE` that does not exist in `LOCATIONS` (no foreign key). `HOLIDAY_DATE` is a `DATE` with no truncation constraint, so a row carrying a time component never matches the `HOLIDAY_DATE = v_date` comparisons in `PKG_LEAVE.calculate_business_days` and `PKG_VALIDATION.is_business_day`.
**Impact:** A holiday entered with a time component is silently ignored in every business-day calculation.
**Recommendation:** Add `UNIQUE (HOLIDAY_DATE, LOCATION_CODE)`, a foreign key to `LOCATIONS`, and `CHECK (HOLIDAY_DATE = TRUNC(HOLIDAY_DATE))`.

### DATA-012 — `README.md` inventory does not match the repository
**Severity:** MEDIUM
**Location:** `README.md:36-47`, `:66-79`, `:116`

```
| Forms Modules    |  | PL/SQL Packages  |  | Oracle Reports   |
| 18 forms         |  | 12 packages      |  | 8 reports        |
...
|   42 tables           |
|   15 views            |
|   200+ triggers       |
```

**Issue:** Actual contents: 30 tables, 6 views, 29 sequences, 6 database triggers, 6 Forms XML exports, 11 packages, 0 reports. `README.md:69` lists a `PKG_DEPARTMENT` that does not exist, though `TRG_DEPARTMENT_AUDIT` and the department LOVs imply department logic lives somewhere. The "History tables (`_HIST` suffix)" convention at `:116` is contradicted by the sole history table, `EMPLOYEE_HISTORY`.
**Impact:** Migration scoping and effort estimates built from the README are wrong by a factor of roughly two on tables and by an order of magnitude on triggers.
**Recommendation:** Regenerate the inventory from the tree and keep it in sync, or replace the counts with a generated manifest.

### DATA-013 — No data dictionary, and column comments cover two tables
**Severity:** LOW
**Location:** `schema/tables/01_core_tables.sql:29-30`, `:146-147`

```sql
COMMENT ON COLUMN HRMS.EMPLOYEES.SSN_ENCRYPTED IS 'AES-256 encrypted SSN - decrypted only in PKG_SECURITY';
```

**Issue:** No `DATA_DICTIONARY.md` exists. `COMMENT ON COLUMN` is present only for `DEPARTMENTS` (2 columns) and `EMPLOYEES` (2 columns); the remaining 28 tables have none. Where a comment does exist it is already drifting — `SSN_ENCRYPTED` is described as decrypted only in `PKG_SECURITY`, which is true, but the comment does not record the fixed-key weakness that makes the claim weaker than it sounds (`SEC-003`).
**Impact:** There is no authoritative source to validate code usage against, which is how the `EMPLOYEE_HISTORY` mismatch (`DATA-001`) survived.
**Recommendation:** Generate `DATA_DICTIONARY.md` from `ALL_TAB_COLUMNS`/`ALL_COL_COMMENTS` and add a CI check comparing package and trigger column references against it.

### DATA-014 — `VW_ORG_HIERARCHY` drops subtrees under an inactive manager
**Severity:** MEDIUM
**Location:** `schema/views/hrms_views.sql:47-57`

```sql
WHERE EMPLOYMENT_STATUS = 'ACTIVE'
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
```

**Issue:** The status filter is applied after the hierarchy is walked, so a terminated or on-leave manager severs the branch: every active employee beneath them disappears from the view. `START WITH MANAGER_EMP_ID IS NULL` also assumes exactly one root and silently excludes any orphaned subtree.
**Impact:** Org charts and any headcount derived from the view under-report, and the omission is invisible — the rows are simply absent.
**Recommendation:** Walk the full tree and mark inactive nodes, or re-root orphans; move the filter into the `CONNECT BY` only if pruning is genuinely intended.

### DATA-015 — Soft-delete filters applied inconsistently across queries
**Severity:** MEDIUM
**Location:** `schema/views/hrms_views.sql:36-37`, `:54`, `:80`, `:103`; `plsql/packages/PKG_REPORTING.pkb:26`, `:57`, `:190`; `plsql/packages/PKG_PAYROLL.pkb:296-299`

```sql
WHERE e.EMPLOYMENT_STATUS = 'ACTIVE'
AND e.ACTIVE_FLAG = 'Y';
```

```sql
WHERE e.EMPLOYMENT_STATUS = 'ACTIVE';
```

**Issue:** `EMPLOYEES` carries two independent "is this real" flags. `VW_ACTIVE_EMPLOYEES` and payroll calculation check both; `VW_EMPLOYEE_COMPENSATION`, `VW_LEAVE_SUMMARY`, `VW_ORG_HIERARCHY` and the reporting package check only `EMPLOYMENT_STATUS`. Nothing keeps the two columns consistent — the documented soft-delete workaround (`DATA-006`) sets `ACTIVE_FLAG = 'N'` while leaving `EMPLOYMENT_STATUS = 'ACTIVE'`, producing exactly the divergent state.
**Impact:** Headcount differs between reports depending on which view they use, and a soft-deleted employee still appears in compensation, leave and org reporting — and is still paid.
**Recommendation:** Pick one authority (`EMPLOYMENT_STATUS`), add `CHECK (ACTIVE_FLAG = 'Y' OR EMPLOYMENT_STATUS = 'TERMINATED')`, and standardize every query on it.

---

## Prioritized Migration Roadmap

Effort is expressed in engineering sessions of focused work, excluding external waits (security review, payroll parallel-run sign-off, vendor coordination on the ADP feed).

### Phase 1 — Critical security (do first; `SEC-001` and `DATA-001`/`DATA-002` are production-blocking)

| Order | Findings | Work | Effort |
|-------|----------|------|--------|
| 1 | `SEC-001`, `SEC-005`, `SEC-002` | Build `USER_CREDENTIALS` with salted stretched hashes; make `authenticate` verify and fail closed; make `change_password` persist | 2 sessions |
| 2 | `SEC-004` | Convert `search_employees` to fully bound dynamic SQL | 0.5 session |
| 3 | `SEC-003`, `SEC-007` | Move SSN/bank encryption to TDE or wallet-held keys with per-row IVs; re-encrypt existing rows | 1–2 sessions |
| 4 | `SEC-006`, `SEC-010`, `SEC-011`, `SEC-014` | Failed-attempt tracking with lockout; constant-time failure path; reject ambiguous logins; return `EMP_ID` from `authenticate` | 1 session |
| 5 | `SEC-008`, `SEC-009`, `SEC-012`, `SEC-013` | Credentials to wallet; SMTP endpoint and policy values from `SYSTEM_PARAMETERS`; STARTTLS + AUTH | 1 session |

**Exit criteria:** no code path issues a session without verifying a credential; no secret in version control; a penetration test of the login and search paths passes.

### Phase 2 — Data integrity (restores basic correctness)

| Order | Findings | Work | Effort |
|-------|----------|------|--------|
| 1 | `DATA-001`, `DATA-002`, `DATA-003` | Rewrite or remove the employee triggers so insert and update work against the real DDL | 1 session |
| 2 | `DATA-004`, `ARCH-001` | Fix the audit action value; add loss detection to `PKG_AUDIT` | 0.5 session |
| 3 | `RACE-001`, `RACE-008`, `DATA-005`, `DATA-009` | Sequence-based employee numbers; unique index on `UPPER(EMAIL)`; partial unique index on active salary | 1 session |
| 4 | `RACE-002` … `RACE-007`, `DATA-008`, `DATA-010` | Add `FOR UPDATE` / `MERGE` / row-count assertions to the leave, payroll and session paths | 1–2 sessions |
| 5 | `DATA-006`, `DATA-007`, `DATA-011`, `DATA-014`, `DATA-015` | Single soft-delete authority; single "available" definition; holiday constraints; hierarchy view fix | 1–2 sessions |
| 6 | `VAL-001` … `VAL-007`, `DEP-003` | Collapse duplicated validation into `PKG_VALIDATION`; parameterize thresholds | 1–2 sessions |

**Exit criteria:** a concurrency test suite (parallel hires, parallel leave submissions, parallel payroll runs) produces no duplicates and no negative balances; every trigger compiles clean.

### Phase 3 — Performance (safe to defer until Phase 2 stabilizes the data model)

| Order | Findings | Work | Effort |
|-------|----------|------|--------|
| 1 | `PERF-001`, `PERF-002` | Set-based holiday-aware business-day function used by both modules | 1 session |
| 2 | `PERF-003` | Single SMTP connection per batch with reconnect-on-error | 0.5 session |
| 3 | `PERF-006`, `PERF-007`, `ARCH-006` | Set-based payroll and accrual with checkpoint/restart | 2 sessions |
| 4 | `PERF-004`, `PERF-008`, `PERF-009` | Prune the hierarchy walk, index `MANAGER_EMP_ID`, analytic latest-run views | 1 session |
| 5 | `PERF-005` | `ALTER SEQUENCE ... CACHE` across the schema | 0.25 session |

**Exit criteria:** payroll for the full workforce and the monthly accrual job each complete within their batch window with a single transaction boundary.

### Phase 4 — Modernization

| Order | Findings | Work | Effort |
|-------|----------|------|--------|
| 1 | `ARCH-002`, `ARCH-007` | Drive tax calculation from `TAX_BRACKETS`; join pay elements by code | 1–2 sessions |
| 2 | `ARCH-003` | Implement or fail-loud the time-attendance, org-sync and reporting-refresh stubs | 1–2 sessions |
| 3 | `ARCH-004` | Replace `UTL_FILE` feeds with logged, idempotent, acknowledged transfers | 2 sessions |
| 4 | `ARCH-005`, `DEP-001`, `DEP-002` | Single authority for defaults; invert the security/employee dependency; correct the dependency documentation | 1–2 sessions |
| 5 | `ARCH-008`, `ARCH-009` | Structured logging; remove blanket exception handlers | 1 session |
| 6 | `DATA-012`, `DATA-013` | Generate `DATA_DICTIONARY.md` and a CI check that column references match the DDL | 1 session |

**Exit criteria:** no business rule exists in more than one place; the schema/code consistency check runs in CI; reference data changes require no recompilation.

---

## Appendix — Verification Notes

- Package dependency graph was extracted from all eleven `.pkb` files; the only cross-package edges are `PKG_EMPLOYEE → {PKG_PAYROLL, PKG_NOTIFICATION, PKG_AUDIT, PKG_COMMON}`, `PKG_SECURITY → {PKG_EMPLOYEE, PKG_AUDIT}`, `PKG_LEAVE → {PKG_AUDIT, PKG_NOTIFICATION}`, `PKG_PERFORMANCE → {PKG_AUDIT, PKG_NOTIFICATION}`, `PKG_PAYROLL → {PKG_AUDIT, PKG_COMMON}`, `PKG_INTEGRATION → PKG_COMMON`, `PKG_REPORTING → PKG_COMMON`, `PKG_VALIDATION → PKG_COMMON`, `PKG_NOTIFICATION → PKG_COMMON`. The graph is acyclic (`DEP-001`).
- Trigger column lists were compared line by line against `schema/tables/01_core_tables.sql` and `schema/tables/04_performance_tables.sql`; `DATA-001`, `DATA-003` and `DATA-004` are mismatches confirmed against the DDL.
- `SELECT ... INTO` sites were reviewed individually. `PKG_EMPLOYEE.pkb:520-524` and `:657-660` and `PKG_PAYROLL.pkb:193-196` do lock correctly and are **not** reported as defects; the sites listed under section 2 are the ones that write based on an unlocked read.
- Repository inventory used for `DATA-012`: 30 tables, 6 views, 29 sequences, 6 triggers, 6 Forms XML exports, 11 package spec/body pairs, 2 PLL libraries.
