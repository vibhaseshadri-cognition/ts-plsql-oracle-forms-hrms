# Technical Debt Report — Oracle Forms / PL/SQL HRMS

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Scope:** every file in the repository: 11 PL/SQL packages (spec + body), 2 trigger scripts, 4 table DDL scripts, sequences, views, 2 seed scripts, 2 PLL library sources, 1 menu source, 6 Forms XML exports. That is 42 files and about 8,600 lines.
**Report date:** 2026-10-12

> All file and line references were checked against the current `main` branch. The repository contains a literal AES key. It is **redacted** in this report.

---

## Executive Summary

The analysis found **59 technical-debt items**. The most serious are listed here.

1. **Authentication never checks a password.** `PKG_SECURITY.authenticate` opens a session for any active employee email address, whatever password is entered.
2. **The `EMPLOYEES` update trigger cannot compile.** `TRG_EMP_BEFORE_UPDATE` writes to `EMPLOYEE_HISTORY` columns that do not exist. An invalid trigger makes **every** `UPDATE` on `EMPLOYEES` fail with ORA-04098. That breaks transfer, promotion, termination, rehire, profile edits and Forms saves.
3. **A single bad employee stops the whole payroll run.** The per-employee error handler inserts `ELEMENT_ID = 0`, which is not in `PAY_ELEMENTS`. The resulting FK violation escapes the handler and the run stops. Work already committed stays committed, and the run is left in `CALCULATING`.
4. **The employee search API has a SQL-injection hole.** `PKG_EMPLOYEE.search_employees` builds its WHERE clause by string concatenation, using `p_last_name`, `p_first_name`, `p_status` and `p_location_code`.
5. **The seed scripts cannot load.** They insert into columns that are not in the DDL (`LOCATIONS.PHONE`, `JOB_GRADES.GRADE_LEVEL`, `SYSTEM_PARAMETERS.DESCRIPTION`).

### Severity counts

| Severity | Count |
|----------|------:|
| CRITICAL | 6 |
| HIGH | 15 |
| MEDIUM | 28 |
| LOW | 10 |
| **Total** | **59** |

### Category breakdown

| Category | CRITICAL | HIGH | MEDIUM | LOW | Total |
|----------|---:|---:|---:|---:|---:|
| 1. Security vulnerabilities (SEC) | 4 | 4 | 5 | 1 | 14 |
| 2. Race conditions (RACE) | 0 | 1 | 4 | 0 | 5 |
| 3. Performance (PERF) | 0 | 0 | 5 | 3 | 8 |
| 4. Validation drift (DRIFT) | 0 | 3 | 3 | 0 | 6 |
| 5. Circular dependencies (CIRC) | 0 | 0 | 0 | 1 | 1 |
| 6. Architectural anti-patterns (ARCH) | 0 | 2 | 3 | 3 | 8 |
| 7. Data integrity (DATA) | 2 | 5 | 8 | 2 | 17 |
| **Total** | **6** | **15** | **28** | **10** | **59** |

### Corrections to earlier reports and in-code comments

Several claims in package headers, the README or earlier versions of this report do not match the code. Each one was re-checked:

| Claim | Where | What the code actually does |
|-------|-------|-----------------------------|
| "PKG_EMPLOYEE ↔ PKG_PAYROLL circular dependency" | `PKG_EMPLOYEE.pks:9`, `PKG_PAYROLL.pks:6,9`, `README.md:127` | `PKG_PAYROLL.pkb` never references `PKG_EMPLOYEE`. Today the dependency is one-way only (see CIRC-01). |
| PLL email check "rejects valid subdomains" | `HRMS_VALIDATION_LIB.pll.sql:17-19,39` | The `INSTR` logic **accepts** subdomains. The real drift is that it accepts addresses the server rejects (see DRIFT-01). |
| PLL salary check "uses a hard-coded cache" | `HRMS_VALIDATION_LIB.pll.sql:104-106` | It queries `JOB_GRADES` on every call (`:120-123`). |
| "Carryover expiry double-expires if run twice" | `PKG_LEAVE.pks:10`, `PKG_LEAVE.pkb:608` | The same `UPDATE` resets `CARRYOVER_FROM_PREV = 0`, so a second run matches no rows. The real defect is different (see DATA-10). |
| "FTP credentials stored in SYSTEM_PARAMETERS (cleartext)" | `PKG_INTEGRATION.pks:12` | No FTP code or FTP parameter exists anywhere in the repo. This could not be confirmed and is not counted as a finding. |
| "Overtime calculation does not account for holidays" | `PKG_PAYROLL.pks:11` | `PKG_PAYROLL.pkb` has no overtime calculation at all (see DATA-16). |
| Trigger column mismatch makes history inserts "silently fail" | earlier report | The trigger fails to compile, and an invalid trigger blocks **all** `EMPLOYEES` updates (see DATA-01). |

---

## 1. Security Vulnerabilities

### SEC-01: Authentication never verifies the password (CRITICAL)

**File:** `plsql/packages/PKG_SECURITY.pkb:30-80` (note at `:59-61`)
```sql
SELECT EMP_ID INTO v_emp_id
FROM EMPLOYEES
WHERE UPPER(EMAIL) = UPPER(p_username)
AND EMPLOYMENT_STATUS = 'ACTIVE';
...
-- NOTE: In the real system, passwords are stored in a separate
-- USER_CREDENTIALS table. For this legacy codebase, we simulate
-- authentication against a simplified model.

-- Create session
SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
```
**Issue:** `p_password` is never hashed or compared. The variables `v_stored_hash` and `v_input_hash` (`:37-38`) are declared but never used. Any active employee's email address is enough to log in.
**Impact:** Anyone can take over any account, including payroll administrators, from the `HRMS_LOGIN` form (`HRMS_LOGIN.xml:75-79`).
**Recommendation:** Create a `USER_CREDENTIALS` table (salted adaptive hash, failed-attempt counter, lockout timestamp). Verify the password before inserting `USER_SESSIONS`. Better still, move to SSO (SAML/OIDC) and remove database-side passwords.

---

### SEC-02: Unsalted MD5 password hashing (CRITICAL)

**File:** `plsql/packages/PKG_SECURITY.pkb:14-24`
```sql
RETURN RAWTOHEX(
    DBMS_CRYPTO.HASH(
        UTL_RAW.CAST_TO_RAW(p_password),
        DBMS_CRYPTO.HASH_MD5
    )
);
```
**Issue:** MD5 with no salt. `authenticate` does not even call it today (SEC-01), but it is the only hashing primitive in the codebase and the obvious one for a fix to reuse.
**Impact:** If hashes are stored with this function, they can be cracked with rainbow tables in seconds.
**Recommendation:** Use PBKDF2/bcrypt/Argon2 with a per-user salt (via an external service or Java stored procedure). At an absolute minimum, use `DBMS_CRYPTO.HASH_SH512` with a per-user salt and iteration as an interim step.

---

### SEC-03: Hard-coded AES-256 key; CBC with no IV (CRITICAL)

**File:** `plsql/packages/PKG_SECURITY.pkb:6-7`, `:184-188`, `:197-201`
```sql
-- VULNERABILITY: Encryption key hard-coded in source
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('<REDACTED — literal key in source>');
...
typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
key => c_encryption_key
```
**Issue:** The key that protects `EMPLOYEES.SSN_ENCRYPTED`, `EMPLOYEE_DEPENDENTS.SSN_ENCRYPTED` and (by design) `EMPLOYEE_BANK_ACCOUNTS.ACCOUNT_NUMBER_ENC` is stored in source control. No `iv` is passed, so encryption is deterministic: the same SSN always produces the same ciphertext.
**Impact:** Anyone who can read the repo or `ALL_SOURCE` can decrypt all SSNs. Identical ciphertexts also reveal which records share a value. This is regulatory exposure (PII, PCI-DSS for bank data).
**Recommendation:** Rotate the key now and treat the current one as compromised. Load keys from Oracle Wallet / OCI Vault / HSM. Generate a random IV per value and store it with the ciphertext. Consider TDE column encryption.

---

### SEC-04: SQL injection in `search_employees` (CRITICAL)

**File:** `plsql/packages/PKG_EMPLOYEE.pkb:442-498`
```sql
-- VULNERABILITY: String concatenation instead of bind variable
v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
...
v_sql := v_sql || 'AND e.EMPLOYMENT_STATUS = ''' || p_status || ''' ';
...
v_sql := v_sql || 'AND e.LOCATION_CODE = ''' || p_location_code || ''' ';
...
OPEN p_cursor FOR v_sql;
```
**Issue:** Four string parameters are concatenated into dynamic SQL (`:467`, `:471`, `:479`, `:483`). The header comment (`:442-443`) relies on Forms LOVs to sanitise input, but the package is public and callable directly.
**Impact:** Arbitrary reads under the `HRMS` schema owner's privileges (for example a `UNION SELECT` against `EMPLOYEE_BANK_ACCOUNTS` or `SSN_ENCRYPTED`).
**Recommendation:** Rewrite with bind variables, using the `(:p IS NULL OR col LIKE :p)` pattern or `DBMS_SQL` with `BIND_VARIABLE`. Use `DBMS_ASSERT` for any identifiers.

---

### SEC-05: Authorization is enforced only in Forms, and keyed on a surrogate ID (HIGH)

**Files:** `plsql/packages/PKG_SECURITY.pkb:134-174`; `plsql/packages/PKG_PAYROLL.pkb:555-578` (`approve_payroll`), `:583-600` (`reverse_payroll`); `forms/xml-exports/HRMS_PAYROLL.xml:137-142`
```sql
IF v_grade_id >= 8 THEN
    RETURN TRUE;  -- Senior management - full access
END IF;
```
**Issue:** `approve_payroll`, `reverse_payroll`, `calculate_payroll`, `terminate_employee` and the other mutating APIs do no permission check on the server. Only the Forms button triggers call `has_permission`. `has_permission` compares the surrogate key `JOB_GRADES.GRADE_ID` numerically, as if it were a seniority level. The same user can calculate **and** approve a run, so there is no segregation of duties.
**Impact:** Any database session (SQL*Plus, a report tool, another app) can approve or reverse payroll. Re-numbering grades silently changes who has access.
**Recommendation:** Check permissions inside each API using a `ROLES`/`USER_ROLES` model. Enforce maker-checker on payroll (approver ≠ submitter). Do not tie authorization to surrogate keys.

---

### SEC-06: Forms session validation uses the DB username as the session ID (HIGH)

**Files:** `forms/xml-exports/HRMS_EMPLOYEE.xml:34-35`, `HRMS_PAYROLL.xml:27-28`, `HRMS_LEAVE.xml:25-26`, `HRMS_PERFORMANCE.xml:23-24`
```sql
v_session_id := TO_NUMBER(GET_APPLICATION_PROPERTY(USERNAME));
IF NOT PKG_SECURITY.is_session_valid(v_session_id) THEN
```
**Issue:** The login form stores the session in `:GLOBAL.session_id` (`HRMS_LOGIN.xml:82`), and `HRMS_COMMON_LIB.check_session` (`HRMS_COMMON_LIB.pll.sql:127-138`) reads it correctly. Four forms instead pass the Oracle **username** to `TO_NUMBER`. For any non-numeric schema user this raises `ORA-06502`. For a numeric one it validates the wrong row.
**Impact:** Either the forms cannot open, or session expiry and logout are never actually enforced.
**Recommendation:** Replace the inline checks with `HRMS_COMMON_LIB.check_session`, and add a regression test per form.

---

### SEC-07: No account lockout; user enumeration by timing (HIGH)

**File:** `plsql/packages/PKG_SECURITY.pkb:28`, `:46-56`
```sql
WHEN NO_DATA_FOUND THEN
    -- VULNERABILITY: Timing attack - different response time for
    -- invalid user vs invalid password
    RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
```
**Issue:** Failed attempts are not counted and there is no lockout or backoff. Unknown usernames fail fast, while valid ones go on to create a session.
**Impact:** Unlimited brute force. Valid usernames can be enumerated.
**Recommendation:** Track failed attempts in a credentials table, lock after N failures with exponential backoff, run the same work on every code path, and log failed attempts.

---

### SEC-08: Cleartext credential transmission; no MFA (HIGH)

**File:** `forms/xml-exports/HRMS_LOGIN.xml:10-13`, `:75-79`
```sql
v_session_id := PKG_SECURITY.authenticate(
    :LOGIN.USERNAME,
    :LOGIN.PASSWORD,
    GET_APPLICATION_PROPERTY(CLIENT_HOST)
);
```
**Issue:** The form header documents that the password travels in cleartext ("Forms applet limitation") and that there is no CAPTCHA or 2FA.
**Impact:** Credentials can be sniffed on the network, and a compromised password gives full access.
**Recommendation:** Enforce Oracle Native Network Encryption or TLS (TCPS) on all Forms↔DB traffic. Front the application with SSO plus MFA.

---

### SEC-09: `change_password` is a stub that logs success (MEDIUM)

**File:** `plsql/packages/PKG_SECURITY.pkb:211-234`
```sql
-- NOTE: Actual password update would go to USER_CREDENTIALS table
-- This is a stub for the legacy system model

PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
```
**Issue:** `p_old_password` is never checked and nothing is stored, yet an `UPDATE` audit record is written. The menu exposes this as "Change Password" (`HRMS_MENU.xml:166`).
**Impact:** Users believe they rotated a credential when nothing changed, and the audit trail is false.
**Recommendation:** Implement this together with SEC-01/SEC-02, or remove the menu item.

---

### SEC-10: Session timeout is absolute, hard-coded and not committed (MEDIUM)

**File:** `plsql/packages/PKG_SECURITY.pkb:8`, `:113-121`; parameter `data/seed/01_reference_data.sql:190-191`
```sql
c_session_timeout_min CONSTANT NUMBER := 30;
...
IF (SYSDATE - v_login_time) * 24 * 60 > c_session_timeout_min THEN
```
**Issue:** The timeout is measured from `LOGIN_TIME`, not from last activity. The `SECURITY.SESSION_TIMEOUT_MIN` parameter is ignored. The expiry `UPDATE` runs inside the caller's transaction and is lost if the form rolls back. Comparing to DB-server `SYSDATE` (`PKG_SECURITY.pks:10`) adds clock-skew risk across tiers.
**Impact:** Active users are logged out every 30 minutes, while idle sessions stay valid until then. Expiry state is unreliable.
**Recommendation:** Store `LAST_ACTIVITY` and use a sliding timeout read from `SYSTEM_PARAMETERS`. Persist expiry explicitly.

---

### SEC-11: Hard-coded SMTP over port 25; mail header injection (MEDIUM)

**File:** `plsql/packages/PKG_NOTIFICATION.pkb:7-10`, `:96-101`
```sql
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
...
UTL_SMTP.WRITE_DATA(v_connection,
    'Subject: ' || notif_rec.SUBJECT || UTL_TCP.CRLF);
```
**Issue:** The configuration is compiled into the package even though `NOTIFICATION.SMTP_HOST` and `FROM_ADDRESS` exist in `SYSTEM_PARAMETERS` (`01_reference_data.sql:194-197`). There is no TLS. Subjects are built from employee names (for example `PKG_EMPLOYEE.pkb:320`, `:730`) and written without stripping CR/LF.
**Impact:** Mail is sent unencrypted, an environment change needs a recompile, and an attacker can inject headers.
**Recommendation:** Read the configuration from `SYSTEM_PARAMETERS` or a wallet, use `UTL_SMTP.STARTTLS` on 587, and sanitise header values.

---

### SEC-12: JSON and log payloads built by string concatenation (MEDIUM)

**Files:** `plsql/packages/PKG_COMMON.pkb:24-25`, `:53-54`; `plsql/triggers/trg_audit.sql:20-29`, `:56-57`
```sql
'{"package":"' || p_package || '","procedure":"' || p_procedure ||
'","message":"' || REPLACE(SUBSTR(p_message, 1, 3000), '"', '\"') || '"}',
```
**Issue:** `log_error` escapes only `"`. `log_info` escapes nothing. A NULL salary in `TRG_SALARY_AUDIT` produces invalid JSON (`"salary":,`).
**Impact:** Audit and log records get corrupted and log injection is possible.
**Recommendation:** Use `JSON_OBJECT(...)` (19c), and validate with `IS JSON` check constraints on `AUDIT_LOG.OLD_VALUES/NEW_VALUES`.

---

### SEC-13: PII written to server flat files (MEDIUM)

**File:** `plsql/packages/PKG_INTEGRATION.pkb:98-131`
```sql
v_filename := 'BENEFITS_' || TO_CHAR(SYSDATE, 'YYYYMMDD') || '.txt';
v_file := UTL_FILE.FOPEN(c_benefits_output_dir, v_filename, 'W', 32767);
...
RPAD(NVL(TO_CHAR(rec.DATE_OF_BIRTH, 'YYYY-MM-DD'), ' '), 10) ||
...
RPAD(NVL(TO_CHAR(rec.DEP_DOB, 'YYYY-MM-DD'), ' '), 10)
```
**Issue:** Employee and dependent names, dates of birth, gender and marital status are written in cleartext to a DB-server directory, with no encryption, checksum or retention control. The pay register (`PKG_PAYROLL.pkb:842`) does the same for pay data.
**Impact:** PII is exposed to anyone with OS access to the DB host or the transfer path.
**Recommendation:** Encrypt feeds (PGP) and deliver them over SFTP/API. Restrict directory-object grants and purge files after acknowledgement.

---

### SEC-14: `decrypt_ssn` hides every error (LOW)

**File:** `plsql/packages/PKG_SECURITY.pkb:203-205`
```sql
EXCEPTION
    WHEN OTHERS THEN
        RETURN '***DECRYPT_ERROR***';
```
**Issue:** Key mismatches and corrupted ciphertext become a display string.
**Impact:** Key-rotation failures go unnoticed, and the sentinel value can end up in downstream feeds.
**Recommendation:** Log the error and re-raise it, or return NULL and record an alert.

---

## 2. Race Conditions

### RACE-01: Employee number generated with `MAX()+1` (HIGH)

**File:** `plsql/packages/PKG_EMPLOYEE.pkb:37-55`; caller `forms/xml-exports/HRMS_EMPLOYEE.xml:327`; unused sequence `schema/sequences/hrms_sequences.sql:19-21`
```sql
-- BUG: race condition under concurrent inserts - no SELECT FOR UPDATE
SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
INTO v_max_num
FROM EMPLOYEES
WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
...
WHEN OTHERS THEN
    RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMPLOYEE.NEXTVAL, 6, '0');
```
**Issue:** Two concurrent sessions read the same MAX. The fallback uses `SEQ_EMPLOYEE` (the EMP_ID sequence), not the dedicated `SEQ_EMP_NUMBER`, which is never used.
**Impact:** `UK_EMP_NUMBER` violations ("Duplicate employee number generated. Please retry", `:331-332`) during hiring waves. The fallback numbers can also collide with MAX-based numbers.
**Recommendation:** `'EMP-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0')`, with `SEQ_EMP_NUMBER` re-based above the current maximum.

---

### RACE-02: Payroll run creation checks period status without a lock (MEDIUM)

**File:** `plsql/packages/PKG_PAYROLL.pkb:241-248`
```sql
SELECT STATUS INTO v_status
FROM PAY_PERIODS
WHERE PERIOD_ID = p_period_id;

IF v_status = 'CLOSED' THEN
```
**Issue:** There is no `FOR UPDATE` and no check for an existing REGULAR run in the period. `close_pay_period` does lock (`:193-196`), so the two paths are inconsistent.
**Impact:** Runs can be created against a period that closes concurrently, or two REGULAR runs can exist for one period (double pay).
**Recommendation:** Add `SELECT ... FOR UPDATE` and a unique constraint or function-based index on `(PERIOD_ID, RUN_TYPE)` for non-reversed REGULAR runs.

---

### RACE-03: Promotion and rehire read and update without locking (MEDIUM)

**File:** `plsql/packages/PKG_EMPLOYEE.pkb:592-614` (`promote_employee`), `:750-793` (`rehire_employee`)
```sql
SELECT JOB_ID INTO v_old_job_id
FROM EMPLOYEES
WHERE EMP_ID = p_emp_id;
```
**Issue:** `transfer_employee` and `terminate_employee` use `FOR UPDATE` (`:520-523`, `:657-660`), but `promote_employee` and `rehire_employee` do not. Rehire also never checks that the employee is currently TERMINATED, and never validates `p_job_id` or the manager.
**Impact:** Concurrent HR edits lose updates and the history rows record the wrong "old" values.
**Recommendation:** Lock the row with `FOR UPDATE NOWAIT`, check the status, and reuse `validate_dept`/`validate_manager`/job validation.

---

### RACE-04: The notification queue can be processed twice at once (MEDIUM)

**File:** `plsql/packages/PKG_NOTIFICATION.pkb:78-87`
```sql
FOR notif_rec IN (
    SELECT NOTIFICATION_ID, RECIPIENT_EMAIL, SUBJECT, BODY, NOTIFICATION_TYPE
    FROM NOTIFICATION_QUEUE
    WHERE STATUS = 'PENDING'
    ...
    FETCH FIRST p_batch_size ROWS ONLY
) LOOP
```
**Issue:** Rows are not locked or claimed. If the 5-minute job overlaps with itself or a manual run, both sessions send the same rows.
**Impact:** Duplicate emails, including termination and leave notices.
**Recommendation:** Use `FOR UPDATE SKIP LOCKED`, or claim rows with `UPDATE ... SET STATUS='SENDING' ... RETURNING`. Better, use Oracle AQ.

---

### RACE-05: Leave balance check is not atomic with the reservation (MEDIUM)

**File:** `plsql/packages/PKG_LEAVE.pkb:141-182`
```sql
v_balance := get_leave_balance(p_emp_id, p_leave_type_id);
IF v_balance < v_total_days THEN
...
UPDATE LEAVE_BALANCES
SET PENDING = PENDING + v_total_days
```
**Issue:** The overlap check, the balance check and the `PENDING` reservation run as separate unlocked statements.
**Impact:** Two concurrent submissions (Forms plus self-service) can both pass, overdrawing the balance or creating overlapping requests.
**Recommendation:** Lock the `LEAVE_BALANCES` row (`SELECT ... FOR UPDATE`) before checking, or do a guarded `UPDATE ... WHERE AVAILABLE >= :days` and check `SQL%ROWCOUNT`.

---

## 3. Performance Issues

### PERF-01: Day-by-day loop with one holiday query per day (MEDIUM)

**File:** `plsql/packages/PKG_LEAVE.pkb:12-40`
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count
        FROM HOLIDAYS
        WHERE HOLIDAY_DATE = v_date
        ...
    v_date := v_date + 1;
END LOOP;
```
**Issue:** O(n) PL/SQL iterations, plus one SQL round-trip per weekday, on every leave submission.
**Impact:** Slow submissions for long leaves (sabbatical, maternity), and unnecessary load during peak periods.
**Recommendation:** Do a single set-based count, for example `SELECT COUNT(*) FROM (calendar CTE) WHERE dow NOT IN (...) AND NOT EXISTS (holiday)`, or use a calendar dimension table.

---

### PERF-02: Day-by-day loops in `PKG_COMMON` (MEDIUM)

**File:** `plsql/packages/PKG_COMMON.pkb:132-146` (`business_days_between`), `:151-165` (`add_business_days`)
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        v_count := v_count + 1;
    END IF;
    v_date := v_date + 1;
END LOOP;
```
**Issue:** The same O(n) pattern. These helpers also **ignore holidays**, unlike `PKG_LEAVE.calculate_business_days` (see DRIFT-05).
**Impact:** CPU cost on long ranges, and different "business day" answers depending on which helper is called.
**Recommendation:** Use closed-form weekday arithmetic or a calendar table, with one shared implementation.

---

### PERF-03: `CONNECT BY` org hierarchy (MEDIUM)

**Files:** `schema/views/hrms_views.sql:43-57`; `plsql/packages/PKG_EMPLOYEE.pkb:818-840`
```sql
-- WARNING: Performance degrades significantly with >500 employees
CREATE OR REPLACE VIEW HRMS.VW_ORG_HIERARCHY AS
...
WHERE EMPLOYMENT_STATUS = 'ACTIVE'
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
ORDER SIBLINGS BY LAST_NAME;
```
**Issue:** The view and `get_org_chart` both walk the whole tree on every query, and there is no index on `MANAGER_EMP_ID`. The `WHERE` filter is applied **after** the hierarchy is built, so employees under a terminated manager still appear, with that terminated manager in their `ORG_PATH`.
**Impact:** Self-documented timeouts above about 500 employees, and misleading org paths.
**Recommendation:** Index `EMPLOYEES(MANAGER_EMP_ID)`. Move the status filter into `START WITH`/`CONNECT BY`, or use a recursive CTE. Materialise a closure table for org-chart reads.

---

### PERF-04: New SMTP connection per notification (MEDIUM)

**File:** `plsql/packages/PKG_NOTIFICATION.pkb:88-107`
```sql
v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
UTL_SMTP.HELO(v_connection, c_smtp_host);
...
UTL_SMTP.QUIT(v_connection);
```
**Issue:** Each batch of 50 performs 50 TCP handshakes and HELO exchanges.
**Impact:** Slow queue drain, so bursts (open enrolment, review cycles) can outlast the 5-minute schedule.
**Recommendation:** Open one connection per batch and use `RSET` between messages, or hand delivery to an MTA or mail service.

---

### PERF-05: Row-by-row payroll and accrual batches (MEDIUM)

**Files:** `plsql/packages/PKG_PAYROLL.pkb:295-327`, `:405-543`; `plsql/packages/PKG_LEAVE.pkb:470-546`
```sql
-- BUG: Cursor loop - should use BULK COLLECT + FORALL
FOR emp_rec IN (
    SELECT e.EMP_ID
    FROM EMPLOYEES e
    WHERE e.EMPLOYMENT_STATUS = 'ACTIVE'
```
**Issue:** Each employee costs about 6 single-row inserts plus 4 lookups (salary, tax info, YTD, period). Monthly accrual is a nested employee × leave-type loop with `get_leave_balance` per pair.
**Impact:** Payroll and accrual windows grow linearly with headcount and many context switches.
**Recommendation:** Use `BULK COLLECT`/`FORALL`, or set-based `INSERT ... SELECT` for earnings and statutory taxes. Pre-aggregate YTD once per run.

---

### PERF-06: `NOCACHE` sequences (LOW)

**File:** `schema/sequences/hrms_sequences.sql:9-49`
```sql
CREATE SEQUENCE HRMS.SEQ_PAYROLL_DETAIL START WITH 1 INCREMENT BY 1 NOCACHE;
```
**Issue:** 28 of 29 sequences are `NOCACHE`. Only `SEQ_AUDIT` uses `CACHE 100` (`:45`).
**Impact:** Data dictionary updates on every `NEXTVAL`, which causes contention during payroll (`SEQ_PAYROLL_DETAIL`), accrual and notification bursts.
**Recommendation:** Use `CACHE 100`–`1000` for high-volume sequences. Gaps are acceptable for surrogate keys.

---

### PERF-07: Per-row lookups in Forms `POST-QUERY` (LOW)

**Files:** `forms/xml-exports/HRMS_EMPLOYEE.xml:345-368`; `forms/xml-exports/HRMS_LEAVE.xml:94-106`
```sql
SELECT DEPT_NAME INTO :EMPLOYEE.DEPT_NAME_DISP
FROM DEPARTMENTS WHERE DEPT_ID = :EMPLOYEE.DEPT_ID;
```
**Issue:** Three extra round-trips per employee row (dept, job, manager), and an extra join query per leave row.
**Impact:** Slow multi-record queries over the WAN.
**Recommendation:** Base the blocks on views that already contain the display columns (for example `VW_ACTIVE_EMPLOYEES`).

---

### PERF-08: Reporting refresh is a placeholder; reports read stale data (LOW)

**Files:** `plsql/packages/PKG_REPORTING.pkb:196-204`; `plsql/packages/PKG_REPORTING.pks:9`
```sql
-- Placeholder for nightly refresh of denormalized reporting tables
-- In production, this truncates and repopulates RPT_* tables
PKG_COMMON.log_info('PKG_REPORTING', 'refresh_reporting_tables',
    'Reporting tables refreshed', p_user);
```
**Issue:** The refresh job logs success without doing anything, and no `RPT_*` tables exist in the DDL.
**Impact:** Operators believe the nightly refresh works.
**Recommendation:** Implement the refresh with materialised views (`REFRESH FAST ON COMMIT` where possible), or remove the job.

---
## 4. Validation Drift (PLL vs Forms vs Server vs Triggers)

### DRIFT-01: Email validation differs across three layers (HIGH)

**Client PLL:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41`
```sql
v_at_pos := INSTR(p_email, '@');
...
v_dot_pos := INSTR(p_email, '.', v_at_pos);
IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN
    RETURN FALSE;
END IF;
-- BUG: Only checks for one dot after @, rejects valid subdomains
RETURN TRUE;
```
**Server:** `plsql/packages/PKG_COMMON.pkb:265-268` (called by `PKG_VALIDATION.validate_email_format`, `PKG_VALIDATION.pkb:50-55`)
```sql
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```
**Issue:** The two rules disagree, but not in the way the PLL comment says. The PLL **accepts** subdomains (`user@mail.company.com`). It also accepts addresses the server regex rejects: one-letter TLDs (`a@b.c`), spaces (`john smith@co.com`) and characters such as `!`. The `HRMS_EMPLOYEE` form calls the server rule (`HRMS_EMPLOYEE.xml:375-380`), which leaves the PLL function as attached dead code. The write APIs `PKG_EMPLOYEE.create_employee` and `update_employee` validate nothing; they only lower-case and trim (`PKG_EMPLOYEE.pkb:267`, `:371`).
**Impact:** Batch, API and integration paths store invalid emails. Email is also the login username (SEC-01), and bad addresses make notifications fail (`PKG_NOTIFICATION.pkb:117-124`).
**Recommendation:** Keep a single server-side rule in `PKG_VALIDATION`. Call it from the APIs and enforce it with a `CHECK (REGEXP_LIKE(...))` constraint. Delete the PLL copy.

---

### DRIFT-02: The future hire-date limit is 90 days, 180 days or unlimited, depending on the path (HIGH)

| Layer | Rule | Location |
|-------|------|----------|
| Forms `WHEN-VALIDATE-ITEM` | `HIRE_DATE > SYSDATE + 90` → error | `forms/xml-exports/HRMS_EMPLOYEE.xml:382-386` |
| DB trigger | `HIRE_DATE > SYSDATE + 180` → error | `plsql/triggers/trg_employees.sql:34-38` |
| PLL | `validate_date_not_future`: any future date is invalid | `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:96-99` |
| `PKG_EMPLOYEE.create_employee` / `rehire_employee` | no check | `plsql/packages/PKG_EMPLOYEE.pkb:184-342`, `:750-793` |

**Issue:** Four different rules for the same field.
**Impact:** A hire dated 120 days out is blocked in the form but accepted through the API, which confuses users and support.
**Recommendation:** Pick one value, store it in `SYSTEM_PARAMETERS`, and enforce it in `PKG_VALIDATION`. Forms should call that rule for immediate feedback.

---

### DRIFT-03: Salary-range enforcement ranges from a hard error to nothing (HIGH)

**Files:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:102-135`; `plsql/packages/PKG_VALIDATION.pkb:17-48`; `plsql/packages/PKG_EMPLOYEE.pkb:220-241`; `plsql/packages/PKG_PAYROLL.pkb:19-33`
```sql
-- PKG_EMPLOYEE.create_employee
IF p_base_salary < v_min OR p_base_salary > v_max THEN
    -- NOTE: This is a soft warning, not an error
    ...
    IF g_debug_mode THEN
        DBMS_OUTPUT.PUT_LINE('WARNING: Salary ' || p_base_salary || ...
```
**Issue:** The PLL and `PKG_VALIDATION` reject out-of-grade salaries. `create_employee` only prints a warning when debug is on (it is off by default, `PKG_EMPLOYEE.pks:17`). `promote_employee`, `rehire_employee` and `PKG_PAYROLL.create_salary_record` only check `> 0`. The PLL comment says the check is cached (`:104-106`), but the code queries the table every time (`:120-123`).
**Impact:** Out-of-band salaries enter the system through any path except the form, which skews compa-ratios (`VW_EMPLOYEE_COMPENSATION`) and creates pay-equity exposure.
**Recommendation:** Enforce the grade range in `create_salary_record` with an explicit, audited override flag (approver ID). Remove the duplicate checks.

---

### DRIFT-04: SSN and phone rules differ between PLL and server (MEDIUM)

**Files:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:47-63`, `:69-90`; `plsql/packages/PKG_COMMON.pkb:270-280`
```sql
-- PLL
v_digits := TRANSLATE(p_phone, '0123456789()-. +x', '0123456789');
...
IF SUBSTR(v_digits, 1, 3) = '000' OR SUBSTR(v_digits, 4, 2) = '00' ...
-- Server
RETURN REGEXP_LIKE(REGEXP_REPLACE(p_ssn, '[^0-9]', ''), '^\d{9}$');
```
**Issue:** The PLL `TRANSLATE` strips only the listed punctuation, so letters remain and count toward the length (`555ABC1234` passes the PLL but fails the server). The PLL rejects SSNs with an all-zero group; the server accepts `000-00-0000`.
**Impact:** The same input gets different accept/reject results in different layers, and invalid SSNs can be stored through APIs.
**Recommendation:** Use one rule set in `PKG_VALIDATION`, with SSA rules (no 000/666/9xx area, no 00 group, no 0000 serial).

---

### DRIFT-05: Date-range and business-day logic differ between packages (MEDIUM)

**Files:** `plsql/packages/PKG_VALIDATION.pkb:6-15`, `:78-97`; `plsql/packages/PKG_COMMON.pkb:132-165`; `plsql/packages/PKG_LEAVE.pkb:12-40`, `:116-126`
```sql
-- PKG_VALIDATION.validate_date_range
IF p_start_date IS NULL OR p_end_date IS NULL THEN
    RETURN FALSE;
```
**Issue:** `validate_date_range` treats an open-ended range as invalid. Nothing calls it: `PKG_LEAVE` re-implements the check inline and adds a 5-day backdating rule that exists only on the server. `PKG_COMMON.business_days_between` ignores holidays, while `PKG_LEAVE.calculate_business_days` and `PKG_VALIDATION.is_business_day` subtract them.
**Impact:** Different day counts in leave, notification SLA and report calculations.
**Recommendation:** Centralise calendar logic in one package backed by a calendar table, and remove the unused duplicates.

---

### DRIFT-06: Configuration exists in `SYSTEM_PARAMETERS` but the code hard-codes it (MEDIUM)

| Parameter (seed) | Hard-coded in code |
|------------------|--------------------|
| `PAYROLL.FISCAL_YEAR_START = 10` (`data/seed/01_reference_data.sql:188-189`) | `PKG_COMMON.pkb:170-195` (`>= 10`, quarter map) |
| `SECURITY.SESSION_TIMEOUT_MIN = 30` (`:190-191`) | `PKG_SECURITY.pkb:8` |
| `SECURITY.PASSWORD_MIN_LENGTH = 8` (`:192-193`) | `PKG_SECURITY.pkb:218` |
| `NOTIFICATION.SMTP_HOST`, `FROM_ADDRESS` (`:194-197`) | `PKG_NOTIFICATION.pkb:7-10` |

**Issue:** Admins can edit these values (`EDITABLE_FLAG='Y'`), but changes have no effect.
**Impact:** Configuration changes silently do nothing, which leads to false assurance during audits.
**Recommendation:** Read the values through `PKG_COMMON.get_param*` (with caching), or remove the unused parameters.

---

## 5. Circular Dependencies

### CIRC-01: The documented PKG_EMPLOYEE ↔ PKG_PAYROLL cycle is not in the code; a real cycle is planned (LOW)

**Files:** `plsql/packages/PKG_EMPLOYEE.pks:6,9`; `plsql/packages/PKG_PAYROLL.pks:6,9`; `README.md:127`; `plsql/packages/PKG_EMPLOYEE.pkb:273-275`, `:737-739`

Body-level references (from `grep PKG_*.` across `plsql/`):

| Package body | Calls |
|--------------|-------|
| PKG_EMPLOYEE | PKG_AUDIT, PKG_COMMON, PKG_NOTIFICATION, **PKG_PAYROLL** |
| PKG_PAYROLL | PKG_AUDIT, PKG_COMMON (**no PKG_EMPLOYEE**) |
| PKG_SECURITY | PKG_AUDIT, **PKG_EMPLOYEE** |
| PKG_LEAVE / PKG_PERFORMANCE | PKG_AUDIT, PKG_NOTIFICATION |
| PKG_NOTIFICATION / PKG_INTEGRATION / PKG_REPORTING / PKG_VALIDATION | PKG_COMMON |

```sql
-- PKG_EMPLOYEE.pkb:273-274
-- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
-- which in turn may call PKG_EMPLOYEE.is_active for validation
...
-- PKG_EMPLOYEE.pkb:738
-- TODO: Revoke system access via PKG_SECURITY
```
**Issue:** The body-level graph has no cycles. `PKG_PAYROLL` never calls `PKG_EMPLOYEE.is_active`, yet its spec header declares that dependency. The TODO at `:738` would create a real `PKG_SECURITY ↔ PKG_EMPLOYEE` cycle, because `PKG_SECURITY.authenticate` already calls `PKG_EMPLOYEE.set_session_context` (`PKG_SECURITY.pkb:75`).
**Impact:** Stale documentation sends refactoring effort in the wrong direction. Implementing the TODO as written would bring back cascade invalidation.
**Recommendation:** Correct the headers and README. When adding access revocation, raise an event (for example an AQ message or a `PKG_EMPLOYEE_EVENTS` hook) instead of calling `PKG_SECURITY` directly. Split `set_session_context` into a dependency-free context package.

---

## 6. Architectural Anti-Patterns

### ARCH-01: Autonomous transactions combined with swallowed exceptions (HIGH)

**Files:** `plsql/packages/PKG_AUDIT.pkb:14`, `:27-30`; `plsql/packages/PKG_COMMON.pkb:16`, `:46`; `plsql/packages/PKG_NOTIFICATION.pkb:27`, `:57-63`; `plsql/packages/PKG_EMPLOYEE.pkb:155`, `:171-178`
```sql
PRAGMA AUTONOMOUS_TRANSACTION;
...
EXCEPTION
    WHEN OTHERS THEN
        -- Audit logging must never fail the calling transaction
        ROLLBACK;
```
**Issue:** Audit, history and notification writes commit independently of the business transaction, and every failure is swallowed. `create_employee` writes the HIRE history, the audit row and the welcome emails autonomously. If anything fails afterwards, those records remain for a hire that never happened.
**Impact:** Phantom audit and history rows, emails about events that were rolled back, and audit gaps nobody notices (DATA-05 is one live example).
**Recommendation:** Write history and notifications in the main transaction (use the outbox pattern for email). Keep `AUTONOMOUS_TRANSACTION` only for error logging, and make audit failures visible through an alert or metric.

---

### ARCH-02: Hard-coded 2024 tax tables while a `TAX_BRACKETS` table exists (HIGH)

**Files:** `plsql/packages/PKG_PAYROLL.pkb:7-14`, `:602-686`, `:689-718`; unused table `schema/tables/02_payroll_tables.sql:159-172`
```sql
c_ss_wage_base_2024   CONSTANT NUMBER := 168600;   -- Social Security wage base
...
-- 2024 Federal tax brackets (Single)
-- TODO: Read from TAX_BRACKETS table instead of hard-coding
IF p_filing_status = 'SINGLE' OR p_filing_status = 'MARRIED_SEPARATE' THEN
    IF v_taxable <= 11600 THEN
```
**Issue:** Federal brackets, standard deductions, the Social Security wage base and the Medicare threshold are fixed at 2024 values. State tax is a flat rate per state with a **5% default for any unlisted state** (`:714`). `HEAD_OF_HOUSEHOLD` falls through every branch and gets **zero federal tax** (`:645-677`). `v_taxable_income` ignores pre-tax deductions (`:437`).
**Impact:** Wrong withholding in 2025 and later (the report date is 2026), with compliance and penalty risk.
**Recommendation:** Drive all tax data from effective-dated `TAX_BRACKETS` and statutory-limit tables, or integrate a tax engine. Add unit tests (utPLSQL) per filing status.

---

### ARCH-03: UTL_FILE flat-file integrations with no integrity controls (MEDIUM)

**Files:** `plsql/packages/PKG_INTEGRATION.pkb:7-9`, `:27`, `:99`, `:162`; `plsql/packages/PKG_PAYROLL.pkb:842`, `:869-880`
```sql
v_file := UTL_FILE.FOPEN(c_gl_output_dir, v_filename, 'W', 32767);
...
'"' || rec.EMP_NAME || '",' ||
```
**Issue:** The GL journal, benefits feed, time import and pay register all go through server-side files. There is no checksum, acknowledgement, retry or idempotency. CSV fields are quoted but embedded quotes are not escaped. `RPAD` silently truncates names longer than 30 characters in the fixed-width ADP feed.
**Impact:** Files lost or corrupted silently, malformed CSV, and truncated vendor records.
**Recommendation:** Move to API or AQ-based integration with delivery receipts. Until then, add trailer hash totals, `.done` marker files and an `INTEGRATION_LOG` table.

---

### ARCH-04: Stubs and placeholders that report success (MEDIUM)

| Routine | Location | Behaviour |
|---------|----------|-----------|
| `import_time_attendance` | `PKG_INTEGRATION.pkb:168-171` | Counts lines as "imported"; parses nothing (`-- TODO`) |
| `sync_org_structure` | `PKG_INTEGRATION.pkb:196-203` | Logs "Org structure sync completed"; does nothing |
| `refresh_reporting_tables` | `PKG_REPORTING.pkb:196-204` | Logs "refreshed"; does nothing |
| `change_password` | `PKG_SECURITY.pkb:211-234` | Validates complexity only; never persists |
| `terminate_employee` | `PKG_EMPLOYEE.pkb:737-739` | COBRA, access revocation and final pay are all TODO |
| `get_payslip` | `PKG_PAYROLL.pkb:784-785` | `YTD_GROSS`/`YTD_NET` hard-coded to 0 |

**Impact:** Operations dashboards and logs show success for work that never happened. Terminated employees get no final-pay calculation.
**Recommendation:** Either implement each routine or make it raise `-20999 'Not implemented'` so it is not silently trusted.

---

### ARCH-05: Forms bypasses the API layer; delete paths fight the soft-delete trigger (MEDIUM)

**Files:** `forms/xml-exports/HRMS_EMPLOYEE.xml:323-334`, `:533-536`; `forms/libraries/HRMS_COMMON_LIB.pll.sql:88-91`; `plsql/triggers/trg_employees.sql:120-130`
```sql
-- HRMS_EMPLOYEE PRE-INSERT
:EMPLOYEE.EMP_ID := SEQ_EMPLOYEE.NEXTVAL;
:EMPLOYEE.EMP_NUMBER := PKG_EMPLOYEE.generate_emp_number;
...
-- TRG_EMP_INSTEAD_OF_DELETE (BEFORE DELETE)
RAISE_APPLICATION_ERROR(-20504,
    'Direct deletion not allowed. Use termination process or set ACTIVE_FLAG to N.');
```
**Issue:** The Employee form inserts directly into `EMPLOYEES` through its base-table block, which skips `PKG_EMPLOYEE.create_employee`: no HIRE history, no initial salary record, no notifications. The form still ships a "Confirm Delete" alert, and the shared toolbar calls `DELETE_RECORD`. Both always hit ORA-20504. Despite its name, the trigger is `BEFORE DELETE`, not `INSTEAD OF`.
**Impact:** Two different hire workflows with different side effects, and user-facing errors on delete.
**Recommendation:** Base the block on a view with `INSTEAD OF` triggers that call `PKG_EMPLOYEE`, or use procedure-based DML (`ON-INSERT`/`ON-DELETE` → API). Remove the delete affordances.

---

### ARCH-06: Hard-coded fiscal year (LOW)

**Files:** `plsql/packages/PKG_COMMON.pkb:170-195`; `plsql/packages/PKG_REPORTING.pks:10`
```sql
IF EXTRACT(MONTH FROM p_date) >= 10 THEN
    RETURN EXTRACT(YEAR FROM p_date) + 1;
```
**Issue:** The fiscal year is fixed to start on 1 October, even though `PAYROLL.FISCAL_YEAR_START` exists (DRIFT-06).
**Recommendation:** Derive it from the parameter, or from a fiscal calendar table.

---

### ARCH-07: Package global variables used as session state (LOW)

**File:** `plsql/packages/PKG_EMPLOYEE.pks:13-17`; `plsql/packages/PKG_EMPLOYEE.pkb:948-963`
```sql
g_current_user       VARCHAR2(30);
g_current_emp_id     NUMBER(10);
g_current_dept_id    NUMBER(10);
```
**Issue:** Session context lives in package globals that `authenticate` sets. Nothing in the bodies reads them. They are lost when the package is recompiled (ORA-04068) and leak between users under connection pooling.
**Recommendation:** Use an application context (`DBMS_SESSION.SET_CONTEXT`) or pass the identity explicitly.

---

### ARCH-08: Magic pay-element IDs (LOW)

**Files:** `plsql/packages/PKG_PAYROLL.pkb:409`, `:448`, `:466`, `:481`, `:495`, `:780-783`, `:854-857`; `plsql/packages/PKG_REPORTING.pkb:157-160`
```sql
SUM(CASE WHEN pd.ELEMENT_ID = 100 THEN ABS(pd.AMOUNT) ELSE 0 END) AS FEDERAL_TAX,
```
**Issue:** The values 1, 100, 101, 102 and 103 are hard-coded throughout and only match by convention with the seed (`data/seed/01_reference_data.sql:122-133`).
**Recommendation:** Look elements up by `ELEMENT_CODE` (unique, `UK_PAY_ELEM_CODE`) through constants or a cached function.

---
## 7. Data Integrity Risks

### DATA-01: `TRG_EMP_BEFORE_UPDATE` uses columns that do not exist; every `EMPLOYEES` update fails (CRITICAL)

**Trigger:** `plsql/triggers/trg_employees.sql:62-111` (INSERTs at `:78`, `:90`, `:102`)
**Table DDL:** `schema/tables/01_core_tables.sql:152-177`
```sql
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (
    SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'DEPARTMENT_CHANGE', SYSDATE, ...
```

| Trigger column | Actual `EMPLOYEE_HISTORY` column |
|----------------|----------------------------------|
| `HISTORY_ID` | `HIST_ID` |
| `CHANGE_DATE` | `EFFECTIVE_DATE` |
| `OLD_VALUE` / `NEW_VALUE` | `OLD_DEPT_ID`/`NEW_DEPT_ID`, `OLD_JOB_ID`/`NEW_JOB_ID`, … (typed columns) |
| `CHANGED_BY` | `CREATED_BY` (NOT NULL, never supplied) |
| `CHANGE_REASON` | `REASON_CODE` / `COMMENTS` |
| `CHANGE_TYPE` values `'DEPARTMENT_CHANGE'`, `'JOB_CHANGE'` | not allowed by `CHK_CHANGE_TYPE` (`:173-176`) |

**Issue:** Static SQL that references unknown columns is a compile error (PLS-00904/ORA-00904), so the trigger is created **INVALID**. Oracle then raises **ORA-04098 "trigger is invalid and failed re-validation"** on every `UPDATE` of `HRMS.EMPLOYEES`, whatever columns change. Even after a compile fix, the CHANGE_TYPE values would fail the check constraint. The same changes are also already recorded by `PKG_EMPLOYEE.log_history` (`PKG_EMPLOYEE.pkb:137-179`), which uses the correct columns, so the trigger duplicates that history.
**Impact:** `update_employee`, `transfer_employee`, `promote_employee`, `terminate_employee`, `rehire_employee` and every Forms save on the EMPLOYEE block fail.
**Recommendation:** Drop the trigger's history inserts and rely on `PKG_EMPLOYEE.log_history`. If trigger-level capture is required, rewrite it against the real columns and the allowed `CHANGE_TYPE` values (`STATUS_CHANGE`, `TRANSFER`, …) and supply `CREATED_BY`. Add a deployment check: `SELECT * FROM USER_ERRORS` must return no rows.

---

### DATA-02: The payroll error handler violates an FK; one bad employee stops the run (CRITICAL)

**File:** `plsql/packages/PKG_PAYROLL.pkb:286-326`; FK `schema/tables/02_payroll_tables.sql:153`; seed `data/seed/01_reference_data.sql:122-153`
```sql
COMMIT;   -- :292, run marked CALCULATING
...
EXCEPTION
    WHEN OTHERS THEN
        v_error_count := v_error_count + 1;
        INSERT INTO PAYROLL_DETAILS (
            DETAIL_ID, RUN_ID, EMP_ID, ELEMENT_ID, ...
        ) VALUES (
            SEQ_PAYROLL_DETAIL.NEXTVAL, p_run_id, emp_rec.EMP_ID, 0,
            'ERROR', 0, 'ERROR', SUBSTR(SQLERRM, 1, 4000), ...
```
**Issue:** `ELEMENT_ID = 0` is not a `PAY_ELEMENTS` row (the seed defines 1, 100–103 and 200–205), so the insert inside the handler raises ORA-02291 and leaves `calculate_payroll`. A common trigger is any active employee with no salary record (`-20104`, `:396-399`). By then the run is committed as `CALCULATING` (`:292`) and detail rows are committed every 50 employees (`:322-326`). The Forms *Calculate* button only allows `PENDING` runs (`HRMS_PAYROLL.xml:114-117`), so the run cannot be restarted from the UI.
**Impact:** Payroll stops partway through and stays stuck, with partial pay data committed. Recovery needs a manual DBA cleanup.
**Recommendation:** Seed a dedicated `ERROR` pay element, or write errors to a separate `PAYROLL_ERRORS` table. Make the calculation restartable: delete the run's details first, then recalculate in one transaction or behind a savepoint per employee. Handle NULL-salary employees up front.

---

### DATA-03: The rehire process is blocked by the trigger that points users to it (HIGH)

**Files:** `plsql/triggers/trg_employees.sql:69-74`; `plsql/packages/PKG_EMPLOYEE.pkb:761-771`
```sql
-- trigger
IF :OLD.EMPLOYMENT_STATUS = 'TERMINATED' AND :NEW.EMPLOYMENT_STATUS = 'ACTIVE' THEN
    RAISE_APPLICATION_ERROR(-20503,
        'Cannot directly reactivate a terminated employee. Use the rehire process.');
-- PKG_EMPLOYEE.rehire_employee
UPDATE EMPLOYEES SET
    EMPLOYMENT_STATUS  = 'ACTIVE',
```
**Issue:** The rehire process makes exactly the transition the trigger forbids.
**Impact:** Rehires are impossible, even once DATA-01 is fixed.
**Recommendation:** Let the rehire path through, for example with a context flag set by `PKG_EMPLOYEE` and checked by the trigger. Better, move the rule into the API and drop it from the trigger.

---

### DATA-04: Seed scripts reference columns missing from the DDL (HIGH)

| Seed | Column used | DDL |
|------|-------------|-----|
| `data/seed/01_reference_data.sql:11-18` (LOCATIONS) | `PHONE` | `PHONE_NUMBER` (`schema/tables/01_core_tables.sql:44`) |
| `data/seed/01_reference_data.sql:23-42` (JOB_GRADES) | `GRADE_LEVEL` | no such column (`01_core_tables.sql:57-72`) |
| `data/seed/01_reference_data.sql:182-201` (SYSTEM_PARAMETERS) | `DESCRIPTION` | `PARAM_DESCRIPTION` (`schema/tables/04_performance_tables.sql:115`) |

**Issue:** 23 INSERT statements fail with ORA-00904. Everything that depends on them fails next: departments and jobs (FK to locations and grades), then all of `02_employee_data.sql`. The seed also sets `DEPARTMENTS.MANAGER_EMP_ID` for dept 30 twice (`02_employee_data.sql:166-167`).
**Impact:** Fresh environments (dev, test, DR rehearsal) cannot be built from the repo. This also explains why the trigger bugs above were never caught by tests.
**Recommendation:** Fix the column names, add a CI job that installs schema plus seed into an Oracle container (gvenzl/oracle-free) and fails on any error, and run `utPLSQL` there.

---

### DATA-05: The leave-status audit trigger violates `AUDIT_LOG`; failures are swallowed (HIGH)

**Files:** `plsql/triggers/trg_audit.sql:47-59`; `schema/tables/04_performance_tables.sql:96`, `:104`; `plsql/packages/PKG_AUDIT.pkb:27-30`
```sql
PKG_AUDIT.log_action(
    'LEAVE_REQUESTS',
    :NEW.REQUEST_ID,
    'STATUS_CHANGE',
```
**Issue:** `ACTION_TYPE` is `VARCHAR2(10)` with `CHECK (ACTION_TYPE IN ('INSERT','UPDATE','DELETE'))`. `'STATUS_CHANGE'` is 13 characters and is not in the list. `PKG_AUDIT.log_action` catches `WHEN OTHERS` and rolls back its autonomous transaction.
**Impact:** No leave approval, rejection or cancellation is ever audited by the trigger, and nothing reports it.
**Recommendation:** Use `'UPDATE'` with the status in the JSON payload, or widen the column and constraint. Make audit failures visible (ARCH-01).

---

### DATA-06: FICA and Medicare YTD includes the current period and unapproved runs (HIGH)

**File:** `plsql/packages/PKG_PAYROLL.pkb:405-414`, `:474`, `:488`, `:802-819`
```sql
INSERT INTO PAYROLL_DETAILS (...) VALUES (..., 1, 'EARNING', v_period_gross, 'CALCULATED', ...);
-- Get YTD gross for tax calculations
v_ytd_gross := get_ytd_earnings(p_emp_id, EXTRACT(YEAR FROM v_period_end));
...
WHERE pd.EMP_ID = p_emp_id
AND pd.ELEMENT_TYPE = 'EARNING'
AND pd.STATUS = 'CALCULATED'
AND EXTRACT(YEAR FROM pp.PERIOD_START_DATE) = p_tax_year;
```
**Issue:** The current period's earning is inserted before YTD is read, so it is counted twice. `get_ytd_earnings` has no `PAYROLL_RUNS.STATUS` filter, so PENDING, ERROR and re-run CALCULATED runs all add to YTD. It also takes the year from `PERIOD_START_DATE`, while the caller uses `PERIOD_END_DATE`, which differs for biweekly periods that cross a year boundary.
**Impact:** The Social Security wage-base cap and the Additional Medicare threshold trigger too early, so withholding is too low and tax filings are wrong.
**Recommendation:** Compute YTD from runs with status `APPROVED`/`PAID` only, read it before inserting the current period, and key it on pay date (constructive receipt).

---

### DATA-07: Cross-year leave uses inconsistent balance years (HIGH)

**File:** `plsql/packages/PKG_LEAVE.pkb:148`, `:176-182`, `:241-248`, `:296-302`, `:346-360`, `:369-387`
```sql
v_balance := get_leave_balance(p_emp_id, p_leave_type_id);   -- defaults to CURRENT year
...
UPDATE LEAVE_BALANCES
SET PENDING = PENDING + v_total_days
...
AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);         -- START-DATE year
```
**Issue:** The balance check uses the current year, while the reservation and deduction use the start-date year. A request spanning Dec 31 → Jan 1 charges every day to the old year. If no balance row exists for the start-date year, the `UPDATE` affects 0 rows and nothing is reserved, with no error.
**Impact:** Balances are wrong at year end, and requests submitted in December for next year can get around balance limits.
**Recommendation:** Split requests by calendar year, check and reserve against each year's row, and raise an error when `SQL%ROWCOUNT = 0`.

---

### DATA-08: `PENDING` is omitted from "available" in the view, carryover and reports (MEDIUM)

**Files:** `schema/views/hrms_views.sql:96` vs `schema/tables/03_leave_tables.sql:47`; `plsql/packages/PKG_LEAVE.pkb:567`, `:572`; `plsql/packages/PKG_REPORTING.pkb:134`
```sql
-- table virtual column
AVAILABLE NUMBER(6,2) GENERATED ALWAYS AS (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL,
-- VW_LEAVE_SUMMARY
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,
```
**Issue:** The view, `process_carryover` and `leave_utilization_report` all re-derive "available" without `- PENDING`, while the table and `get_leave_balance` (`PKG_LEAVE.pkb:376`) subtract it.
**Impact:** Managers see inflated availability, and year-end carryover counts days that are already pending.
**Recommendation:** Reference `lb.AVAILABLE` everywhere instead of re-deriving it. Decide explicitly whether pending days carry over.

---

### DATA-09: `promote_employee` applies `ROWNUM` before `ORDER BY` (MEDIUM)

**File:** `plsql/packages/PKG_EMPLOYEE.pkb:597-603`
```sql
SELECT BASE_SALARY INTO v_old_salary
FROM SALARY_RECORDS
WHERE EMP_ID = p_emp_id
AND ACTIVE_FLAG = 'Y'
AND ROWNUM = 1
ORDER BY EFFECTIVE_DATE DESC;
```
**Issue:** `ROWNUM = 1` is evaluated before the sort, so an arbitrary active row is used.
**Impact:** Wrong `CHANGE_PCT` on the new salary record and a wrong `OLD_SALARY` in history.
**Recommendation:** Call `PKG_PAYROLL.get_current_salary`, which correctly uses `FETCH FIRST 1 ROW ONLY` (`PKG_PAYROLL.pkb:63-81`).

---

### DATA-10: Carryover expiry removes used days too (MEDIUM)

**File:** `plsql/packages/PKG_LEAVE.pkb:605-623`
```sql
UPDATE LEAVE_BALANCES SET
    ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
    CARRYOVER_FROM_PREV = 0,
...
WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE)
AND CARRYOVER_FROM_PREV > 0;
```
**Issue:** As written, the `UPDATE` is idempotent, because a second run matches no rows; the "double-subtract" comment is out of date. The real defect is that it subtracts the **whole** carryover even when part of it was already used. The carryover is also posted twice in `process_carryover` (`:586-588`: both `CARRYOVER_FROM_PREV` and `OPENING_BALANCE` are set to `v_carryover`), and each re-run of `process_carryover` overwrites the next year's opening balance.
**Impact:** Balances can go negative after expiry, and re-running carryover discards any opening balance that was already set.
**Recommendation:** Expire only `GREATEST(0, CARRYOVER_FROM_PREV - used_from_carryover)`, track carryover consumption separately, and add a run log keyed by (year, job).

---

### DATA-11: Half-day requests are not modelled end to end (MEDIUM)

**Files:** `plsql/packages/PKG_LEAVE.pkb:45-62`, `:129-130`; `forms/xml-exports/HRMS_LEAVE.xml:152-160`; `plsql/packages/PKG_LEAVE.pks:9`
```sql
-- check_leave_overlap ignores HALF_DAY_FLAG / HALF_DAY_PERIOD
AND START_DATE <= p_end_date
AND END_DATE >= p_start_date;
```
**Issue:** The overlap check blocks an AM plus a PM half-day on the same date. The form never passes `p_half_day_period`, so half-day requests are stored with a NULL period. `p_half_day_flag = 'Y'` forces 0.5 days even for multi-day ranges.
**Impact:** Legitimate requests are rejected, the period data is incomplete, and multi-day ranges are under-counted.
**Recommendation:** Require a period when the flag is Y, enforce `START_DATE = END_DATE` for half days, and make the overlap check aware of periods.

---

### DATA-12: Observed holidays are not handled (MEDIUM)

**Files:** `plsql/packages/PKG_LEAVE.pkb:9-10`, `:25-29`; `schema/tables/03_leave_tables.sql:114-124`
```sql
-- BUG: Does not handle "observed" holidays (e.g., if July 4 falls on
-- Saturday, the observed Friday is not excluded)
```
**Issue:** `HOLIDAYS` has no observed-date column, and the lookup is an exact match.
**Impact:** The observed Friday or Monday is charged as a leave day.
**Recommendation:** Add `OBSERVED_DATE` (or seed the observed dates directly), and use it in every business-day function.

---

### DATA-13: Missing unique key makes review generation non-idempotent (MEDIUM)

**Files:** `plsql/packages/PKG_PERFORMANCE.pkb:289-317`; `schema/tables/04_performance_tables.sql:31-58`
```sql
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        NULL; -- Review already exists
```
**Issue:** `PERFORMANCE_REVIEWS` has no `UNIQUE (CYCLE_ID, EMP_ID)` constraint, so the handler can never fire.
**Impact:** Re-running `generate_reviews_for_cycle` creates duplicate reviews and duplicate notification emails, and skews `get_rating_distribution`.
**Recommendation:** Add `UNIQUE (CYCLE_ID, EMP_ID, REVIEW_TYPE)` after de-duplicating existing data.

---

### DATA-14: Views and reports pick salary rows and runs ambiguously (MEDIUM)

**Files:** `schema/views/hrms_views.sql:79`, `:121-125`; `plsql/packages/PKG_REPORTING.pkb:56`, `:117`; `plsql/packages/PKG_PAYROLL.pkb:35-42`
```sql
JOIN SALARY_RECORDS sr ON e.EMP_ID = sr.EMP_ID AND sr.ACTIVE_FLAG = 'Y'   -- no date filter
...
WHERE pr.RUN_ID = (SELECT MAX(pr2.RUN_ID) FROM PAYROLL_RUNS pr2 WHERE pr2.STATUS = 'APPROVED')
```
**Issue:** `create_salary_record` only end-dates rows with `EFFECTIVE_DATE < p_effective_date`, so a future-dated raise leaves two `ACTIVE_FLAG='Y'` rows. `VW_EMPLOYEE_COMPENSATION`, `compensation_summary` and `new_hires_report` then return duplicate rows. `VW_PAYROLL_LATEST` takes the single latest approved run across **all** run types and periods: after a BONUS run, every employee's "latest pay" is the bonus run.
**Impact:** Compensation and headcount reports are double counted, and payslip views are misleading.
**Recommendation:** Filter on the effective date range, as `VW_ACTIVE_EMPLOYEES` already does (`:33-35`). Pick the latest run per employee and run type with `ROW_NUMBER()`.

---

### DATA-15: Soft-delete and identity rules are applied inconsistently (MEDIUM)

**Files:** `plsql/packages/PKG_EMPLOYEE.pkb:690`, `:804-809`, `:851-857`; `schema/views/hrms_views.sql:54`, `:80`; `plsql/triggers/trg_employees.sql:42-54`; `schema/tables/01_core_tables.sql:109`; `plsql/packages/PKG_SECURITY.pkb:51-56`; `forms/xml-exports/HRMS_LOGIN.xml:86-90`
```sql
-- email uniqueness (trigger) only among ACTIVE_FLAG='Y'; no UNIQUE on EMAIL
WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL)
AND ACTIVE_FLAG = 'Y';
-- authenticate: TOO_MANY_ROWS -> MIN(EMP_ID); login form: ROWNUM = 1
```
**Issue:**
- "Active" is defined three ways: `EMPLOYMENT_STATUS`, `ACTIVE_FLAG`, or both, depending on the view or procedure.
- Email is the login identifier, but it is unique only among active rows, and only through a trigger.
- When duplicates exist, `authenticate` binds the session to `MIN(EMP_ID)` while the login form selects an arbitrary `ROWNUM = 1` row. The two can identify **different** employees.
- Point-in-time headcount (`get_headcount_by_dept`, `headcount_report`) filters `EMPLOYMENT_STATUS = 'ACTIVE'`, so historical as-of dates leave out people terminated since then.
- The `BEFORE INSERT` self-select also causes ORA-04091 (mutating table) for multi-row `INSERT ... SELECT`.

**Impact:** Wrong identity binding, inconsistent rosters, and wrong historical headcount.
**Recommendation:** Add a function-based unique index on `UPPER(EMAIL)` for active employees (or a separate login identifier). Define "active" once, in a view. Base as-of reports on hire and termination dates only.

---

### DATA-16: Documented payroll defects with no matching implementation (LOW)

**File:** `plsql/packages/PKG_PAYROLL.pks:11-12`
```sql
--   - Overtime calculation does not account for holidays correctly
--   - YTD accumulation resets incorrectly for mid-year hires in some edge cases
```
**Issue:** `PKG_PAYROLL.pkb` has no overtime or hours logic (`HOURS_WORKED`/`RATE` columns exist in `PAYROLL_DETAILS` but are never populated), and the mid-year hire YTD issue cannot be traced to any code. The real YTD defect is DATA-06.
**Recommendation:** Update the header. Track overtime as a missing feature for hourly (non-exempt, `FLSA_STATUS`) staff.

---

### DATA-17: Column widths too small for the values written (LOW)

**Files:** `schema/tables/04_performance_tables.sql:99`, `:156`; `plsql/packages/PKG_SECURITY.pkb:66-77`; `schema/tables/01_core_tables.sql:109`
```sql
USERNAME             VARCHAR2(30)    NOT NULL,   -- USER_SESSIONS
CHANGED_BY           VARCHAR2(30)    NOT NULL,   -- AUDIT_LOG
EMAIL                VARCHAR2(100),              -- EMPLOYEES (used as username)
```
**Issue:** `authenticate` writes the email (up to 100 characters) into 30-character columns. The longest seed email is 29 characters, so this is latent.
**Impact:** Any user with an email longer than 30 characters cannot log in (ORA-12899), and their audit row is silently dropped.
**Recommendation:** Widen to `VARCHAR2(100)`, or store `EMP_ID` instead of the email.

---

## 8. Severity Summary

| ID | Category | Description | Severity | Location | Recommended Fix |
|----|----------|-------------|----------|----------|-----------------|
| SEC-01 | Security | `authenticate` never checks password | CRITICAL | PKG_SECURITY.pkb:30-80 | Credential table + verify / SSO |
| SEC-02 | Security | Unsalted MD5 hashing | CRITICAL | PKG_SECURITY.pkb:14-24 | PBKDF2/bcrypt/Argon2 + salt |
| SEC-03 | Security | Hard-coded AES key, no IV | CRITICAL | PKG_SECURITY.pkb:6-7 | Rotate; Wallet/Vault; random IV |
| SEC-04 | Security | SQL injection in `search_employees` | CRITICAL | PKG_EMPLOYEE.pkb:465-483 | Bind variables |
| SEC-05 | Security | Server APIs lack authorization; grade-ID RBAC | HIGH | PKG_SECURITY.pkb:134-174 | Enforce in API; roles; maker-checker |
| SEC-06 | Security | Forms validate session with DB username | HIGH | HRMS_EMPLOYEE.xml:34 (+3 forms) | Use `check_session` |
| SEC-07 | Security | No lockout; timing enumeration | HIGH | PKG_SECURITY.pkb:46-56 | Lockout + uniform path |
| SEC-08 | Security | Cleartext password; no MFA | HIGH | HRMS_LOGIN.xml:10-13,75-79 | NNE/TLS; SSO+MFA |
| SEC-09 | Security | `change_password` stub logs success | MEDIUM | PKG_SECURITY.pkb:211-234 | Implement or remove |
| SEC-10 | Security | Absolute, hard-coded, uncommitted timeout | MEDIUM | PKG_SECURITY.pkb:8,113-121 | Sliding timeout from params |
| SEC-11 | Security | Hard-coded SMTP:25; header injection | MEDIUM | PKG_NOTIFICATION.pkb:7-10,96-101 | Params; STARTTLS; sanitise |
| SEC-12 | Security | Concatenated JSON in logs/audit | MEDIUM | PKG_COMMON.pkb:24-25,53-54 | `JSON_OBJECT` |
| SEC-13 | Security | PII in cleartext flat files | MEDIUM | PKG_INTEGRATION.pkb:98-131 | Encrypt; SFTP/API |
| SEC-14 | Security | `decrypt_ssn` swallows errors | LOW | PKG_SECURITY.pkb:203-205 | Log + re-raise |
| RACE-01 | Race | Emp number `MAX()+1` | HIGH | PKG_EMPLOYEE.pkb:37-55 | `SEQ_EMP_NUMBER` |
| RACE-02 | Race | Run creation without lock / dup guard | MEDIUM | PKG_PAYROLL.pkb:241-248 | `FOR UPDATE` + unique run |
| RACE-03 | Race | Promote/rehire without lock | MEDIUM | PKG_EMPLOYEE.pkb:592-614,750-793 | `FOR UPDATE NOWAIT` |
| RACE-04 | Race | Queue double-send | MEDIUM | PKG_NOTIFICATION.pkb:78-87 | `SKIP LOCKED` / AQ |
| RACE-05 | Race | Leave balance check not atomic | MEDIUM | PKG_LEAVE.pkb:141-182 | Lock balance row |
| PERF-01 | Performance | Per-day loop + per-day holiday query | MEDIUM | PKG_LEAVE.pkb:12-40 | Set-based calendar |
| PERF-02 | Performance | Per-day loops in PKG_COMMON | MEDIUM | PKG_COMMON.pkb:132-165 | Arithmetic / calendar table |
| PERF-03 | Performance | `CONNECT BY` hierarchy, no index | MEDIUM | hrms_views.sql:43-57 | Index; closure table |
| PERF-04 | Performance | SMTP connection per message | MEDIUM | PKG_NOTIFICATION.pkb:88-107 | Reuse connection |
| PERF-05 | Performance | Row-by-row payroll/accrual | MEDIUM | PKG_PAYROLL.pkb:295-327 | BULK/FORALL/set-based |
| PERF-06 | Performance | 28/29 sequences NOCACHE | LOW | hrms_sequences.sql | `CACHE 100+` |
| PERF-07 | Performance | POST-QUERY N+1 lookups | LOW | HRMS_EMPLOYEE.xml:345-368 | View-based blocks |
| PERF-08 | Performance | Reporting refresh is a placeholder | LOW | PKG_REPORTING.pkb:196-204 | MVs or remove |
| DRIFT-01 | Validation | Email rule differs across layers | HIGH | HRMS_VALIDATION_LIB:21-41 vs PKG_COMMON.pkb:265-268 | Single server rule + CHECK |
| DRIFT-02 | Validation | Hire-date limit 90/180/0/none | HIGH | HRMS_EMPLOYEE.xml:382-386 vs trg_employees.sql:34-38 | One parameterised rule |
| DRIFT-03 | Validation | Salary-grade check error→none | HIGH | PKG_EMPLOYEE.pkb:220-241 | Enforce in `create_salary_record` |
| DRIFT-04 | Validation | SSN/phone rules differ | MEDIUM | HRMS_VALIDATION_LIB:47-90 vs PKG_COMMON.pkb:270-280 | Unify (SSA rules) |
| DRIFT-05 | Validation | Date-range/business-day logic differ | MEDIUM | PKG_VALIDATION.pkb:6-15; PKG_COMMON.pkb:132-165 | One calendar package |
| DRIFT-06 | Validation | Params defined but code hard-codes | MEDIUM | 01_reference_data.sql:188-197 | Read via `get_param` |
| CIRC-01 | Circular Dep | Documented cycle absent; latent SECURITY↔EMPLOYEE | LOW | PKG_EMPLOYEE.pks:9; PKG_EMPLOYEE.pkb:738 | Fix docs; event-based revoke |
| ARCH-01 | Architecture | Autonomous TX + swallowed errors | HIGH | PKG_AUDIT.pkb:14,27-30 | Outbox; visible failures |
| ARCH-02 | Architecture | Hard-coded 2024 tax; HOH = 0 tax | HIGH | PKG_PAYROLL.pkb:7-14,602-718 | Effective-dated tax tables |
| ARCH-03 | Architecture | UTL_FILE integrations w/o controls | MEDIUM | PKG_INTEGRATION.pkb:27,99,162 | API/AQ; checksums |
| ARCH-04 | Architecture | Stubs that report success | MEDIUM | PKG_INTEGRATION.pkb:168-203 | Implement or raise |
| ARCH-05 | Architecture | Forms bypass API; delete vs soft-delete | MEDIUM | HRMS_EMPLOYEE.xml:323-334; trg_employees.sql:120-130 | API-based DML |
| ARCH-06 | Architecture | Hard-coded fiscal year | LOW | PKG_COMMON.pkb:170-195 | Parameter / calendar |
| ARCH-07 | Architecture | Package globals as session state | LOW | PKG_EMPLOYEE.pks:13-17 | App context |
| ARCH-08 | Architecture | Magic pay-element IDs | LOW | PKG_PAYROLL.pkb:409-495 | Look up by code |
| DATA-01 | Data Integrity | Trigger column mismatch → ORA-04098 on all updates | CRITICAL | trg_employees.sql:62-111 | Remove/rewrite trigger inserts |
| DATA-02 | Data Integrity | Payroll error row FK violation aborts run | CRITICAL | PKG_PAYROLL.pkb:311-319 | Error element / table; restartable |
| DATA-03 | Data Integrity | Trigger blocks rehire | HIGH | trg_employees.sql:71-74 | Allow API path |
| DATA-04 | Data Integrity | Seed uses non-existent columns | HIGH | 01_reference_data.sql:11-42,182-201 | Fix + CI install test |
| DATA-05 | Data Integrity | Leave audit violates AUDIT_LOG check | HIGH | trg_audit.sql:54 | Use `UPDATE` action |
| DATA-06 | Data Integrity | YTD double-counts / unapproved runs | HIGH | PKG_PAYROLL.pkb:405-414,808-816 | Approved-only, pre-insert YTD |
| DATA-07 | Data Integrity | Cross-year leave balance mismatch | HIGH | PKG_LEAVE.pkb:148,182 | Split by year; check rowcount |
| DATA-08 | Data Integrity | PENDING omitted from "available" | MEDIUM | hrms_views.sql:96 | Use `AVAILABLE` column |
| DATA-09 | Data Integrity | `ROWNUM` before `ORDER BY` | MEDIUM | PKG_EMPLOYEE.pkb:597-603 | `get_current_salary` |
| DATA-10 | Data Integrity | Carryover expiry removes used days | MEDIUM | PKG_LEAVE.pkb:605-623 | Expire unused only |
| DATA-11 | Data Integrity | Half-day not modelled | MEDIUM | PKG_LEAVE.pkb:45-62; HRMS_LEAVE.xml:152-160 | Period-aware logic |
| DATA-12 | Data Integrity | Observed holidays ignored | MEDIUM | PKG_LEAVE.pkb:9-10,25-29 | `OBSERVED_DATE` |
| DATA-13 | Data Integrity | No UK on reviews → duplicates | MEDIUM | 04_performance_tables.sql:31-58 | Add unique key |
| DATA-14 | Data Integrity | Ambiguous salary/run selection | MEDIUM | hrms_views.sql:79,121-125 | Date filters; per-type latest |
| DATA-15 | Data Integrity | Inconsistent soft-delete/identity | MEDIUM | trg_employees.sql:42-54; PKG_SECURITY.pkb:51-56 | Unique login id; one "active" def |
| DATA-16 | Data Integrity | Documented defects with no code | LOW | PKG_PAYROLL.pks:11-12 | Fix header; track overtime gap |
| DATA-17 | Data Integrity | 30-char username/audit columns | LOW | 04_performance_tables.sql:99,156 | Widen / store EMP_ID |

---

## 9. Prioritized Migration Roadmap

### Phase 1 — Critical security (weeks 1–2)

| # | Item | Effort | Risk if deferred |
|---|------|--------|------------------|
| 1 | SEC-01 / SEC-02: credential store + real password verification (or SSO) | 4 days | Anyone can log in as anyone |
| 2 | SEC-03: rotate AES key, move to Wallet/Vault, add random IV, re-encrypt PII | 3 days | Full SSN/bank data exposure |
| 3 | SEC-04: bind variables in `search_employees` | 0.5 day | Arbitrary data reads |
| 4 | SEC-05: server-side authorization + payroll maker-checker | 3 days | Unauthorised payroll approval |
| 5 | SEC-06 / SEC-07 / SEC-08: shared `check_session`, lockout, Native Network Encryption | 3 days | Broken session control; brute force; sniffing |

### Phase 2 — Data integrity (weeks 3–6)

| # | Item | Effort | Risk if deferred |
|---|------|--------|------------------|
| 1 | DATA-01 / DATA-03: fix or remove `TRG_EMP_BEFORE_UPDATE` inserts; allow rehire | 1 day | All employee updates fail |
| 2 | DATA-04: fix seed columns; add CI job that installs schema + seed on Oracle Free | 2 days | No reproducible environments; regressions undetected |
| 3 | DATA-02: payroll error handling + restartable runs | 2 days | Stuck payroll runs |
| 4 | DATA-06 / ARCH-02: correct YTD; effective-dated tax tables | 1–2 weeks | Wrong withholding |
| 5 | DATA-05 / ARCH-01: audit action fix; visible audit failures; outbox | 3 days | Missing audit trail |
| 6 | DATA-07 / DATA-08 / DATA-10 / DATA-11 / RACE-05: leave balance correctness | 1 week | Wrong balances |
| 7 | RACE-01 / RACE-02 / RACE-03 / RACE-04: sequences, locks, `SKIP LOCKED` | 2 days | Duplicates under load |
| 8 | DRIFT-01 / DRIFT-02 / DRIFT-03: single validation source + DB constraints | 1 week | Inconsistent data entry |
| 9 | DATA-13 / DATA-14 / DATA-15: unique keys, view fixes, identity uniqueness | 3 days | Duplicates; misreporting |

### Phase 3 — Performance (months 2–3)

| # | Item | Effort | Risk if deferred |
|---|------|--------|------------------|
| 1 | PERF-01 / PERF-02 / DRIFT-05 / DATA-12: calendar table + set-based business-day logic | 1 week | Slow leave flows; inconsistent counts |
| 2 | PERF-05: bulk payroll and accrual | 2 weeks | Batch windows grow with headcount |
| 3 | PERF-03: `MANAGER_EMP_ID` index + closure table | 3 days | Org-chart timeouts |
| 4 | PERF-04 / RACE-04: connection reuse or MTA/AQ | 2 days | Notification backlog |
| 5 | PERF-06 / PERF-07: sequence caching; view-based Forms blocks | 2 days | Contention; slow screens |

### Phase 4 — Modernization (months 3–12)

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 1 | Automated test harness | 1 month | utPLSQL suites per package, run in CI on Oracle Free; required before any refactor |
| 2 | API-first business layer | 2–3 months | Consolidate DML behind packages/REST (ORDS); remove trigger-duplicated logic (ARCH-05, CIRC-01) |
| 3 | Integration modernisation | 1–2 months | Replace UTL_FILE feeds with API/AQ; encrypted transport; finish stubs (ARCH-03, ARCH-04, SEC-13) |
| 4 | Configuration externalisation | 2 weeks | All hard-coded config from `SYSTEM_PARAMETERS`/Vault (DRIFT-06, ARCH-06, SEC-11) |
| 5 | UI migration off Oracle Forms | 3–6 months | APEX or a web/SPA frontend with SSO+MFA; retire PLL validation duplicates |
| 6 | Identity & session redesign | 1 month | OIDC tokens, application contexts instead of package globals (ARCH-07, SEC-10, DATA-15) |

---

## 10. Methodology & Verification

- **Static review** of every source file. Line numbers are per file and were checked against `main` with `grep -n` / `awk '{print FNR}'`.
- **Trigger and DML vs DDL cross-reference:** a script parsed every `INSERT INTO <table> (cols)` and `UPDATE <table> SET` in `plsql/`, `data/seed/` and `forms/`, and compared the column names with the `CREATE TABLE` definitions in `schema/tables/`. Mismatches found: `EMPLOYEE_HISTORY` (trigger), `LOCATIONS`, `JOB_GRADES`, `SYSTEM_PARAMETERS` (seed). There were no mismatches in package bodies.
- **Constraint cross-reference:** literal values written to `CHECK`-constrained columns (`AUDIT_LOG.ACTION_TYPE`, `EMPLOYEE_HISTORY.CHANGE_TYPE`) and FK targets (`PAYROLL_DETAILS.ELEMENT_ID` vs seeded `PAY_ELEMENTS`).
- **Dependency graph:** `grep -o 'PKG_[A-Z]*\.'` per package body.
- **Forms XML:** `xmllint --noout forms/xml-exports/*.xml` — all 6 files are well-formed.
- **Not available:** there is no Oracle instance in the analysis environment, so nothing was compiled or executed. Runtime consequences (ORA-04098, ORA-02291, ORA-00904, ORA-12899) are inferred from Oracle semantics and the DDL, not observed. `sqlfluff` was not installed in this environment. `DATA_DICTIONARY.md` does not exist; column semantics were taken from DDL `COMMENT ON` statements.
