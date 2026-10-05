# Technical Debt Report — Oracle Forms/PL/SQL HRMS Estate

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Baseline commit:** `1c33787` (Initial commit: Oracle Forms 11g/12c legacy HRMS codebase)
**Report date:** 2026-10-05
**Scope:** 11 PL/SQL packages (`plsql/packages/`, 4,170 body lines), 2 trigger scripts, 4 table DDL scripts, 1 view script, 1 sequence script, 2 PLL libraries, 6 Forms XML exports, 1 menu, seed data.

**Method:** Static review of every source file. Trigger and package DML column lists were cross-referenced against the table DDL; view definitions were compared against table virtual columns and the package logic they mirror; PLL validation was compared function-by-function with the server-side packages. No `DATA_DICTIONARY.md` exists in the repo, so the `COMMENT ON` statements in `schema/tables/` were used as the column documentation. No Oracle instance was available, so compile/runtime effects are inferred from the DDL and Oracle semantics, not observed.

---

## Executive Summary

The estate has **45 findings**: **5 CRITICAL**, **11 HIGH**, **17 MEDIUM**, **12 LOW**.

The most urgent issues:

1. **Authentication does not check the password** (SEC-03). `PKG_SECURITY.authenticate` accepts `p_password` and never uses it, so any active employee email logs in. The MD5 hashing (SEC-01) and hard-coded AES key (SEC-02) only matter once this is fixed.
2. **Every UPDATE on `EMPLOYEES` fails** (DATA-01). `TRG_EMP_BEFORE_UPDATE` inserts into six `EMPLOYEE_HISTORY` columns that do not exist in the DDL. The trigger compiles INVALID, and Oracle then raises ORA-04098 on every UPDATE of the table — transfers, promotions, terminations and Forms saves.
3. **SQL injection in employee search** (SEC-04). `PKG_EMPLOYEE.search_employees` concatenates five user-supplied parameters into dynamic SQL.
4. **Module forms check the wrong session ID** (SEC-07). Four forms pass `TO_NUMBER(GET_APPLICATION_PROPERTY(USERNAME))` (the DB connect user) to `is_session_valid` instead of `:GLOBAL.session_id`.
5. **Payroll is pinned to 2024** (ARCH-04). Federal brackets and the Social Security wage base are literals, so tax is wrong for every later year.

### Severity × Category

| Category | CRITICAL | HIGH | MEDIUM | LOW | Total |
|---|---:|---:|---:|---:|---:|
| 1. Security vulnerabilities | 4 | 4 | 4 | 2 | 14 |
| 2. Race conditions | 0 | 1 | 1 | 1 | 3 |
| 3. Performance | 0 | 0 | 5 | 2 | 7 |
| 4. Validation drift | 0 | 1 | 2 | 2 | 5 |
| 5. Circular dependencies | 0 | 0 | 0 | 1 | 1 |
| 6. Architectural anti-patterns | 0 | 2 | 2 | 3 | 7 |
| 7. Data integrity | 1 | 3 | 3 | 1 | 8 |
| **Total** | **5** | **11** | **17** | **12** | **45** |

### Changes from the previous report

- **New CRITICAL:** SEC-03 now covers the unused `p_password` (authentication bypass), not just cleartext transmission. SEC-04 (SQL injection in `search_employees`) was missing before.
- **New HIGH:** SEC-07 (wrong session ID in forms), SEC-08 (`change_password` stub), DATA-02 (`CHANGE_TYPE` values rejected by `CHK_CHANGE_TYPE`, plus duplicate history rows), DATA-04 (email uniqueness the comment claims but no constraint enforces), ARCH-04 (2024 tax constants).
- **Corrected:** CIRC-01. The `PKG_EMPLOYEE ↔ PKG_PAYROLL` cycle exists only in comments: `PKG_PAYROLL.pkb` never references `PKG_EMPLOYEE`, and the package graph has no cycles. DRIFT-01: the PLL comment says the client rejects subdomain emails, but it actually accepts them. The real drift is that the client is *more permissive* than the server. DATA-06: `expire_carryover` cannot double-subtract (it zeroes `CARRYOVER_FROM_PREV`); the real bug is that it can drive balances negative.
- **Dropped:** "No MFA" (feature gap, not code debt). Cross-year, half-day, holiday-observed and overtime findings were dropped because this revision's code could not be traced to specific lines for them.

---

## 1. Security Vulnerabilities

### SEC-01: MD5 password hashing (CRITICAL)
**Location:** `plsql/packages/PKG_SECURITY.pkb:14-24`
```sql
FUNCTION hash_password(p_password IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
    RETURN RAWTOHEX(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(p_password), DBMS_CRYPTO.HASH_MD5));
END hash_password;
```
**Issue:** Unsalted MD5. MD5 is broken and fast enough to brute-force at GPU speed, and the lack of a salt makes rainbow tables effective.
**Impact:** If credential hashes leak, they can be recovered almost immediately.
**Recommendation:** Use a per-user random salt with PBKDF2, bcrypt or Argon2 (outside the DB if needed), or at minimum `DBMS_CRYPTO.HASH_SH512` with a salt and iterations. Re-hash on next successful login.

### SEC-02: Hard-coded AES-256 encryption key (CRITICAL)
**Location:** `plsql/packages/PKG_SECURITY.pkb:7`, used at `:184-188` and `:197-201`
```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```
**Issue:** The SSN encryption key is in source control. It is not even declared `CONSTANT`. CBC mode is used without an IV, so identical SSNs give identical ciphertext.
**Impact:** Anyone with repo or `DBA_SOURCE` access can decrypt every `SSN_ENCRYPTED` value.
**Recommendation:** Move the key to Oracle Wallet/TDE or an external KMS. Use a random IV per value. Rotate the key and re-encrypt.

### SEC-03: Authentication never verifies the password (CRITICAL)
**Location:** `plsql/packages/PKG_SECURITY.pkb:30-80`; caller `forms/xml-exports/HRMS_LOGIN.xml:75-79`
```sql
FUNCTION authenticate(p_username IN VARCHAR2, p_password IN VARCHAR2, ...) RETURN NUMBER IS
    v_stored_hash VARCHAR2(200);   -- declared, never assigned
    v_input_hash  VARCHAR2(200);   -- declared, never assigned
BEGIN
    SELECT EMP_ID INTO v_emp_id FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
    ...
    INSERT INTO USER_SESSIONS (...) VALUES (v_session_id, v_emp_id, p_username, SYSDATE, ...);
```
**Issue:** `p_password` is never referenced. The function creates a session for any active employee's email. The password also travels as a cleartext PL/SQL argument from the login form.
**Impact:** Full authentication bypass. Knowing a colleague's email is enough to act as them, including grade ≥ 8 executives, who `has_permission` grants full access.
**Recommendation:** Add a `USER_CREDENTIALS` table (salted hash, failure count, lock timestamp). Compare hashes in constant time. Better still, delegate to SSO/LDAP (see Phase 4).

### SEC-04: SQL injection in `search_employees` (CRITICAL)
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:465-498`
```sql
v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
v_sql := v_sql || 'AND e.DEPT_ID = ' || p_dept_id || ' ';
v_sql := v_sql || 'AND e.EMPLOYMENT_STATUS = ''' || p_status || ''' ';
v_sql := v_sql || 'AND e.LOCATION_CODE = ''' || p_location_code || ''' ';
...
OPEN p_cursor FOR v_sql;
```
**Issue:** `p_last_name`, `p_first_name`, `p_status` and `p_location_code` are spliced into SQL text unescaped. `p_dept_id` is spliced in via implicit conversion.
**Impact:** Input like `' UNION SELECT ... FROM USER_SESSIONS --` exfiltrates any table the `HRMS` schema can read. Every distinct search string also hard-parses, flooding the shared pool.
**Recommendation:** Build the predicate with bind placeholders and `OPEN p_cursor FOR v_sql USING ...`, or use the `(:p IS NULL OR col = :p)` static-SQL pattern. Validate with `DBMS_ASSERT` where dynamic identifiers are unavoidable.

### SEC-05: No brute-force protection or account lockout (HIGH)
**Location:** `plsql/packages/PKG_SECURITY.pkb:28-50`
```sql
-- VULNERABILITY: No brute-force protection (no lockout after N failures)
```
**Issue:** Failed attempts are not counted, delayed or logged (only successful sessions are audited, at `:77`).
**Impact:** Unlimited online guessing once SEC-03 is fixed, with no detection trail.
**Recommendation:** Track failures per account and per IP. Lock after N failures with a timed unlock. Audit failures through `PKG_AUDIT`.

### SEC-06: Username enumeration and duplicate-email login ambiguity (HIGH)
**Location:** `plsql/packages/PKG_SECURITY.pkb:46-57`
```sql
WHEN NO_DATA_FOUND THEN
    -- VULNERABILITY: Timing attack - different response time for invalid user vs invalid password
    RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
WHEN TOO_MANY_ROWS THEN
    SELECT MIN(EMP_ID) INTO v_emp_id FROM EMPLOYEES WHERE UPPER(EMAIL) = UPPER(p_username) ...
```
**Issue:** Unknown users fail fast while known users take the session-creation path, so response time reveals valid accounts. Because `EMAIL` has no unique constraint (DATA-04), one login can map to several employees, and the lowest `EMP_ID` silently wins.
**Impact:** Account enumeration, and possible login as the wrong person.
**Recommendation:** Run the same work for unknown users (dummy hash compare). Enforce unique login identifiers (DATA-04).

### SEC-07: Module forms validate the DB username instead of the session ID (HIGH)
**Location:** `forms/xml-exports/HRMS_EMPLOYEE.xml:34-35`, `HRMS_PAYROLL.xml:27-28`, `HRMS_LEAVE.xml:25-26`, `HRMS_PERFORMANCE.xml:23-24`
```sql
v_session_id := TO_NUMBER(GET_APPLICATION_PROPERTY(USERNAME));
IF NOT PKG_SECURITY.is_session_valid(v_session_id) THEN
```
**Issue:** `HRMS_LOGIN.xml:82` stores the real session in `:GLOBAL.session_id`, and `HRMS_COMMON_LIB.check_session` (`forms/libraries/HRMS_COMMON_LIB.pll.sql:127-134`) uses it. The four module forms instead pass the Oracle connect username through `TO_NUMBER`.
**Impact:** For a non-numeric DB user, `WHEN-NEW-FORM-INSTANCE` raises ORA-06502 and the form won't open. For a numeric one, the check validates an arbitrary `USER_SESSIONS` row. Either way the session check is not doing its job.
**Recommendation:** Replace the four blocks with `HRMS_COMMON_LIB.check_session`.

### SEC-08: `change_password` is a stub that reports success (HIGH)
**Location:** `plsql/packages/PKG_SECURITY.pkb:211-234`
```sql
-- NOTE: Actual password update would go to USER_CREDENTIALS table
-- This is a stub for the legacy system model
PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
```
**Issue:** `p_old_password` is never verified and nothing is persisted, yet an `UPDATE` audit row is written. The complexity rules (length ≥ 8, one uppercase, one digit) also leave out lowercase/symbol, history and reuse checks.
**Impact:** Users believe they rotated their password. Audit shows a credential change that never happened.
**Recommendation:** Implement this together with SEC-03, verifying the old hash. Remove the audit write until the update is real.

### SEC-09: Coarse, ownership-blind authorization (MEDIUM)
**Location:** `plsql/packages/PKG_SECURITY.pkb:134-174`
```sql
IF v_grade_id >= 8 THEN RETURN TRUE; END IF;                 -- full access
IF p_action = 'VIEW' AND v_grade_id >= 5 THEN RETURN TRUE; END IF;
IF p_module = 'LEAVE' AND p_action IN ('CREATE','VIEW') THEN RETURN TRUE; END IF;   -- "own leave"
IF p_module = 'EMPLOYEE' AND p_action = 'VIEW' THEN RETURN TRUE; END IF;           -- "own profile"
```
**Issue:** The comments say "own records", but no record owner is passed in or checked. Any employee gets `EMPLOYEE/VIEW` for every employee. Grade ≥ 5 can view payroll. Permissions depend on a `GRADE_ID` surrogate value, not a role.
**Impact:** Wider exposure of PII and compensation data than the comments describe.
**Recommendation:** Add `ROLES`/`PERMISSIONS` tables and pass the target record into the check (or use VPD/RLS policies).

### SEC-10: Hard-coded SMTP endpoint over cleartext port 25; header injection (MEDIUM)
**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:7-10`, `:96-101`; duplicate config at `data/seed/01_reference_data.sql:195`
```sql
c_smtp_host CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port CONSTANT NUMBER := 25;
...
UTL_SMTP.WRITE_DATA(v_connection, 'Subject: ' || notif_rec.SUBJECT || UTL_TCP.CRLF);
```
**Issue:** `SYSTEM_PARAMETERS.SMTP_HOST` is seeded but ignored. There is no STARTTLS or auth. `SUBJECT` and `RECIPIENT_EMAIL` go into headers without stripping CR/LF.
**Impact:** Environment changes need a code deploy. Mail contents, including leave-rejection reasons, travel in cleartext. Crafted subjects can inject headers.
**Recommendation:** Read host/port from `PKG_COMMON.get_param`. Use `UTL_SMTP.STARTTLS` with a wallet. Strip CR/LF from header values.

### SEC-11: FTP credentials stored in cleartext (MEDIUM)
**Location:** `plsql/packages/PKG_INTEGRATION.pks:12`
```sql
--   - FTP credentials stored in SYSTEM_PARAMETERS table (cleartext)
```
**Issue:** The package spec documents that integration credentials sit as plain values in `SYSTEM_PARAMETERS`. Anyone who can read the parameter table can read them.
**Impact:** Credentials leak to anyone with read access; no rotation story.
**Recommendation:** Move the credentials to Oracle Wallet or a secrets manager, and replace FTP with SFTP/HTTPS (ARCH-02).

### SEC-12: SSN encryption is unused, and decrypt failures are masked (MEDIUM)
**Location:** `plsql/packages/PKG_SECURITY.pkb:179-206`; column doc `schema/tables/01_core_tables.sql:146`
```sql
COMMENT ON COLUMN HRMS.EMPLOYEES.SSN_ENCRYPTED IS 'AES-256 encrypted SSN - decrypted only in PKG_SECURITY';
...
EXCEPTION WHEN OTHERS THEN RETURN '***DECRYPT_ERROR***';
```
**Issue:** Nothing in the codebase calls `encrypt_ssn` or `decrypt_ssn`, and no code writes `SSN_ENCRYPTED`. The column comment describes behaviour that doesn't exist. `decrypt_ssn` turns key/corruption errors into a string that looks like valid data.
**Impact:** If SSNs are loaded by some external path, nothing guarantees they are encrypted. Key-rotation failures go unnoticed.
**Recommendation:** Route every SSN write through `encrypt_ssn` (or use TDE column encryption), let decrypt errors raise, and fix the column comment.

### SEC-13: JSON built by string concatenation (LOW)
**Location:** `plsql/packages/PKG_COMMON.pkb:53-54`; `plsql/triggers/trg_audit.sql:20-29`, `:56-57`
```sql
'","message":"' || SUBSTR(p_message, 1, 3000) || '"}'          -- log_info: no escaping
v_new_json := '{"emp_id":' || :NEW.EMP_ID || ',"salary":' || :NEW.BASE_SALARY || ...
```
**Issue:** `log_info` doesn't escape quotes or backslashes (`log_error` at `:25` escapes only `"`). NULL numbers produce invalid JSON (`"salary":}`).
**Impact:** Malformed `AUDIT_LOG.NEW_VALUES` breaks downstream JSON parsing and lets callers forge audit keys.
**Recommendation:** Use `JSON_OBJECT(...)` (12.2+) or `JSON_OBJECT_T`.

### SEC-14: Session timeout is absolute, not idle-based (LOW)
**Location:** `plsql/packages/PKG_SECURITY.pkb:114`
```sql
IF (SYSDATE - v_login_time) * 24 * 60 > c_session_timeout_min THEN
```
**Issue:** The timeout is measured from `LOGIN_TIME`, with no last-activity column. Active users are logged out after 30 minutes, and the hard-coded constant ignores `SYSTEM_PARAMETERS`.
**Impact:** Active users get logged out mid-work; tuning the timeout needs a code change.
**Recommendation:** Add `LAST_ACTIVITY_TIME` and refresh it on each validation. Read the timeout from parameters.

---

## 2. Race Conditions

### RACE-01: Employee number via `MAX()+1` (HIGH)
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:39-55`; unused sequence `schema/sequences/hrms_sequences.sql:19-21`
```sql
SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1 INTO v_max_num
FROM EMPLOYEES WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
...
EXCEPTION WHEN OTHERS THEN
    RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMPLOYEE.NEXTVAL, 6, '0');
```
**Issue:** Two concurrent hires read the same MAX, and the second hits `UK_EMP_NUMBER`. The `WHEN OTHERS` fallback draws from `SEQ_EMPLOYEE` (starts at 10000, the surrogate-key sequence), which collides with the MAX-based series once it reaches 10000. `SEQ_EMP_NUMBER`, created for this purpose, is never used. The query also full-scans `EMPLOYEES`.
**Impact:** Intermittent hire failures under load, and inconsistent numbering.
**Recommendation:** `LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0')` (or an identity column). Delete the MAX path and the fallback.

### RACE-02: Payroll run created without locking the period (MEDIUM)
**Location:** `plsql/packages/PKG_PAYROLL.pkb:241-260` (compare `close_pay_period` at `:193-196`, which does lock)
```sql
SELECT STATUS INTO v_status FROM PAY_PERIODS WHERE PERIOD_ID = p_period_id;   -- no FOR UPDATE
IF v_status = 'CLOSED' THEN RAISE_APPLICATION_ERROR(...); END IF;
INSERT INTO PAYROLL_RUNS (...) VALUES (v_run_id, p_period_id, p_run_type, ...);
```
**Issue:** A concurrent `close_period` can commit between the check and the INSERT. Nothing prevents two `REGULAR` runs for the same period.
**Impact:** Runs attached to closed periods, or duplicate regular runs (double pay if both are approved).
**Recommendation:** `SELECT ... FOR UPDATE` on the period, plus a unique index on `(PERIOD_ID, RUN_TYPE)` filtered to non-cancelled runs.

### RACE-03: `adjust_balance` update-then-initialize retry (LOW)
**Location:** `plsql/packages/PKG_LEAVE.pkb:400-419`
```sql
UPDATE LEAVE_BALANCES SET ADJUSTMENT = ADJUSTMENT + p_adjustment ... ;
IF SQL%ROWCOUNT = 0 THEN
    initialize_balances(p_emp_id, EXTRACT(YEAR FROM SYSDATE), p_user);
    UPDATE LEAVE_BALANCES SET ...;    -- retry
```
**Issue:** Two sessions can both see 0 rows and both initialize, and the second gets `UK_LEAVE_BAL` (ORA-00001). The year is always the current calendar year, so a December adjustment to next year's balance is impossible.
**Impact:** Sporadic ORA-00001 on concurrent adjustments; future-year balances can't be adjusted.
**Recommendation:** Use `MERGE` keyed on `UK_LEAVE_BAL` and take the year as a parameter.

---

## 3. Performance Issues

### PERF-01: Day-by-day loop in `business_days_between` (MEDIUM)
**Location:** `plsql/packages/PKG_COMMON.pkb:132-146`
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT','SUN') THEN v_count := v_count + 1; END IF;
    v_date := v_date + 1;
END LOOP;
```
**Issue:** O(days) loop with a `TO_CHAR` per day. It also ignores `HOLIDAYS`, unlike `PKG_LEAVE.calculate_business_days`, so the two give different answers for the same dates.
**Impact:** Slow when called per row over long ranges, and inconsistent with the leave calculation.
**Recommendation:** Use the closed-form week arithmetic plus a single `COUNT(*)` against `HOLIDAYS`, and keep one implementation.

### PERF-02: Day-by-day loop in `add_business_days` (MEDIUM)
**Location:** `plsql/packages/PKG_COMMON.pkb:151-165`
```sql
WHILE v_added < p_days LOOP
    v_result := v_result + 1;
    IF TO_CHAR(v_result, 'DY', ...) NOT IN ('SAT','SUN') THEN v_added := v_added + 1; END IF;
END LOOP;
```
**Issue:** O(days) loop that ignores holidays. Negative `p_days` silently returns the start date.
**Impact:** Slow for large offsets and wrong around holidays or for backward offsets.
**Recommendation:** Same closed-form approach. Support negative offsets.

### PERF-03: Per-day `HOLIDAYS` query in leave calculation (MEDIUM)
**Location:** `plsql/packages/PKG_LEAVE.pkb:12-40`
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', ...) NOT IN ('SAT','SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count FROM HOLIDAYS WHERE HOLIDAY_DATE = v_date ...;
```
**Issue:** One SQL round-trip (and context switch) per weekday in the range.
**Impact:** A 3-month sabbatical costs about 65 queries per validation. Batch accrual and reporting multiply that.
**Recommendation:** Generate the date range with a row-generator CTE and anti-join `HOLIDAYS` in one statement.

### PERF-04: `CONNECT BY` hierarchies (MEDIUM)
**Location:** `schema/views/hrms_views.sql:47-57`; `plsql/packages/PKG_EMPLOYEE.pkb:828-837`
```sql
-- WARNING: Performance degrades significantly with >500 employees
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
ORDER SIBLINGS BY LAST_NAME;
```
**Issue:** The view rebuilds the full tree with `SYS_CONNECT_BY_PATH` on every query. The `WHERE EMPLOYMENT_STATUS = 'ACTIVE'` filter runs *after* the hierarchy is built, so active reports of a terminated manager stay in the tree under a missing node. No `NOCYCLE` guard exists.
**Impact:** Slow org-chart LOVs, and misleading paths after terminations.
**Recommendation:** Use a recursive CTE with `CYCLE` detection, put the status filter in the recursive member, and index `MANAGER_EMP_ID`. For reporting, consider a materialized closure table.

### PERF-05: New SMTP connection per notification (MEDIUM)
**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:90-107`, `:117-126`
```sql
FOR notif_rec IN (... FETCH FIRST p_batch_size ROWS ONLY) LOOP
    v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
    UTL_SMTP.HELO(...); ... UTL_SMTP.QUIT(v_connection);
```
**Issue:** TCP connect + HELO for each of up to 50 messages. The exception handler never calls `QUIT`/`CLOSE_CONNECTION`, so connections leak on failure. The queue isn't locked (`FOR UPDATE SKIP LOCKED`), so overlapping scheduler runs send duplicates.
**Impact:** Slow batches, leaked sockets, and duplicate emails when runs overlap.
**Recommendation:** Open one connection per batch and send multiple `MAIL/RCPT/DATA` transactions on it. Close it in the handler. Claim rows with `SKIP LOCKED`.

### PERF-06: NOCACHE sequences (LOW)
**Location:** `schema/sequences/hrms_sequences.sql:9-49` (28 of 29 sequences; only `SEQ_AUDIT` at `:45` uses `CACHE 100`)
```sql
CREATE SEQUENCE HRMS.SEQ_PAYROLL_DETAIL START WITH 1 INCREMENT BY 1 NOCACHE;
```
**Issue:** Every `NEXTVAL` updates `SEQ$` in the data dictionary. `SEQ_PAYROLL_DETAIL` has 7 call sites in `PKG_PAYROLL` (typically 5+ per employee per run), and `SEQ_NOTIFICATION` once per message.
**Impact:** Row-cache contention during payroll runs and other bulk operations.
**Recommendation:** `CACHE 100` or higher for high-volume sequences. Gapless numbering isn't a real requirement here; `SEQ_EMP_NUMBER`'s comment confirms gaps already exist.

### PERF-07: Reporting refresh is a placeholder (LOW)
**Location:** `plsql/packages/PKG_REPORTING.pkb:200`
```sql
-- Placeholder for nightly refresh of denormalized reporting tables
```
**Issue:** The scheduled refresh does nothing, so any denormalized reporting tables never refresh.
**Impact:** Reports may show stale data with no signal that it is stale.
**Recommendation:** Implement it as materialized views with `REFRESH FAST ON COMMIT`/scheduled complete refresh, or remove the job.

---

## 4. Validation Drift (PLL vs Server)

### DRIFT-01: Email validation — client is more permissive than server (HIGH)
**Client:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41`
```sql
v_at_pos := INSTR(p_email, '@');
IF v_at_pos = 0 OR v_at_pos = 1 OR v_at_pos = LENGTH(p_email) THEN RETURN FALSE; END IF;
v_dot_pos := INSTR(p_email, '.', v_at_pos);
IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN RETURN FALSE; END IF;
-- BUG: Only checks for one dot after @, rejects valid subdomains
RETURN TRUE;
```
**Server:** `plsql/packages/PKG_COMMON.pkb:265-268` (wrapped by `PKG_VALIDATION.validate_email_format`, `PKG_VALIDATION.pkb:50-55`)
```sql
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```
**Issue:** The in-code comment is wrong. `user@mail.company.com` *passes* the PLL check, because `INSTR` finds the first dot. The PLL check does accept addresses the server rejects:

| Input | PLL | Server |
|---|---|---|
| `a@b.c` (1-char TLD) | TRUE | FALSE |
| `a b@corp.com` (space) | TRUE | FALSE |
| `a@b@corp.com` | TRUE | FALSE |
| `a@corp.com.` (trailing dot) | TRUE | FALSE |
| `NULL` | TRUE | NULL (falsy) |

`HRMS_EMPLOYEE.xml:375-380` calls the server function directly, so the PLL routine either feeds other forms or is dead code. The comment misleads maintainers either way.
**Impact:** Forms that use the PLL routine accept emails the server later rejects, and the error surfaces at commit time instead of at the field.
**Recommendation:** Delete the PLL copy and call `PKG_VALIDATION.validate_email_format` everywhere. Fix the comment.

### DRIFT-02: SSN validation rules differ (MEDIUM)
**Client:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:69-90` · **Server:** `plsql/packages/PKG_COMMON.pkb:277-280`
```sql
-- PLL: strips only '-', then rejects 000-xx-xxxx, xxx-00-xxxx, xxx-xx-0000
v_digits := TRANSLATE(p_ssn, '0123456789-', '0123456789');
-- Server: strips all non-digits, accepts any 9 digits
RETURN REGEXP_LIKE(REGEXP_REPLACE(p_ssn, '[^0-9]', ''), '^\d{9}$');
```
**Issue:** The server accepts `000-00-0000`, which the client rejects. The client rejects `123 45 6789` (spaces are kept), which the server accepts. Neither rejects the SSA-invalid `666` or `9xx` area numbers.
**Impact:** Batch loads that skip Forms can store invalid SSNs, while legitimate formats are rejected in the UI.
**Recommendation:** Keep one server-side rule set covering SSA rules, and have the PLL call it.

### DRIFT-03: Phone normalization differs (LOW)
**Client:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:47-63` · **Server:** `plsql/packages/PKG_COMMON.pkb:270-275`
```sql
v_digits := TRANSLATE(p_phone, '0123456789()-. +x', '0123456789');   -- PLL: other letters survive
v_digits := REGEXP_REPLACE(p_phone, '[^0-9]', '');                    -- server: all non-digits removed
```
**Issue:** `555-123-4567 ext1` fails in the PLL (it keeps `e` and `t`) but passes on the server (11 digits). The server also accepts any 11-digit number, not just ones with a leading `1`, which `format_phone` (`PKG_COMMON.pkb:209`) requires.
**Impact:** The same phone number can pass one layer and fail the other, so users see inconsistent errors.
**Recommendation:** Use one server function, and align `is_valid_phone` with `format_phone`.

### DRIFT-04: Salary-range enforcement is inconsistent (MEDIUM)
**Client:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:101-135` · **Server:** `plsql/packages/PKG_VALIDATION.pkb:17-48`, `plsql/packages/PKG_EMPLOYEE.pkb:231-239`
```sql
-- PLL comment: "Uses a hard-coded cache ... never refreshed"   (code actually queries JOB_GRADES live)
IF p_salary IS NULL OR p_grade_id IS NULL THEN RETURN NULL; END IF;            -- PLL: NULL = valid
IF p_salary IS NULL OR p_grade_id IS NULL THEN RETURN 'Salary and grade are required'; END IF;  -- server
-- PKG_EMPLOYEE.create_employee: out-of-range only prints DBMS_OUTPUT when g_debug_mode
```
**Issue:** The two layers treat NULL differently, the PLL comment describes caching the code doesn't do, and the hire path in `PKG_EMPLOYEE` treats out-of-range salaries as a debug-only message. No server-side check enforces the grade range.
**Impact:** Salaries outside the grade range can be saved with no recorded approval.
**Recommendation:** Enforce `validate_salary_for_grade` in `create_employee` and `create_salary_record`, with an explicit override flag and approver that get audited.

### DRIFT-05: Date rules differ by layer (LOW)
**Locations:** `plsql/packages/PKG_VALIDATION.pkb:6-15`, `:71-76`; `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:96-99`; `forms/xml-exports/HRMS_EMPLOYEE.xml:382-385`
```sql
IF p_start_date IS NULL OR p_end_date IS NULL THEN RETURN FALSE; END IF;      -- server: NULL invalid
RETURN p_date IS NULL OR TRUNC(p_date) <= TRUNC(SYSDATE);                     -- PLL: NULL valid
IF :EMPLOYEE.HIRE_DATE > SYSDATE + 90 THEN ...                                -- form: +90 days allowed
```
**Issue:** NULL handling is inverted between layers. The form allows hire dates up to 90 days ahead, but no server rule enforces that bound.
**Impact:** Direct API or batch callers can store hire dates years in the future.
**Recommendation:** Add a server-side hire-date rule and make NULL semantics explicit per field.

---

## 5. Circular Dependencies

### CIRC-01: Documented `PKG_EMPLOYEE ↔ PKG_PAYROLL` cycle is stale (LOW)
**Location:** `plsql/packages/PKG_EMPLOYEE.pks:9`, `plsql/packages/PKG_PAYROLL.pks:9`, `plsql/packages/PKG_EMPLOYEE.pkb:273-275`
```sql
-- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
-- which in turn may call PKG_EMPLOYEE.is_active for validation
PKG_PAYROLL.create_salary_record(
```
**Issue:** Both specs and the body comment describe a cycle, but `PKG_PAYROLL.pkb` never references `PKG_EMPLOYEE`. The actual body-level dependency graph has no cycles:

```
PKG_SECURITY     -> PKG_EMPLOYEE, PKG_AUDIT
PKG_EMPLOYEE     -> PKG_PAYROLL, PKG_NOTIFICATION, PKG_AUDIT, PKG_COMMON
PKG_LEAVE        -> PKG_NOTIFICATION, PKG_AUDIT
PKG_PERFORMANCE  -> PKG_NOTIFICATION, PKG_AUDIT
PKG_PAYROLL      -> PKG_AUDIT, PKG_COMMON
PKG_NOTIFICATION -> PKG_COMMON
PKG_INTEGRATION | PKG_REPORTING | PKG_VALIDATION -> PKG_COMMON
PKG_AUDIT, PKG_COMMON -> (none)
```
The remaining coupling risks: `PKG_SECURITY` depends on the business package `PKG_EMPLOYEE` (`PKG_SECURITY.pkb:75`), and the `PKG_EMPLOYEE.terminate_employee` TODOs (`PKG_EMPLOYEE.pkb:737-739`) plan calls into `PKG_SECURITY` and `PKG_PAYROLL`. Implementing them as written would create real `PKG_EMPLOYEE ↔ PKG_SECURITY` and (via the planned `is_active` check) `PKG_EMPLOYEE ↔ PKG_PAYROLL` cycles.
**Impact:** Misleading documentation now, and a likely ORA-04068/compile-order cycle if the TODOs are implemented as written.
**Recommendation:** Fix the comments. Move `set_session_context` into a small `PKG_CONTEXT`. Implement termination side effects as events or a coordinating package, not cross-calls.

---

## 6. Architectural Anti-Patterns

### ARCH-01: Autonomous transactions for business-relevant writes (MEDIUM)
**Locations:** `plsql/packages/PKG_AUDIT.pkb:14`, `plsql/packages/PKG_COMMON.pkb:16`, `:46`, `plsql/packages/PKG_NOTIFICATION.pkb:27`, `plsql/packages/PKG_EMPLOYEE.pkb:155`
```sql
PROCEDURE log_history(...) IS
    PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
    INSERT INTO EMPLOYEE_HISTORY (...); COMMIT;
EXCEPTION WHEN OTHERS THEN ROLLBACK;   -- swallowed
```
**Issue:** `EMPLOYEE_HISTORY` rows and queued notifications (welcome emails, manager alerts at `PKG_EMPLOYEE.pkb:310-321`) commit even when the hire or transfer that produced them rolls back. The audit trigger rows also commit independently of the DML they describe.
**Impact:** History for events that never happened, and emails about phantom hires. Audit insert failures are silently dropped (`PKG_AUDIT.pkb:27-30`).
**Recommendation:** Keep autonomous transactions for error logging only. Write history and notifications in the caller's transaction, or enqueue through Oracle AQ/Transactional Event Queues so delivery happens only after commit.

### ARCH-02: `UTL_FILE` flat-file integrations (MEDIUM)
**Locations:** `plsql/packages/PKG_INTEGRATION.pkb:7-9`, `:24-27`, `:98-99`, `:162`; `plsql/packages/PKG_PAYROLL.pkb:839-842`
```sql
v_filename := 'BENEFITS_' || TO_CHAR(SYSDATE, 'YYYYMMDD') || '.txt';
v_file := UTL_FILE.FOPEN(c_benefits_output_dir, v_filename, 'W', 32767);
```
**Issue:** GL, benefits (ADP fixed-width) and payroll-register feeds are server-side files with no checksum, no write-temp-then-rename step, and no delivery acknowledgement. Re-running the benefits feed on the same day overwrites the file. `RPAD` truncates silently (e.g. 30-char names).
**Impact:** Consumers can pick up partial files, and data is lost silently with no audit of what was sent.
**Recommendation:** Write to a temp name and rename on completion, add trailer checksums, and record each export in a manifest table. Long term, move to REST/AQ (Phase 4).

### ARCH-03: Stub implementations that report success (HIGH)
**Locations:** `plsql/packages/PKG_INTEGRATION.pkb:168-171`, `:196-203`; `plsql/packages/PKG_EMPLOYEE.pkb:737-739`; `plsql/packages/PKG_SECURITY.pkb:230-233`
```sql
-- Parse CSV: emp_number,date,hours_regular,hours_overtime
-- TODO: Implement actual parsing and database update
v_imported := v_imported + 1;
...
PKG_COMMON.log_info('PKG_INTEGRATION', 'sync_org_structure', 'Org structure sync completed', p_user);
```
**Issue:** `import_time_attendance` counts every line as "imported" but writes nothing, so overtime never reaches payroll. `sync_org_structure` logs "completed" without doing anything. Termination skips COBRA, access revocation and final pay. `change_password` is covered in SEC-08.
**Impact:** Operations dashboards show success while hours, directory sync and offboarding never happen. Underpaid overtime is a wage-and-hour compliance problem.
**Recommendation:** Make stubs raise `-20999 Not implemented` until they're built, then implement them with tests.

### ARCH-04: Hard-coded 2024 tax tables and calendar assumptions (HIGH)
**Locations:** `plsql/packages/PKG_PAYROLL.pkb:7`, `:643-660`, `:729-733`, `:437`; `plsql/packages/PKG_COMMON.pkb:170-195`
```sql
c_ss_wage_base_2024 CONSTANT NUMBER := 168600;
-- 2024 Federal tax brackets (Single)
-- TODO: Read from TAX_BRACKETS table instead of hard-coding
IF v_taxable <= 11600 THEN v_tax := v_taxable * 0.10; ...
v_taxable_income := v_period_gross; -- Simplified; should subtract pretax deductions
```
**Issue:** A `TAX_BRACKETS` table and `SEQ_TAX_BRACKET` exist but aren't used. It is now 2026, so withholding and the FICA cap are two years stale. Pre-tax deductions (401k, benefits flagged `PRETAX_FLAG`) are not subtracted from federal taxable income. Fiscal year (Oct 1) and quarter mapping are hard-coded in `get_fiscal_year`/`get_fiscal_quarter`.
**Impact:** Wrong federal withholding and Social Security deductions on every paycheck, plus reconciliation work at year-end.
**Recommendation:** Read brackets and wage bases from `TAX_BRACKETS` keyed by tax year, and subtract pre-tax elements before tax. Move the fiscal start month to `SYSTEM_PARAMETERS`.

### ARCH-05: Element IDs hard-coded in payroll (LOW)
**Location:** `plsql/packages/PKG_PAYROLL.pkb:448`, `:466`, `:481`, `:495`; seed `data/seed/01_reference_data.sql:122-129`
```sql
VALUES (SEQ_PAYROLL_DETAIL.NEXTVAL, p_run_id, p_emp_id, 100, 'TAX', -v_federal_tax, ...)
```
**Issue:** Element IDs `100`–`103` are surrogate keys taken from seed data, and `ELEMENT_TYPE` is copied into `PAYROLL_DETAILS` as well as being stored in `PAY_ELEMENTS`.
**Impact:** Any environment seeded differently posts taxes to the wrong GL accounts (`PKG_INTEGRATION.generate_gl_journal` joins on `ELEMENT_ID`).
**Recommendation:** Look elements up by `ELEMENT_CODE` (`FED_TAX`, `STATE_TAX`, ...) and cache them per run.

### ARCH-06: `WHEN OTHERS` swallowing in infrastructure code (LOW)
**Locations:** `plsql/packages/PKG_AUDIT.pkb:27-30`, `plsql/packages/PKG_NOTIFICATION.pkb:57-62`, `plsql/packages/PKG_COMMON.pkb:58-60`, `plsql/packages/PKG_EMPLOYEE.pkb:51-54`
```sql
EXCEPTION
    WHEN OTHERS THEN
        -- Audit logging must never fail the calling transaction
        ROLLBACK;
```
**Issue:** Errors disappear without a trace. `log_info` failures and audit failures leave no record anywhere.
**Impact:** Compliance gaps in the audit trail that nobody notices.
**Recommendation:** Fall back to a minimal error table or alert log (`DBMS_SYSTEM.KSDWRT`), and track the failure rate.

### ARCH-07: README does not match the codebase (LOW)
**Location:** `README.md:36`, `:44-45`, `:69`, `:80-82`, `:105`
```
| 18 forms | | 12 packages | | 8 reports |      42 tables / 15 views
|-- PKG_DEPARTMENT.pks / .pkb      |-- procedures/      |-- functions/
- Heavy use of DBMS_OUTPUT, UTL_FILE, UTL_MAIL built-in packages
```
**Issue:** The repo has 6 form exports, 11 packages, 6 views, no `PKG_DEPARTMENT`, and no `procedures/` or `functions/` directories. The code uses `UTL_SMTP`, not `UTL_MAIL`.
**Impact:** Migration estimates based on the README will be wrong.
**Recommendation:** Regenerate the inventory from the tree, or mark it as describing the full production estate rather than this sample.

---

## 7. Data Integrity Risks

### DATA-01: `TRG_EMP_BEFORE_UPDATE` column mismatch — every EMPLOYEES UPDATE fails (CRITICAL)
**Trigger:** `plsql/triggers/trg_employees.sql:78-109` · **DDL:** `schema/tables/01_core_tables.sql:152-177`
```sql
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'STATUS_CHANGE', SYSDATE, ...);
```
| Trigger column | Exists in DDL? | Actual DDL column |
|---|---|---|
| `HISTORY_ID` | No | `HIST_ID` |
| `EMP_ID` | Yes | — |
| `CHANGE_TYPE` | Yes | — |
| `CHANGE_DATE` | No | `EFFECTIVE_DATE` |
| `OLD_VALUE` | No | `OLD_DEPT_ID` / `OLD_JOB_ID` / `OLD_SALARY` / ... |
| `NEW_VALUE` | No | `NEW_DEPT_ID` / `NEW_JOB_ID` / `NEW_SALARY` / ... |
| `CHANGED_BY` | No | `CREATED_BY` (NOT NULL) |
| `CHANGE_REASON` | No | `COMMENTS` / `REASON_CODE` |

**Issue:** Six of the eight columns don't exist. The trigger compiles with PL/SQL errors (PLS-00904/ORA-00904) and is left INVALID. Oracle then raises **ORA-04098: trigger 'HRMS.TRG_EMP_BEFORE_UPDATE' is invalid and failed re-validation** on *every* UPDATE of `EMPLOYEES`, whichever columns change. `PKG_EMPLOYEE.log_history` (`PKG_EMPLOYEE.pkb:157-169`) uses the correct columns, which shows the trigger was written against an older schema.
**Impact:** `update_employee`, `transfer_employee`, `promote_employee`, `terminate_employee`, `rehire_employee` and every Forms save on the employee block fail. Core HR maintenance stops working.
**Recommendation:** Rewrite the trigger against the real columns (`HIST_ID`, `EFFECTIVE_DATE`, `OLD_DEPT_ID`/`NEW_DEPT_ID`, `OLD_JOB_ID`/`NEW_JOB_ID`, `CREATED_BY`, `COMMENTS`), or drop it and rely on `PKG_EMPLOYEE.log_history` (see DATA-02). Add a CI step that compiles all objects and fails on `USER_ERRORS`.

### DATA-02: Trigger `CHANGE_TYPE` values violate `CHK_CHANGE_TYPE`, and history is double-written (HIGH)
**Trigger:** `plsql/triggers/trg_employees.sql:94`, `:106` · **Constraint:** `schema/tables/01_core_tables.sql:173-176` · **Package:** `plsql/packages/PKG_EMPLOYEE.pkb:553-555`, `:629-631`
```sql
SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'DEPARTMENT_CHANGE', SYSDATE, ...   -- trigger
SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'JOB_CHANGE', SYSDATE, ...          -- trigger
CONSTRAINT CHK_CHANGE_TYPE CHECK (CHANGE_TYPE IN ('HIRE','TRANSFER','PROMOTION','DEMOTION',
    'SALARY_CHANGE','TERMINATION','REHIRE','LEAVE_START','LEAVE_END','STATUS_CHANGE'))
```
**Issue:** Even with DATA-01 fixed, department and job changes raise ORA-02290. And `transfer_employee`/`promote_employee` already call `log_history('TRANSFER'|'PROMOTION')`, so a fixed trigger would write a second row for the same event.
**Impact:** Transfers and promotions fail outright. Once fixed, history rows are duplicated and history-based reports double-count.
**Recommendation:** Pick one writer, preferably the package API. If the trigger stays, map to `TRANSFER`/`PROMOTION` and skip when a package context flag is set.

### DATA-03: Soft-delete is inconsistent across layers (HIGH)
**Locations:** `plsql/triggers/trg_employees.sql:120-129`; `forms/libraries/HRMS_COMMON_LIB.pll.sql:88-91`; `plsql/packages/PKG_EMPLOYEE.pkb:686-693`; `schema/views/hrms_views.sql:54`, `:80`, `:103`; `plsql/packages/PKG_SECURITY.pkb:42-45`
```sql
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
BEFORE DELETE ON HRMS.EMPLOYEES ...
    RAISE_APPLICATION_ERROR(-20504, 'Direct deletion not allowed. ...');

PROCEDURE toolbar_delete IS BEGIN DELETE_RECORD; END toolbar_delete;   -- Forms toolbar
```
**Issue:**
- The trigger is named `INSTEAD_OF` (and its header says `TRG_EMP_AFTER_DELETE`), but it is a `BEFORE DELETE` trigger that blocks the delete instead of converting it to a soft delete.
- The shared Forms toolbar still issues `DELETE_RECORD`, so every Delete click on the employee form ends in ORA-20504.
- Termination sets both `EMPLOYMENT_STATUS='TERMINATED'` and `ACTIVE_FLAG='N'`, but consumers disagree on which flag counts. `VW_ACTIVE_EMPLOYEES` checks both. `VW_ORG_HIERARCHY`, `VW_EMPLOYEE_COMPENSATION`, `VW_LEAVE_SUMMARY` and `authenticate` check only status. The email-uniqueness trigger checks only `ACTIVE_FLAG`.

**Impact:** Users see errors on delete, and records marked `ACTIVE_FLAG='N'` by the Forms workaround while still `ACTIVE` keep logging in and appearing in compensation and leave views.
**Recommendation:** Pick one soft-delete flag, or derive `ACTIVE_FLAG` from status with a virtual column. Make the toolbar call `PKG_EMPLOYEE.terminate_employee` for this block. Rename the trigger.

### DATA-04: Email uniqueness is claimed but not enforced (HIGH)
**Locations:** `plsql/triggers/trg_employees.sql:40-54`; DDL `schema/tables/01_core_tables.sql:109`, `:134-142`
```sql
-- Validate email uniqueness (also enforced by unique constraint, but
-- this trigger provides a better error message)
SELECT COUNT(*) INTO v_count FROM EMPLOYEES
WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL) AND ACTIVE_FLAG = 'Y';
```
**Issue:** `EMPLOYEES` has no unique constraint or index on `EMAIL`, contrary to the comment. The check runs only in the BEFORE INSERT trigger (UPDATEs can create duplicates), is racy across concurrent inserts, and ignores inactive rows. That breaks rehire scenarios in the other direction.
**Impact:** Duplicate logins (see SEC-06's `MIN(EMP_ID)` workaround), misrouted notifications, and ambiguous `HRMS_LOGIN` lookups (`ROWNUM = 1`).
**Recommendation:** `CREATE UNIQUE INDEX UK_EMP_EMAIL_ACTIVE ON EMPLOYEES (CASE WHEN ACTIVE_FLAG='Y' THEN UPPER(EMAIL) END);` then remove the trigger query.

### DATA-05: `VW_LEAVE_SUMMARY.AVAILABLE` omits `PENDING` (MEDIUM)
**View:** `schema/views/hrms_views.sql:95-96` · **Table:** `schema/tables/03_leave_tables.sql:46-47` · **Carryover:** `plsql/packages/PKG_LEAVE.pkb:567`
```sql
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE              -- view
AVAILABLE GENERATED ALWAYS AS (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL  -- table
```
**Issue:** The view recomputes `AVAILABLE` without subtracting `PENDING`, which contradicts the table's own virtual column. `process_carryover` uses the same pending-blind formula.
**Impact:** Employees and managers see inflated balances and can book more leave than they have. Year-end carryover includes days already requested.
**Recommendation:** Select `lb.AVAILABLE` in the view and in `process_carryover`.

### DATA-06: `expire_carryover` can drive balances negative (MEDIUM)
**Location:** `plsql/packages/PKG_LEAVE.pkb:605-622`
```sql
-- BUG: If run twice on same day, can double-subtract
UPDATE LEAVE_BALANCES SET
    ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
    CARRYOVER_FROM_PREV = 0 ...
WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE) AND CARRYOVER_FROM_PREV > 0;
```
**Issue:** The comment is inaccurate. Zeroing `CARRYOVER_FROM_PREV` together with the `> 0` predicate makes the procedure idempotent. The real defect: the full carried amount is expired even when some of it was already used, which takes back days that were legitimately taken.
**Impact:** Negative or understated balances after the expiry date.
**Recommendation:** Expire `LEAST(CARRYOVER_FROM_PREV, GREATEST(AVAILABLE, 0))`, assuming carryover is consumed first (FIFO). Fix the comment.

### DATA-07: `VW_PAYROLL_LATEST` keys off a global `MAX(RUN_ID)` (MEDIUM)
**Location:** `schema/views/hrms_views.sql:121-125`
```sql
WHERE pr.RUN_ID = (SELECT MAX(pr2.RUN_ID) FROM PAYROLL_RUNS pr2 WHERE pr2.STATUS = 'APPROVED')
```
**Issue:** The view claims to show the "latest payroll per employee", but it returns only the single most recently approved run across the whole company. If that run is an off-cycle or bonus run, every employee not in it disappears. `RUN_ID` order is creation order, not period order.
**Impact:** Pay-stub and reporting consumers show missing or wrong net pay.
**Recommendation:** Pick each employee's latest run with `ROW_NUMBER() OVER (PARTITION BY pd.EMP_ID ORDER BY pp.PERIOD_END_DATE DESC, pr.RUN_ID DESC)`, filtered by `RUN_TYPE` where needed.

### DATA-08: Salary joins can duplicate rows (LOW)
**Location:** `schema/views/hrms_views.sql:32-35`, `:79`
```sql
LEFT JOIN SALARY_RECORDS sr ON e.EMP_ID = sr.EMP_ID AND sr.ACTIVE_FLAG = 'Y' AND sr.EFFECTIVE_DATE <= SYSDATE ...
JOIN SALARY_RECORDS sr ON e.EMP_ID = sr.EMP_ID AND sr.ACTIVE_FLAG = 'Y'       -- VW_EMPLOYEE_COMPENSATION: no date filter
```
**Issue:** Nothing enforces one active salary row per employee. `VW_EMPLOYEE_COMPENSATION` also includes future-dated active records.
**Impact:** Duplicate employees in LOVs and wrong compa-ratios whenever a future raise has been keyed in.
**Recommendation:** Add a unique function-based index on `CASE WHEN ACTIVE_FLAG='Y' THEN EMP_ID END` and apply the date filter in both views.

---

## 8. Severity Index

| ID | Severity | Title | Primary location |
|---|---|---|---|
| SEC-01 | CRITICAL | MD5 password hashing | `PKG_SECURITY.pkb:14-24` |
| SEC-02 | CRITICAL | Hard-coded AES key | `PKG_SECURITY.pkb:7` |
| SEC-03 | CRITICAL | Password never verified | `PKG_SECURITY.pkb:30-80` |
| SEC-04 | CRITICAL | SQL injection in search | `PKG_EMPLOYEE.pkb:465-498` |
| DATA-01 | CRITICAL | Trigger/DDL column mismatch | `trg_employees.sql:78-109` |
| SEC-05 | HIGH | No account lockout | `PKG_SECURITY.pkb:28-50` |
| SEC-06 | HIGH | Enumeration / duplicate login | `PKG_SECURITY.pkb:46-57` |
| SEC-07 | HIGH | Wrong session ID in forms | `HRMS_*.xml` |
| SEC-08 | HIGH | `change_password` stub | `PKG_SECURITY.pkb:211-234` |
| RACE-01 | HIGH | `MAX()+1` employee number | `PKG_EMPLOYEE.pkb:39-55` |
| DRIFT-01 | HIGH | Email validation drift | `HRMS_VALIDATION_LIB.pll.sql:21-41` |
| ARCH-03 | HIGH | Stubs reporting success | `PKG_INTEGRATION.pkb:168-203` |
| ARCH-04 | HIGH | Hard-coded 2024 tax | `PKG_PAYROLL.pkb:7, 643-660` |
| DATA-02 | HIGH | `CHANGE_TYPE` violation / double history | `trg_employees.sql:94,106` |
| DATA-03 | HIGH | Soft-delete inconsistency | `trg_employees.sql:120-129` |
| DATA-04 | HIGH | Email uniqueness unenforced | `trg_employees.sql:40-54` |
| SEC-09 | MEDIUM | Ownership-blind authorization | `PKG_SECURITY.pkb:134-174` |
| SEC-10 | MEDIUM | Hard-coded SMTP / header injection | `PKG_NOTIFICATION.pkb:7-10` |
| SEC-11 | MEDIUM | Cleartext FTP credentials | `PKG_INTEGRATION.pks:12` |
| SEC-12 | MEDIUM | SSN encryption unused | `PKG_SECURITY.pkb:179-206` |
| RACE-02 | MEDIUM | Payroll run without lock | `PKG_PAYROLL.pkb:241-260` |
| PERF-01 | MEDIUM | Day loop `business_days_between` | `PKG_COMMON.pkb:132-146` |
| PERF-02 | MEDIUM | Day loop `add_business_days` | `PKG_COMMON.pkb:151-165` |
| PERF-03 | MEDIUM | Per-day holiday query | `PKG_LEAVE.pkb:12-40` |
| PERF-04 | MEDIUM | `CONNECT BY` hierarchies | `hrms_views.sql:47-57` |
| PERF-05 | MEDIUM | SMTP connection per message | `PKG_NOTIFICATION.pkb:90-107` |
| DRIFT-02 | MEDIUM | SSN rule drift | `HRMS_VALIDATION_LIB.pll.sql:69-90` |
| DRIFT-04 | MEDIUM | Salary range not enforced | `PKG_EMPLOYEE.pkb:231-239` |
| ARCH-01 | MEDIUM | Autonomous transaction overuse | `PKG_EMPLOYEE.pkb:155` |
| ARCH-02 | MEDIUM | `UTL_FILE` integrations | `PKG_INTEGRATION.pkb:24-99` |
| DATA-05 | MEDIUM | Leave view omits `PENDING` | `hrms_views.sql:96` |
| DATA-06 | MEDIUM | Carryover expiry over-deducts | `PKG_LEAVE.pkb:610-622` |
| DATA-07 | MEDIUM | Latest-payroll view uses global MAX | `hrms_views.sql:121-125` |
| SEC-13 | LOW | JSON via concatenation | `PKG_COMMON.pkb:53-54` |
| SEC-14 | LOW | Absolute session timeout | `PKG_SECURITY.pkb:114` |
| RACE-03 | LOW | `adjust_balance` retry race | `PKG_LEAVE.pkb:400-419` |
| PERF-06 | LOW | NOCACHE sequences | `hrms_sequences.sql:9-49` |
| PERF-07 | LOW | Reporting refresh placeholder | `PKG_REPORTING.pkb:200` |
| DRIFT-03 | LOW | Phone normalization drift | `HRMS_VALIDATION_LIB.pll.sql:47-63` |
| DRIFT-05 | LOW | Date rule drift | `PKG_VALIDATION.pkb:6-15` |
| CIRC-01 | LOW | Stale documented cycle | `PKG_EMPLOYEE.pkb:273-275` |
| ARCH-05 | LOW | Hard-coded element IDs | `PKG_PAYROLL.pkb:448-495` |
| ARCH-06 | LOW | `WHEN OTHERS` swallowing | `PKG_AUDIT.pkb:27-30` |
| ARCH-07 | LOW | README inventory drift | `README.md:36-105` |
| DATA-08 | LOW | Salary join duplicates | `hrms_views.sql:32-35, 79` |

---

## 9. Migration Roadmap

### Phase 1: Critical Security (weeks 1-2)

| # | Item | Findings | Effort |
|---|---|---|---|
| 1 | Implement real credential verification (`USER_CREDENTIALS`, salted slow hash, constant-time compare) | SEC-03, SEC-01, SEC-08 | 4 days |
| 2 | Bind variables in `search_employees` | SEC-04 | 0.5 day |
| 3 | Move the SSN key to Wallet/KMS, add an IV, re-encrypt; wire `encrypt_ssn` into writes | SEC-02, SEC-12 | 3 days |
| 4 | Fix the four forms to use `HRMS_COMMON_LIB.check_session` | SEC-07 | 0.5 day |
| 5 | Lockout, failure auditing, uniform failure timing | SEC-05, SEC-06 | 2 days |
| 6 | Externalize SMTP/FTP config and secrets; STARTTLS; header sanitising | SEC-10, SEC-11 | 2 days |

### Phase 2: Data Integrity (weeks 3-5)

| # | Item | Findings | Effort |
|---|---|---|---|
| 1 | Rewrite or drop `TRG_EMP_BEFORE_UPDATE`; single history writer; valid `CHANGE_TYPE`s | DATA-01, DATA-02 | 2 days |
| 2 | Add a CI compile gate (`USER_ERRORS` must be empty) | DATA-01 | 1 day |
| 3 | `SEQ_EMP_NUMBER` for employee numbers; lock the period in `create_payroll_run` with a unique run index | RACE-01, RACE-02 | 1 day |
| 4 | Unique active-email index; unique active-salary index | DATA-04, DATA-08 | 1 day |
| 5 | Unify the soft-delete model; route Forms delete to termination | DATA-03 | 3 days |
| 6 | Fix the leave view/carryover formulas, carryover expiry, and `VW_PAYROLL_LATEST` | DATA-05, DATA-06, DATA-07 | 2 days |
| 7 | Data-driven tax brackets/wage base; pre-tax deductions; element lookup by code | ARCH-04, ARCH-05 | 1 week |
| 8 | Make stubs fail loudly; implement time-and-attendance import | ARCH-03 | 1 week |
| 9 | Enforce salary-for-grade server-side with an audited override | DRIFT-04 | 1 day |

### Phase 3: Performance (weeks 6-9)

| # | Item | Findings | Effort |
|---|---|---|---|
| 1 | Set-based business-day calculation (one implementation, holiday-aware) | PERF-01, PERF-02, PERF-03 | 2 days |
| 2 | Recursive CTE org hierarchy with cycle detection and an index on `MANAGER_EMP_ID` | PERF-04 | 2 days |
| 3 | Batch SMTP connection; `SKIP LOCKED` queue claim; close connections on error | PERF-05 | 1 day |
| 4 | Sequence caching | PERF-06 | 0.5 day |
| 5 | Implement or remove the reporting refresh | PERF-07 | 2 days |
| 6 | Move business history and notifications out of autonomous transactions (AQ/TxEventQ) | ARCH-01, ARCH-06 | 1 week |

### Phase 4: Modernization (months 3-12)

| # | Item | Findings | Effort |
|---|---|---|---|
| 1 | Move all validation server-side behind a single API; retire duplicated PLL validation | DRIFT-01..05 | 2 weeks |
| 2 | Role/permission model with record-level checks (or VPD); SSO/OIDC replaces `USER_SESSIONS` | SEC-09, SEC-14 | 1 month |
| 3 | Replace `UTL_FILE` feeds with REST/event integrations and delivery manifests | ARCH-02 | 1 month |
| 4 | Decouple `PKG_SECURITY` from `PKG_EMPLOYEE`; event-driven termination side effects | CIRC-01 | 1 week |
| 5 | Replace Oracle Forms with a web UI (APEX or SPA) on top of the cleaned-up package API | — | 3-6 months |
| 6 | utPLSQL test suite covering payroll, leave and security; fix README inventory | ARCH-07 | 2 months |
