# Technical Debt Report — Oracle Forms/PL/SQL HRMS Estate

**Generated**: 2026-06-29
**Repository**: `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Scope**: Full codebase audit of PL/SQL packages, triggers, schema DDL, PLL libraries, views, sequences, seed data, and Oracle Forms XML exports.

---

## Executive Summary

This report catalogs **38 identified technical debt items** across the Oracle Forms/PL/SQL HRMS application. The findings span security vulnerabilities, race conditions, performance bottlenecks, client/server validation drift, circular dependencies, architectural anti-patterns, and data integrity risks.

| Severity | Count | Categories |
|----------|-------|------------|
| CRITICAL | 7 | Security (MD5 hashing, hard-coded encryption key, cleartext password transmission, SQL injection), trigger column mismatch, AUDIT_LOG constraint violation, seed data column mismatches |
| HIGH | 12 | Race conditions, timing attack, no account lockout, cleartext FTP credentials, hard-coded tax brackets, validation drift (email, SSN), non-idempotent carryover expiry, partial payroll commits, VW_LEAVE_SUMMARY mismatch |
| MEDIUM | 13 | Performance (day-by-day loops, CONNECT BY, per-iteration SMTP), architectural (autonomous transactions, UTL_FILE, fiscal year hard-coding, stale reporting), weak password complexity, SMTP hard-coding, circular dependency |
| LOW | 6 | NOCACHE sequences, stub implementations, soft-delete trigger confusion, no MFA |

---

## 1. Security Vulnerabilities

### SEC-01: MD5 Password Hashing (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:17-24`
```sql
RETURN RAWTOHEX(
    DBMS_CRYPTO.HASH(
        UTL_RAW.CAST_TO_RAW(p_password),
        DBMS_CRYPTO.HASH_MD5
    )
);
```

**Issue**: MD5 is cryptographically broken. Rainbow table attacks can crack MD5 hashes in seconds. No salt is applied.
**Impact**: Complete password database compromise if the EMPLOYEES table or USER_CREDENTIALS table is leaked.
**Recommendation**: Migrate to bcrypt, scrypt, or PBKDF2 with per-user salt. Oracle 19c supports `DBMS_CRYPTO.HASH_SH256` as a minimum upgrade, but proper password hashing libraries (bcrypt) require external integration or a Java stored procedure wrapper.

---

### SEC-02: Hard-Coded Encryption Key (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:7`
```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```

**Issue**: AES-256 encryption key for SSN data is embedded as a string literal in the package body. Anyone with `SELECT ANY DICTIONARY` or `CREATE ANY PROCEDURE` can read it. The key is also visible in source control.
**Impact**: Full decryption of all SSN_ENCRYPTED values in EMPLOYEES and EMPLOYEE_DEPENDENTS tables.
**Recommendation**: Store the key in Oracle Wallet (TDE) or Oracle Key Vault. At minimum, move to a SYSTEM_PARAMETERS entry with restricted access, though a proper key management solution is strongly preferred.

---

### SEC-03: SQL Injection via String Concatenation (CRITICAL)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:457-494`
```sql
v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
-- ... repeated for p_first_name, p_status, p_location_code
```

**Issue**: The `search_employees` procedure builds dynamic SQL by concatenating user-supplied parameters directly into the query string without bind variables. While Oracle Forms LOVs pass validated values, any direct PL/SQL caller can inject arbitrary SQL.
**Impact**: Unauthorized data exfiltration, privilege escalation, or data modification via crafted search parameters.
**Recommendation**: Replace string concatenation with bind variables using `DBMS_SQL` or native dynamic SQL with `USING` clause:
```sql
v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(:b_last_name) ';
-- then: OPEN p_cursor FOR v_sql USING ..., p_last_name || '%', ...;
```

---

### SEC-04: Cleartext Password Transmission (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:14-24` (hash_password) and `plsql/packages/PKG_SECURITY.pkb:211-234` (change_password)
```sql
FUNCTION hash_password(
    p_password IN VARCHAR2  -- plaintext password arrives here
) RETURN VARCHAR2 IS
```

**Issue**: Passwords are passed as plaintext VARCHAR2 parameters through the PL/SQL call stack. In Oracle Forms over HTTP (non-TLS), credentials traverse the network unencrypted. The `change_password` procedure accepts both old and new passwords in cleartext.
**Impact**: Network sniffing can capture credentials in transit. SGA/shared pool may retain plaintext values.
**Recommendation**: Enforce TLS for all Oracle Forms connections (HTTPS via WebLogic). Consider client-side hashing as defense-in-depth, though server-side hashing remains essential.

---

### SEC-05: No Account Lockout After Failed Attempts (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb:30-80`
```sql
-- VULNERABILITY: No brute-force protection (no lockout after N failures)
FUNCTION authenticate(
    p_username   IN VARCHAR2,
    p_password   IN VARCHAR2,
    ...
```

**Issue**: The `authenticate` function has no failed-attempt counter or account lockout mechanism. Attackers can make unlimited login attempts.
**Impact**: Brute-force and credential-stuffing attacks are trivially feasible.
**Recommendation**: Add a `FAILED_LOGIN_COUNT` and `LOCKED_UNTIL` column to USER_SESSIONS or a separate USER_CREDENTIALS table. Lock accounts after 5 consecutive failures with exponential backoff or time-based lockout (e.g., 15 minutes).

---

### SEC-06: Timing Attack on Authentication (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb:41-57`
```sql
BEGIN
    SELECT EMP_ID INTO v_emp_id
    FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username)
    AND EMPLOYMENT_STATUS = 'ACTIVE';
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        -- VULNERABILITY: Timing attack - different response time for
        -- invalid user vs invalid password
        RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
```

**Issue**: When the username doesn't exist, the function raises immediately. When the username exists but the password is wrong, additional processing occurs (hash computation, session creation). The response time difference reveals whether an account exists.
**Impact**: Username enumeration enables targeted attacks.
**Recommendation**: Always perform the hash computation regardless of whether the user exists. Use a constant-time comparison for the hash result.

---

### SEC-07: Cleartext FTP/Integration Credentials (HIGH)

**File**: `plsql/packages/PKG_INTEGRATION.pks:12`
```sql
-- Known issues:
--   - FTP credentials stored in SYSTEM_PARAMETERS table (cleartext)
```

**Issue**: Integration credentials (FTP for file transfers) are stored in plaintext in the SYSTEM_PARAMETERS table, accessible to anyone with SELECT on that table.
**Impact**: Credential exposure enables unauthorized access to external systems (GL, benefits provider).
**Recommendation**: Store integration credentials in Oracle Wallet or an external secrets manager. At minimum, encrypt values in SYSTEM_PARAMETERS using PKG_SECURITY.encrypt_ssn (with proper key management per SEC-02).

---

### SEC-08: Hard-Coded SMTP Configuration (MEDIUM)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb:7-10`
```sql
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
c_from_name    CONSTANT VARCHAR2(100) := 'HRMS System';
```

**Issue**: SMTP server address, port, and sender identity are hard-coded as package constants. Port 25 implies no TLS (STARTTLS on 587 or implicit TLS on 465 preferred). Changing these requires recompiling the package.
**Impact**: Reduced portability across environments (dev/staging/prod). Email contents may be transmitted in cleartext.
**Recommendation**: Read SMTP configuration from SYSTEM_PARAMETERS (which already has SMTP_HOST/FROM_ADDRESS entries in seed data). Upgrade to TLS-enabled SMTP.

---

### SEC-09: Weak Password Complexity Requirements (MEDIUM)

**File**: `plsql/packages/PKG_SECURITY.pkb:217-228`
```sql
IF LENGTH(p_new_password) < 8 THEN ...
IF NOT REGEXP_LIKE(p_new_password, '[A-Z]') THEN ...
IF NOT REGEXP_LIKE(p_new_password, '[0-9]') THEN ...
```

**Issue**: Password policy only requires 8 characters, one uppercase letter, and one digit. No checks for: lowercase requirement, special characters, password history, dictionary words, or similarity to username.
**Impact**: Weak passwords remain possible (e.g., "Aaaaaaaa1").
**Recommendation**: Add lowercase + special character requirements, minimum 12 characters, password history (last 5), and dictionary check. Consider integration with `DBMS_CREDENTIAL` or external password policy enforcement.

---

### SEC-10: No Multi-Factor Authentication (LOW)

**File**: `plsql/packages/PKG_SECURITY.pks` (entire authentication flow)

**Issue**: Authentication relies solely on username/password. No second factor (TOTP, SMS, hardware token) is supported.
**Impact**: Stolen credentials provide full access with no additional barrier.
**Recommendation**: Implement 2FA/SSO integration (SAML, OAuth) through the WebLogic layer, or add TOTP support via a Java stored procedure.

---

## 2. Race Conditions

### RACE-01: Employee Number Generation via MAX()+1 (HIGH)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:39-55`
```sql
FUNCTION generate_emp_number RETURN VARCHAR2 IS
    v_max_num NUMBER;
BEGIN
    SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
    INTO v_max_num
    FROM EMPLOYEES
    WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
    -- No FOR UPDATE, no serialization
```

**Issue**: Concurrent `create_employee` calls read the same MAX value and generate duplicate employee numbers. The `EXCEPTION WHEN OTHERS` fallback uses SEQ_EMPLOYEE which produces a different numbering scheme, causing inconsistent EMP_NUMBER formats.
**Impact**: `DUP_VAL_ON_INDEX` errors on the `UK_EMP_NUMBER` unique constraint during concurrent onboarding. Retry logic uses sequence-based fallback, creating format inconsistency (e.g., `EMP-000042` vs `EMP-010001`).
**Recommendation**: Replace the MAX()+1 pattern entirely with `SEQ_EMP_NUMBER.NEXTVAL`:
```sql
v_new_number := c_emp_number_prefix || '-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0');
```
This is atomic, gap-safe, and eliminates the race condition. The sequence `SEQ_EMP_NUMBER` already exists (schema/sequences/hrms_sequences.sql:21) but is unused by the primary code path.

---

### RACE-02: Payroll Run Creation Without Locking Period (HIGH)

**File**: `plsql/packages/PKG_PAYROLL.pkb:240-243`
```sql
SELECT STATUS INTO v_status
FROM PAY_PERIODS
WHERE PERIOD_ID = p_period_id;
-- No FOR UPDATE -- another session could close the period between SELECT and INSERT
```

**Issue**: `create_payroll_run` checks the period status without `FOR UPDATE`. A concurrent `close_pay_period` call could close the period between the status check and the INSERT, creating a payroll run for a closed period.
**Impact**: Invalid payroll runs created against closed periods, leading to incorrect pay calculations and compliance issues.
**Recommendation**: Add `FOR UPDATE NOWAIT` to the SELECT, matching the pattern already used correctly in `close_pay_period` (line 196) and `approve_payroll` (line 564).

---

## 3. Performance Issues

### PERF-01: Day-by-Day Cursor Loop for Business Days (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pkb:12-40`
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count
        FROM HOLIDAYS
        WHERE HOLIDAY_DATE = v_date ...;
        IF v_holiday_count = 0 THEN v_count := v_count + 1; END IF;
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Issue**: Iterates day-by-day between two dates, issuing a separate `SELECT COUNT(*)` against the HOLIDAYS table for each weekday. A 30-day leave request generates ~22 individual queries.
**Impact**: Slow leave request submission for long date ranges. Holiday table full-scans on each iteration.
**Recommendation**: Replace with set-based arithmetic:
```sql
-- Weekdays via formula: total_days - (2 * full_weeks) - weekend_adjustments
-- Then subtract holidays in a single query:
SELECT COUNT(*) FROM HOLIDAYS WHERE HOLIDAY_DATE BETWEEN p_start AND p_end
  AND TO_CHAR(HOLIDAY_DATE, 'DY') NOT IN ('SAT','SUN') AND ACTIVE_FLAG = 'Y';
```

---

### PERF-02: Duplicate Day-by-Day Loop in PKG_COMMON (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:132-146`
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        v_count := v_count + 1;
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Issue**: `business_days_between` in PKG_COMMON uses the same day-by-day loop pattern as PKG_LEAVE but without holiday checking. Code is duplicated rather than shared, and still O(n) where n = days in range.
**Impact**: Performance degradation for large date ranges; code duplication increases maintenance burden.
**Recommendation**: Replace both with a shared set-based calculation. Consolidate into a single function in PKG_COMMON that accepts an optional holiday-check flag.

---

### PERF-03: CONNECT BY Hierarchical Query in Org Chart (MEDIUM)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:828-837` and `schema/views/hrms_views.sql:47-57`
```sql
START WITH EMP_ID = p_root_emp_id
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
AND LEVEL <= p_max_depth
ORDER SIBLINGS BY LAST_NAME, FIRST_NAME;
```

**Issue**: CONNECT BY performs a recursive tree walk without materialization. For organizations with >500 employees, query execution time degrades exponentially. The view `VW_ORG_HIERARCHY` has no depth limit at all.
**Impact**: Timeouts on org chart display for large departments; full-company queries may hang.
**Recommendation**: Replace with recursive CTE (`WITH RECURSIVE`) which allows the optimizer to use hash joins. Add materialized view for the full hierarchy, refreshed on employee changes. Add index on `(MANAGER_EMP_ID, EMPLOYMENT_STATUS)`.

---

### PERF-04: Per-Iteration SMTP Connection (MEDIUM)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb:88-107`
```sql
FOR notif_rec IN (...) LOOP
    v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
    UTL_SMTP.HELO(v_connection, c_smtp_host);
    -- ... send one email ...
    UTL_SMTP.QUIT(v_connection);
END LOOP;
```

**Issue**: `process_queue` opens and closes an SMTP connection for every single notification. TCP handshake + SMTP HELO/EHLO per message adds ~100-300ms overhead each.
**Impact**: Batch notification processing (e.g., after payroll run generating 500+ notifications) takes minutes instead of seconds. Can cause SMTP server connection exhaustion.
**Recommendation**: Open the connection once before the loop, send all messages, then close:
```sql
v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
UTL_SMTP.HELO(v_connection, c_smtp_host);
FOR notif_rec IN (...) LOOP
    UTL_SMTP.RSET(v_connection);  -- reset for next message
    -- ... send email using existing connection ...
END LOOP;
UTL_SMTP.QUIT(v_connection);
```

---

### PERF-05: NOCACHE on All Sequences (LOW)

**File**: `schema/sequences/hrms_sequences.sql:9-48`
```sql
CREATE SEQUENCE HRMS.SEQ_DEPARTMENT START WITH 100 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
-- ... (all 22 sequences except SEQ_AUDIT use NOCACHE)
```

**Issue**: 21 out of 22 sequences use NOCACHE, requiring a data dictionary write for every `.NEXTVAL` call. Only `SEQ_AUDIT` (high-frequency) has `CACHE 100`.
**Impact**: Contention on `SYS.SEQ$` table during concurrent operations; unnecessary I/O overhead.
**Recommendation**: Add `CACHE 20` to all frequently-used sequences (SEQ_EMPLOYEE, SEQ_SALARY, SEQ_PAYROLL_DETAIL, SEQ_LEAVE_REQUEST, SEQ_NOTIFICATION). Keep NOCACHE only for low-volume sequences where gap-free numbering matters.

---

### PERF-06: Row-by-Row Payroll Processing (MEDIUM)

**File**: `plsql/packages/PKG_PAYROLL.pkb:296-327`
```sql
FOR emp_rec IN (
    SELECT e.EMP_ID FROM EMPLOYEES e
    WHERE e.EMPLOYMENT_STATUS = 'ACTIVE' ...
) LOOP
    calculate_employee_pay(p_run_id, emp_rec.EMP_ID, v_period_id, p_user);
    IF MOD(v_emp_count, 50) = 0 THEN COMMIT; END IF;
END LOOP;
```

**Issue**: Payroll calculation processes one employee at a time in a cursor loop. Each iteration performs multiple SELECTs and INSERTs. Mid-loop COMMITs every 50 employees create partial-commit risk.
**Impact**: Payroll runs for 1000+ employees take excessive time. A failure at employee #501 leaves #1-#500 committed but #501-#1000 unprocessed, requiring manual cleanup.
**Recommendation**: Refactor to BULK COLLECT + FORALL for the insertion of payroll details. Use SAVEPOINT-based error handling instead of mid-loop COMMITs. Consider Oracle's parallel DML for large-scale runs.

---

## 4. Validation Drift

### DRIFT-01: Email Validation — Client vs Server (HIGH)

**Client (PLL)**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41`
```sql
v_at_pos := INSTR(p_email, '@');
v_dot_pos := INSTR(p_email, '.', v_at_pos);
-- Only checks for one dot after @
```

**Server (PKG_COMMON)**: `plsql/packages/PKG_COMMON.pkb:265-268`
```sql
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

**Issue**: The PLL library uses manual INSTR-based parsing that rejects valid emails with subdomains (e.g., `user@mail.company.com`). The server-side regex correctly accepts subdomains. Users entering valid subdomain emails get rejected by the form but would pass server-side validation.
**Impact**: Valid employee email addresses blocked at data entry; HR staff must use workarounds.
**Recommendation**: Replace PLL email validation with a call to `PKG_VALIDATION.validate_email_format` (which delegates to `PKG_COMMON.is_valid_email`). Single source of truth for email validation.

---

### DRIFT-02: SSN Validation — Client vs Server (HIGH)

**Client (PLL)**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:69-90`
```sql
-- Checks for zero groups: 000, 00, 0000
IF SUBSTR(v_digits, 1, 3) = '000' OR
   SUBSTR(v_digits, 4, 2) = '00' OR
   SUBSTR(v_digits, 6, 4) = '0000' THEN
    RETURN FALSE;
END IF;
```

**Server (PKG_COMMON)**: `plsql/packages/PKG_COMMON.pkb:277-280`
```sql
FUNCTION is_valid_ssn(p_ssn IN VARCHAR2) RETURN BOOLEAN IS
BEGIN
    RETURN REGEXP_LIKE(REGEXP_REPLACE(p_ssn, '[^0-9]', ''), '^\d{9}$');
END is_valid_ssn;
```

**Issue**: The PLL validation enforces SSA rules (no all-zero groups), but the server-side `is_valid_ssn` only checks for 9 digits. An SSN like `000-12-3456` would pass server-side but fail client-side.
**Impact**: Inconsistent behavior depending on data entry path (Forms vs direct API). Invalid SSNs could be stored if entered through a non-Forms interface.
**Recommendation**: Add zero-group validation to `PKG_COMMON.is_valid_ssn` to match the stricter PLL rules:
```sql
RETURN REGEXP_LIKE(v_digits, '^\d{9}$')
   AND SUBSTR(v_digits, 1, 3) != '000'
   AND SUBSTR(v_digits, 4, 2) != '00'
   AND SUBSTR(v_digits, 6, 4) != '0000';
```

---

### DRIFT-03: Salary Range Error Message Formatting (MEDIUM)

**Client (PLL)**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:126-128`
```sql
RETURN 'Below minimum (' || TO_CHAR(v_min, 'FM$999,999') || ')';
```

**Server (PKG_VALIDATION)**: `plsql/packages/PKG_VALIDATION.pkb:35-37`
```sql
RETURN 'Salary ' || TO_CHAR(p_salary, 'FM$999,999,990.00') ||
       ' is below minimum for grade ' || v_grade_name ||
       ' (' || TO_CHAR(v_min, 'FM$999,999,990.00') || ')';
```

**Issue**: The PLL shows abbreviated errors without cents or the actual salary value. The server-side shows full detail with grade name and precise amounts. Forms users get less diagnostic information.
**Impact**: HR staff must re-check salary details manually when the form shows a terse error. Low operational efficiency during bulk data entry.
**Recommendation**: Delegate PLL salary validation to `PKG_VALIDATION.validate_salary_for_grade` and display its full message in the Forms status bar.

---

### DRIFT-04: Date Validation Inconsistencies (MEDIUM)

**Client (PLL)**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:96-99`
```sql
FUNCTION validate_date_not_future(p_date IN DATE) RETURN BOOLEAN IS
BEGIN
    RETURN p_date IS NULL OR TRUNC(p_date) <= TRUNC(SYSDATE);
END;
```

**Server (PKG_VALIDATION)**: `plsql/packages/PKG_VALIDATION.pkb:71-76`
```sql
FUNCTION is_future_date(p_date IN DATE) RETURN BOOLEAN IS
BEGIN
    RETURN TRUNC(p_date) > TRUNC(SYSDATE);
END;
```

**Issue**: Function naming is inverted — PLL uses `validate_date_not_future` (returns TRUE if valid), while server uses `is_future_date` (returns TRUE if future). The PLL function treats NULL as valid; the server function would raise on NULL input. Different semantics make it easy for callers to misuse.
**Impact**: Subtle bugs when developers assume consistent semantics. NULL dates pass PLL validation but may cause NullPointerException-equivalent behavior server-side.
**Recommendation**: Standardize on a single function with consistent naming and NULL handling. Add `is_future_date` to PKG_VALIDATION with NULL-safe behavior, and have the PLL call it.

---

## 5. Circular Dependencies

### CIRC-01: PKG_EMPLOYEE <-> PKG_PAYROLL (MEDIUM)

**Files**:
- `plsql/packages/PKG_EMPLOYEE.pks:6`: `Dependencies: PKG_COMMON, PKG_AUDIT, PKG_NOTIFICATION, PKG_PAYROLL`
- `plsql/packages/PKG_PAYROLL.pks:6`: `Dependencies: PKG_EMPLOYEE, PKG_COMMON, PKG_AUDIT, PKG_NOTIFICATION`
- `plsql/packages/PKG_EMPLOYEE.pkb:273-281`:
```sql
-- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
-- which in turn may call PKG_EMPLOYEE.is_active for validation
PKG_PAYROLL.create_salary_record(
    p_emp_id         => v_emp_id,
    p_effective_date => p_hire_date,
    p_base_salary    => p_base_salary, ...
```

**Issue**: PKG_EMPLOYEE calls `PKG_PAYROLL.create_salary_record` during employee creation (and promotion/rehire). PKG_PAYROLL's validation may call back to `PKG_EMPLOYEE.is_active`. This creates a compile-order dependency: both packages must be compiled in spec-first, body-second order or compilation fails.
**Impact**: Deployment scripts must carefully order compilation. ORA-04068 (package state discarded) errors after recompilation of either package invalidate the other.
**Recommendation**: Extract the salary record creation into a thin mediator package (e.g., `PKG_SALARY_MGR`) that both can call without circular reference. Alternatively, move `is_active` to PKG_COMMON to break the cycle.

---

## 6. Architectural Anti-Patterns

### ARCH-01: Autonomous Transaction Overuse (MEDIUM)

**Files**:
- `plsql/packages/PKG_AUDIT.pkb:14`: `PRAGMA AUTONOMOUS_TRANSACTION;` in `log_action`
- `plsql/packages/PKG_COMMON.pkb:16,46`: `PRAGMA AUTONOMOUS_TRANSACTION;` in `log_error`, `log_info`
- `plsql/packages/PKG_EMPLOYEE.pkb:155`: `PRAGMA AUTONOMOUS_TRANSACTION;` in `log_history`
- `plsql/packages/PKG_NOTIFICATION.pkb:27`: `PRAGMA AUTONOMOUS_TRANSACTION;` in `send_notification`

**Issue**: Five procedures use autonomous transactions. While this is appropriate for audit logging (which must persist even if the main transaction rolls back), the `log_history` in PKG_EMPLOYEE means history records are committed even when the main employee operation rolls back, creating orphaned history entries.
**Impact**: Orphaned audit/history records after failed transactions. Debugging is complicated by history that doesn't match actual data state.
**Recommendation**: Keep autonomous transactions for `PKG_AUDIT.log_action` and `PKG_COMMON.log_error/log_info` (true audit). Remove from `PKG_EMPLOYEE.log_history` — employee history should commit/rollback with the employee change. Keep in `PKG_NOTIFICATION.send_notification` (notification queue is intentionally independent).

---

### ARCH-02: UTL_FILE Flat-File Integration (MEDIUM)

**Files**:
- `plsql/packages/PKG_PAYROLL.pkb:826-894`: `generate_pay_register` writes CSV via `UTL_FILE.FOPEN('PAYROLL_OUTPUT', ...)`
- `plsql/packages/PKG_INTEGRATION.pkb:16-83`: `generate_gl_journal` writes pipe-delimited file via `UTL_FILE`
- `plsql/packages/PKG_INTEGRATION.pkb:90-147`: `export_benefits_feed` writes fixed-width file via `UTL_FILE`
- `plsql/packages/PKG_INTEGRATION.pkb:153-194`: `import_time_attendance` reads CSV via `UTL_FILE`

**Issue**: Four integration points use UTL_FILE for flat-file exchange. Files are written to Oracle directory objects on the database server filesystem. No file transfer verification, no checksums, no acknowledgment protocol. If the file system is full or the directory object is misconfigured, data is silently lost.
**Impact**: Integration failures are not detected until downstream systems report missing data (e.g., missed GL journal entries, stale benefits enrollments). No retry mechanism.
**Recommendation**: Phase 1: Add file verification (checksum, record count trailer validation). Phase 2: Replace with REST API integration or Oracle Advanced Queuing (AQ) for real-time, reliable messaging. Phase 3: Move to event-driven integration with proper error handling and dead-letter queues.

---

### ARCH-03: Hard-Coded Tax Brackets (HIGH)

**File**: `plsql/packages/PKG_PAYROLL.pkb:606-677`
```sql
-- 2024 Federal tax brackets (Single)
-- TODO: Read from TAX_BRACKETS table instead of hard-coding
IF p_filing_status = 'SINGLE' OR p_filing_status = 'MARRIED_SEPARATE' THEN
    IF v_taxable <= 11600 THEN
        v_tax := v_taxable * 0.10;
    ELSIF v_taxable <= 47150 THEN ...
```

**Issue**: Federal tax brackets for 2024 are hard-coded as numeric literals. The `TAX_BRACKETS` table exists in the schema (02_payroll_tables.sql:159-173) but is unused. State tax rates are also hard-coded as a CASE expression (lines 703-715). Constants for Social Security wage base and deduction amounts are also hard-coded (lines 7-14).
**Impact**: Annual IRS bracket updates require code changes, recompilation, and redeployment instead of a simple data update. Risk of using outdated brackets if the code change is missed.
**Recommendation**: Read all tax parameters from the TAX_BRACKETS and SYSTEM_PARAMETERS tables. Populate TAX_BRACKETS with 2024 (and future) bracket data. Add a version/year check to ensure current-year brackets are loaded before payroll runs.

---

### ARCH-04: Hard-Coded Fiscal Year Start (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:170-179`
```sql
FUNCTION get_fiscal_year(p_date IN DATE DEFAULT SYSDATE) RETURN NUMBER IS
BEGIN
    IF EXTRACT(MONTH FROM p_date) >= 10 THEN  -- October
        RETURN EXTRACT(YEAR FROM p_date) + 1;
    ELSE
        RETURN EXTRACT(YEAR FROM p_date);
    END IF;
END;
```

**Issue**: Fiscal year start month (October) is hard-coded. A SYSTEM_PARAMETERS entry (`FISCAL_YEAR_START = '10'`) already exists in seed data (01_reference_data.sql:189) but is not used by this function.
**Impact**: If the company changes its fiscal year (e.g., to January for calendar-year alignment), code must be modified and recompiled.
**Recommendation**: Read the fiscal year start month from `PKG_COMMON.get_param_number('PAYROLL', 'FISCAL_YEAR_START')` and use it dynamically.

---

### ARCH-05: Stub/TODO Implementations (LOW)

**Files**:
- `plsql/packages/PKG_EMPLOYEE.pkb:737-739`:
```sql
-- TODO: Integrate with benefits system to trigger COBRA
-- TODO: Revoke system access via PKG_SECURITY
-- TODO: Calculate final pay via PKG_PAYROLL.calculate_final_pay
```
- `plsql/packages/PKG_INTEGRATION.pkb:170-171`:
```sql
-- TODO: Implement actual parsing and database update
v_imported := v_imported + 1;
```
- `plsql/packages/PKG_INTEGRATION.pkb:196-203`: `sync_org_structure` — empty placeholder
- `plsql/packages/PKG_REPORTING.pkb:196-204`: `refresh_reporting_tables` — empty placeholder

**Issue**: Four procedures are stubs or contain TODO comments indicating incomplete functionality. The `import_time_attendance` procedure reads the file but never actually parses or persists the data. Termination does not trigger COBRA notifications or access revocation.
**Impact**: Time attendance data is silently discarded. Terminated employees retain system access. No COBRA compliance notifications. Reporting tables are never refreshed.
**Recommendation**: Prioritize implementation of security-critical stubs (access revocation on termination). Document the stubs in a backlog with severity tags. Add runtime warnings (DBMS_OUTPUT or audit log entries) when stubs are invoked.

---

### ARCH-06: Stale Denormalized Reporting Tables (MEDIUM)

**File**: `plsql/packages/PKG_REPORTING.pks:9`
```sql
-- Known issues:
--   - Denormalized reporting tables refreshed nightly; stale during business hours
```

**Issue**: Reporting data is served from denormalized RPT_* tables that are only refreshed by the `refresh_reporting_tables` batch job (currently a stub). During business hours, reports show stale data.
**Impact**: Management decisions based on outdated headcount, compensation, or turnover data. Discrepancies between operational screens and reports confuse users.
**Recommendation**: Implement the `refresh_reporting_tables` procedure. Consider materialized views with `REFRESH ON COMMIT` for critical reports, or accept nightly refresh for less time-sensitive reports with clear "as of" timestamps.

---

## 7. Data Integrity Risks

### DATA-01: Trigger Column Mismatch — EMPLOYEE_HISTORY (CRITICAL)

**Trigger**: `plsql/triggers/trg_employees.sql:78-85`
```sql
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (
    SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'STATUS_CHANGE', SYSDATE,
    :OLD.EMPLOYMENT_STATUS, :NEW.EMPLOYMENT_STATUS,
    NVL(:NEW.MODIFIED_BY, USER), 'Triggered by status update'
);
```

**Table DDL**: `schema/tables/01_core_tables.sql:152-177`
```sql
CREATE TABLE HRMS.EMPLOYEE_HISTORY (
    HIST_ID              NUMBER(15)      NOT NULL,  -- NOT "HISTORY_ID"
    EMP_ID               NUMBER(10)      NOT NULL,
    CHANGE_TYPE          VARCHAR2(30)    NOT NULL,
    EFFECTIVE_DATE       DATE            NOT NULL,  -- NOT "CHANGE_DATE"
    OLD_DEPT_ID          NUMBER(10),                -- NOT "OLD_VALUE"
    NEW_DEPT_ID          NUMBER(10),                -- NOT "NEW_VALUE"
    ...
    CREATED_BY           VARCHAR2(30)    NOT NULL,  -- NOT "CHANGED_BY"
    ...
    REASON_CODE          VARCHAR2(30),              -- NOT "CHANGE_REASON"
```

**Issue**: The trigger `TRG_EMP_BEFORE_UPDATE` references **six columns that do not exist** in the EMPLOYEE_HISTORY table:
| Trigger Column | Actual DDL Column |
|---|---|
| `HISTORY_ID` | `HIST_ID` |
| `CHANGE_DATE` | `EFFECTIVE_DATE` |
| `OLD_VALUE` | (no VARCHAR2 equivalent — table uses typed columns like `OLD_DEPT_ID`) |
| `NEW_VALUE` | (no VARCHAR2 equivalent) |
| `CHANGED_BY` | `CREATED_BY` |
| `CHANGE_REASON` | `REASON_CODE` |

This trigger would fail at runtime with ORA-00904 ("invalid identifier") for every employee status change, department transfer, and job change.
**Impact**: All trigger-based history logging is silently broken. Employee status changes, transfers, and promotions are not recorded in history. The trigger converts what should be an audit trail into a runtime error that is swallowed (if the trigger has an exception handler) or blocks the update entirely.
**Recommendation**: **Immediate fix required.** Rewrite the trigger INSERT to match the actual table DDL. For status changes, use a generic approach mapping to the existing column structure, or add `OLD_VALUE`/`NEW_VALUE` VARCHAR2 columns to the table for trigger-based generic logging.

---

### DATA-02: AUDIT_LOG Constraint Violation — STATUS_CHANGE Action (CRITICAL)

**Table DDL**: `schema/tables/04_performance_tables.sql:104`
```sql
CONSTRAINT CHK_AUDIT_ACTION CHECK (ACTION_TYPE IN ('INSERT', 'UPDATE', 'DELETE'))
```

**Trigger**: `plsql/triggers/trg_audit.sql:54`
```sql
PKG_AUDIT.log_action(
    'LEAVE_REQUESTS',
    :NEW.REQUEST_ID,
    'STATUS_CHANGE',  -- NOT in allowed CHECK constraint values
    ...
```

**Issue**: The `TRG_LEAVE_REQUEST_AUDIT` trigger passes `'STATUS_CHANGE'` as the `ACTION_TYPE`, but the `CHK_AUDIT_ACTION` CHECK constraint only allows `'INSERT'`, `'UPDATE'`, `'DELETE'`. This would cause an ORA-02290 constraint violation at runtime.
**Impact**: Every leave request status change (approve, reject, cancel) would fail with a constraint violation, either blocking the operation entirely or silently dropping the audit record (since `PKG_AUDIT.log_action` uses autonomous transaction with a WHEN OTHERS handler that rolls back and suppresses the error).
**Recommendation**: Either expand the CHECK constraint to include `'STATUS_CHANGE'`:
```sql
CHECK (ACTION_TYPE IN ('INSERT', 'UPDATE', 'DELETE', 'STATUS_CHANGE'))
```
Or change the trigger to use `'UPDATE'` as the action type (since a status change is semantically an update).

---

### DATA-03: Seed Data Column Mismatches (CRITICAL)

**File**: `data/seed/01_reference_data.sql`

**Locations table — line 11**:
```sql
INSERT INTO LOCATIONS (..., PHONE, ...) VALUES (..., '212-555-1000', ...);
```
**Actual DDL** (`schema/tables/01_core_tables.sql:44`):
```sql
PHONE_NUMBER         VARCHAR2(30),
```
The seed script uses column name `PHONE` but the table defines `PHONE_NUMBER`.

**JOB_GRADES table — line 23**:
```sql
INSERT INTO JOB_GRADES (GRADE_ID, GRADE_NAME, GRADE_LEVEL, MIN_SALARY, ...)
```
**Actual DDL** (`schema/tables/01_core_tables.sql:57-72`):
The table has `GRADE_CODE` (VARCHAR2(10) NOT NULL) but **no `GRADE_LEVEL` column**. The seed script also omits the required `GRADE_CODE` column.

**Issue**: Seed scripts reference columns that don't exist in the DDL and omit required columns, meaning `01_reference_data.sql` would fail with ORA-00904 if executed against the defined schema.
**Impact**: Fresh environment setup fails. Reference data cannot be loaded without manual correction.
**Recommendation**: Correct the seed script column names to match the DDL. Add GRADE_CODE values. Fix PHONE -> PHONE_NUMBER.

---

### DATA-04: VW_LEAVE_SUMMARY Available Balance Mismatch (HIGH)

**View**: `schema/views/hrms_views.sql:96-97`
```sql
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,
-- Missing: - lb.PENDING
```

**Table DDL**: `schema/tables/03_leave_tables.sql:47`
```sql
AVAILABLE NUMBER(6,2) GENERATED ALWAYS AS
    (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL,
```

**Issue**: The view computes `AVAILABLE` without subtracting `PENDING`, but the table's virtual column correctly subtracts `PENDING`. Users querying the view see a higher available balance than the actual computed column.
**Impact**: Managers reviewing team leave balances through the view see inflated availability. Leave requests may appear to have sufficient balance when they don't.
**Recommendation**: Add `- lb.PENDING` to the view's AVAILABLE formula:
```sql
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT - lb.PENDING AS AVAILABLE
```
Or simply select the virtual column directly: `lb.AVAILABLE`.

---

### DATA-05: Non-Idempotent Carryover Expiry (HIGH)

**File**: `plsql/packages/PKG_LEAVE.pkb:610-623`
```sql
PROCEDURE expire_carryover(p_user IN VARCHAR2 DEFAULT USER) IS
BEGIN
    UPDATE LEAVE_BALANCES SET
        ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
        CARRYOVER_FROM_PREV = 0, ...
    WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE)
    AND CARRYOVER_FROM_PREV > 0;
```

**Issue**: The procedure sets `CARRYOVER_FROM_PREV = 0` but identifies records by `CARRYOVER_FROM_PREV > 0`. If run once, it works correctly. But there is no guard against double-execution on the same day — the second run would find no qualifying rows (since `CARRYOVER_FROM_PREV` was already zeroed). However, as noted in the package header comment: "Carryover expiry job sometimes double-expires if run twice on same day" — this suggests a race condition where the first run's COMMIT hasn't been seen by the second run.
**Impact**: Employee leave balances incorrectly reduced if the batch job fires twice in quick succession (e.g., scheduler misconfiguration, manual re-run).
**Recommendation**: Add an idempotency guard: record the expiry date when processed, and skip already-processed records:
```sql
AND CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE)
AND CARRYOVER_FROM_PREV > 0
AND (CARRYOVER_EXPIRED_FLAG IS NULL OR CARRYOVER_EXPIRED_FLAG = 'N');
-- Then: SET CARRYOVER_EXPIRED_FLAG = 'Y', ...
```

---

### DATA-06: Partial Payroll Commits (HIGH)

**File**: `plsql/packages/PKG_PAYROLL.pkb:322-327`
```sql
-- Commit every 50 employees to avoid long transactions
-- ISSUE: Partial commits mean a failure leaves payroll half-calculated
IF MOD(v_emp_count, 50) = 0 THEN
    COMMIT;
END IF;
```

**Issue**: Mid-loop COMMITs in `calculate_payroll` create atomicity violations. If the process fails at employee #75, employees #1-#50 are committed but #51-#75 are rolled back. The run status shows 'CALCULATING' with no way to know which employees were processed.
**Impact**: Payroll data in an inconsistent state. Some employees have calculated pay, others don't. Manual identification and re-processing of the uncommitted subset is required.
**Recommendation**: Use `SAVEPOINT` instead of `COMMIT` for checkpointing. Only COMMIT once after all employees are processed. For very large runs, implement a resume mechanism that tracks the last successfully processed EMP_ID.

---

### DATA-07: Soft-Delete Trigger Confusion (LOW)

**File**: `plsql/triggers/trg_employees.sql:120-129`
```sql
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
BEFORE DELETE ON HRMS.EMPLOYEES
FOR EACH ROW
BEGIN
    RAISE_APPLICATION_ERROR(-20504,
        'Direct deletion not allowed. Use termination process or set ACTIVE_FLAG to N.');
END;
```

**Issue**: Named `TRG_EMP_INSTEAD_OF_DELETE` but is actually a `BEFORE DELETE` trigger (INSTEAD OF is only valid on views). The trigger unconditionally blocks all DELETEs with an error. This contradicts the soft-delete pattern — the trigger doesn't convert DELETE to UPDATE, it simply prevents deletion.
**Impact**: Oracle Forms `DELETE_RECORD` operation fails. Developers must use a workaround (`ACTIVE_FLAG = 'N'` then `CLEAR_RECORD`). The trigger name is misleading (suggests INSTEAD OF semantics that don't exist on tables).
**Recommendation**: Rename to `TRG_EMP_PREVENT_DELETE` to accurately reflect behavior. Document the soft-delete pattern in application guidelines. Consider adding a `DELETE_EMPLOYEE` procedure that performs the soft-delete and audit logging cleanly.

---

## 8. Additional Observations

### OBS-01: VW_PAYROLL_LATEST Global Scope Issue

**File**: `schema/views/hrms_views.sql:121-125`
```sql
WHERE pr.RUN_ID = (
    SELECT MAX(pr2.RUN_ID)
    FROM PAYROLL_RUNS pr2
    WHERE pr2.STATUS = 'APPROVED'
)
```

**Issue**: The view shows data from the single latest approved payroll run globally, not per-employee. If supplemental or bonus runs are approved after the regular run, all employees show data from the supplemental run (which may only cover a subset of employees).
**Impact**: Most employees would show zero pay in the view after a supplemental run is approved.
**Recommendation**: Change to per-employee latest run:
```sql
WHERE pr.RUN_ID = (SELECT MAX(pr2.RUN_ID) FROM PAYROLL_RUNS pr2
    JOIN PAYROLL_DETAILS pd2 ON pr2.RUN_ID = pd2.RUN_ID
    WHERE pr2.STATUS = 'APPROVED' AND pd2.EMP_ID = pd.EMP_ID)
```

---

### OBS-02: Holiday Observed Dates Not Handled

**File**: `plsql/packages/PKG_LEAVE.pkb:9-10`
```sql
-- BUG: Does not handle "observed" holidays (e.g., if July 4 falls on
-- Saturday, the observed Friday is not excluded)
```

**Issue**: Holiday detection uses exact date match only. Observed holidays (e.g., Friday observance when holiday falls on Saturday) are not handled.
**Impact**: Business day calculations are off by 1-2 days for holidays falling on weekends.
**Recommendation**: Add an `OBSERVED_DATE` column to the HOLIDAYS table and check both `HOLIDAY_DATE` and `OBSERVED_DATE` in business day calculations.

---

## 9. Prioritized Migration Roadmap

### Phase 1: Critical Security Fixes (1-2 weeks)

| Priority | Item | Effort | Risk if Deferred |
|----------|------|--------|-----------------|
| 1 | SEC-03: Fix SQL injection in search_employees | 0.5 day | Active exploitation risk |
| 2 | SEC-02: Move encryption key to Oracle Wallet | 1 day | SSN data compromise |
| 3 | SEC-01: Upgrade MD5 to SHA-256 (interim) / bcrypt (target) | 2 days | Password database compromise |
| 4 | SEC-04: Implement account lockout | 1 day | Brute-force attacks |
| 5 | DATA-01: Fix trigger column mismatch | 0.5 day | All history logging broken |
| 6 | DATA-02: Fix AUDIT_LOG constraint for STATUS_CHANGE | 0.5 day | Leave audit trail broken |
| 7 | DATA-03: Fix seed data column name mismatches | 0.5 day | Environment provisioning blocked |

### Phase 2: Data Integrity & High-Priority Fixes (2-4 weeks)

| Priority | Item | Effort | Risk if Deferred |
|----------|------|--------|-----------------|
| 1 | RACE-01: Replace MAX()+1 with sequence for emp numbers | 0.5 day | Duplicate employee numbers |
| 2 | RACE-02: Add FOR UPDATE to payroll period check | 0.5 day | Invalid payroll runs |
| 3 | DATA-04: Fix VW_LEAVE_SUMMARY AVAILABLE formula | 0.5 day | Inflated leave balances |
| 4 | DATA-05: Make carryover expiry idempotent | 1 day | Lost leave balance |
| 5 | DATA-06: Remove mid-loop COMMITs in payroll | 1 day | Half-calculated payrolls |
| 6 | ARCH-03: Read tax brackets from TAX_BRACKETS table | 2 days | Incorrect tax withholding |
| 7 | DRIFT-01/02: Consolidate email + SSN validation | 1 day | Data entry failures |
| 8 | SEC-07: Move FTP/integration credentials to Wallet | 1 day | Credential exposure |

### Phase 3: Performance & Architecture (1-3 months)

| Priority | Item | Effort | Risk if Deferred |
|----------|------|--------|-----------------|
| 1 | PERF-04: SMTP connection reuse | 1 day | Notification delays |
| 2 | PERF-01/02: Replace date loops with set-based arithmetic | 2 days | Slow leave calculations |
| 3 | PERF-03: Replace CONNECT BY with recursive CTE | 2 days | Slow org chart |
| 4 | PERF-06: Bulk payroll processing | 1 week | Slow payroll runs |
| 5 | ARCH-02: Migrate UTL_FILE integrations to REST/AQ | 2 weeks | Silent data loss |
| 6 | DRIFT-03/04: Consolidate all validation to single layer | 1 week | Maintenance burden |
| 7 | SEC-08: Externalize SMTP config from package constants | 1 day | Portability |
| 8 | ARCH-04: Read fiscal year config from SYSTEM_PARAMETERS | 0.5 day | Configuration rigidity |
| 9 | PERF-05: Add CACHE to high-volume sequences | 0.5 day | Sequence contention |
| 10 | CIRC-01: Break PKG_EMPLOYEE <-> PKG_PAYROLL cycle | 2 days | Compilation fragility |

### Phase 4: Full Modernization (6-12 months)

| Priority | Item | Effort | Description |
|----------|------|--------|-------------|
| 1 | Migrate Forms to modern web framework | 3-6 months | APEX, React, or Angular frontend |
| 2 | Implement proper session management (JWT/OAuth) | 1 month | Replace USER_SESSIONS pattern |
| 3 | Add 2FA/SSO (SEC-10) | 2 weeks | Enterprise SSO integration |
| 4 | Replace PL/SQL business logic with microservices | 3-6 months | API-first architecture |
| 5 | Implement event-driven integration (replace flat files) | 1 month | Real-time GL/benefits sync |
| 6 | Add comprehensive automated testing | 2 months | utPLSQL or similar framework |

---

## Appendix A: Finding Index

| ID | Severity | Category | File | Line(s) |
|---|---|---|---|---|
| SEC-01 | CRITICAL | Security | PKG_SECURITY.pkb | 17-24 |
| SEC-02 | CRITICAL | Security | PKG_SECURITY.pkb | 7 |
| SEC-03 | CRITICAL | Security | PKG_EMPLOYEE.pkb | 457-494 |
| SEC-04 | CRITICAL | Security | PKG_SECURITY.pkb | 14-24, 211-234 |
| SEC-05 | HIGH | Security | PKG_SECURITY.pkb | 30-80 |
| SEC-06 | HIGH | Security | PKG_SECURITY.pkb | 41-57 |
| SEC-07 | HIGH | Security | PKG_INTEGRATION.pks | 12 |
| SEC-08 | MEDIUM | Security | PKG_NOTIFICATION.pkb | 7-10 |
| SEC-09 | MEDIUM | Security | PKG_SECURITY.pkb | 217-228 |
| SEC-10 | LOW | Security | PKG_SECURITY.pks | (entire auth flow) |
| RACE-01 | HIGH | Race Condition | PKG_EMPLOYEE.pkb | 39-55 |
| RACE-02 | HIGH | Race Condition | PKG_PAYROLL.pkb | 240-243 |
| PERF-01 | MEDIUM | Performance | PKG_LEAVE.pkb | 12-40 |
| PERF-02 | MEDIUM | Performance | PKG_COMMON.pkb | 132-146 |
| PERF-03 | MEDIUM | Performance | PKG_EMPLOYEE.pkb | 828-837 |
| PERF-04 | MEDIUM | Performance | PKG_NOTIFICATION.pkb | 88-107 |
| PERF-05 | LOW | Performance | hrms_sequences.sql | 9-48 |
| PERF-06 | MEDIUM | Performance | PKG_PAYROLL.pkb | 296-327 |
| DRIFT-01 | HIGH | Validation Drift | HRMS_VALIDATION_LIB.pll.sql / PKG_COMMON.pkb | 21-41 / 265-268 |
| DRIFT-02 | HIGH | Validation Drift | HRMS_VALIDATION_LIB.pll.sql / PKG_COMMON.pkb | 69-90 / 277-280 |
| DRIFT-03 | MEDIUM | Validation Drift | HRMS_VALIDATION_LIB.pll.sql / PKG_VALIDATION.pkb | 108-135 / 17-48 |
| DRIFT-04 | MEDIUM | Validation Drift | HRMS_VALIDATION_LIB.pll.sql / PKG_VALIDATION.pkb | 96-99 / 71-76 |
| CIRC-01 | MEDIUM | Circular Dependency | PKG_EMPLOYEE.pkb / PKG_PAYROLL.pkb | 273-281 / various |
| ARCH-01 | MEDIUM | Architecture | PKG_AUDIT.pkb, PKG_COMMON.pkb, PKG_EMPLOYEE.pkb, PKG_NOTIFICATION.pkb | 14, 16/46, 155, 27 |
| ARCH-02 | MEDIUM | Architecture | PKG_PAYROLL.pkb, PKG_INTEGRATION.pkb | 826-894, 16-194 |
| ARCH-03 | HIGH | Architecture | PKG_PAYROLL.pkb | 606-677 |
| ARCH-04 | MEDIUM | Architecture | PKG_COMMON.pkb | 170-179 |
| ARCH-05 | LOW | Architecture | PKG_EMPLOYEE.pkb, PKG_INTEGRATION.pkb, PKG_REPORTING.pkb | 737-739, 170-171, 196-204 |
| ARCH-06 | MEDIUM | Architecture | PKG_REPORTING.pks | 9 |
| DATA-01 | CRITICAL | Data Integrity | trg_employees.sql / 01_core_tables.sql | 78-110 / 152-177 |
| DATA-02 | CRITICAL | Data Integrity | trg_audit.sql / 04_performance_tables.sql | 54 / 104 |
| DATA-03 | CRITICAL | Data Integrity | 01_reference_data.sql / schema DDL | 11, 23 |
| DATA-04 | HIGH | Data Integrity | hrms_views.sql / 03_leave_tables.sql | 96-97 / 47 |
| DATA-05 | HIGH | Data Integrity | PKG_LEAVE.pkb | 610-623 |
| DATA-06 | HIGH | Data Integrity | PKG_PAYROLL.pkb | 322-327 |
| DATA-07 | LOW | Data Integrity | trg_employees.sql | 120-129 |
| OBS-01 | MEDIUM | Observation | hrms_views.sql | 121-125 |
| OBS-02 | LOW | Observation | PKG_LEAVE.pkb | 9-10 |
