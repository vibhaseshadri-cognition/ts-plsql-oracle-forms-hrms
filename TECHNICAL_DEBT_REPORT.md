# Technical Debt Report — HRMS Oracle Forms / PL/SQL

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Generated:** 2026-06-22
**Platform:** Oracle Database 19c · Oracle Forms 12c · PL/SQL

---

## Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 6     |
| HIGH     | 12    |
| MEDIUM   | 14    |
| LOW      | 4     |
| **Total**| **36**|

### Category Breakdown

| Category                    | CRITICAL | HIGH | MEDIUM | LOW | Total |
|-----------------------------|----------|------|--------|-----|-------|
| Security Vulnerabilities    | 4        | 2    | 2      | 1   | 9     |
| Race Conditions             | 0        | 2    | 0      | 0   | 2     |
| Performance Issues          | 0        | 1    | 5      | 0   | 6     |
| Validation Drift            | 0        | 2    | 1      | 1   | 4     |
| Circular Dependencies       | 0        | 1    | 0      | 0   | 1     |
| Architectural Anti-Patterns | 0        | 1    | 4      | 1   | 6     |
| Data Integrity Risks        | 2        | 3    | 2      | 1   | 8     |

The most urgent items are the **trigger-to-DDL column mismatches** (DATA-01) and the **audit constraint violation** (DATA-06), which will cause runtime ORA errors in production. Security findings (hard-coded encryption key, MD5 hashing, SQL injection) require immediate remediation to meet compliance standards.

---

## 1. Security Vulnerabilities

### SEC-01 — MD5 Password Hashing

| Field | Value |
|-------|-------|
| **ID** | SEC-01 |
| **Severity** | CRITICAL |
| **File** | `plsql/packages/PKG_SECURITY.pkb:17-24` |

```sql
RETURN RAWTOHEX(
    DBMS_CRYPTO.HASH(
        UTL_RAW.CAST_TO_RAW(p_password),
        DBMS_CRYPTO.HASH_MD5
    )
);
```

**Description:** Password hashing uses MD5 (`DBMS_CRYPTO.HASH_MD5`), which is cryptographically broken. Collision attacks are trivial and rainbow tables are widely available.

**Impact:** An attacker with read access to the database can recover plaintext passwords in seconds. Regulatory non-compliance (PCI-DSS, SOC 2).

**Recommendation:** Replace with `DBMS_CRYPTO.HASH_SH512` at minimum, or use a salted key-derivation function (PBKDF2 via `DBMS_CRYPTO.MAC`) with per-user random salt. Migrate all existing password hashes.

---

### SEC-02 — Hard-Coded Encryption Key

| Field | Value |
|-------|-------|
| **ID** | SEC-02 |
| **Severity** | CRITICAL |
| **File** | `plsql/packages/PKG_SECURITY.pkb:7` |

```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```

**Description:** The AES-256 encryption key used for SSN encryption/decryption is hard-coded in the package body source. Anyone with `SELECT ANY SOURCE` or access to the source repo can read it.

**Impact:** All encrypted SSNs in `EMPLOYEES.SSN_ENCRYPTED` and `EMPLOYEE_DEPENDENTS.SSN_ENCRYPTED` are effectively stored in cleartext. PII breach risk affecting every employee record.

**Recommendation:** Move the key to an Oracle Wallet (`DBMS_CRYPTO` wallet integration) or external key management service. Rotate the key and re-encrypt all SSN values.

---

### SEC-03 — No Account Lockout / Brute-Force Protection

| Field | Value |
|-------|-------|
| **ID** | SEC-03 |
| **Severity** | HIGH |
| **File** | `plsql/packages/PKG_SECURITY.pkb:30-80` |

```sql
FUNCTION authenticate(
    p_username   IN VARCHAR2,
    p_password   IN VARCHAR2,
    p_ip_address IN VARCHAR2 DEFAULT NULL
) RETURN NUMBER IS
    -- No failed-attempt counter, no lockout threshold
```

**Description:** The `authenticate` function has no failed-login counter, no lockout after N failures, and no rate limiting. An attacker can issue unlimited login attempts.

**Impact:** Combined with SEC-01 (weak hashing), brute-force and credential-stuffing attacks are trivially feasible.

**Recommendation:** Add a `FAILED_LOGIN_COUNT` and `LAST_FAILED_LOGIN` column to `USER_SESSIONS` or a separate `LOGIN_ATTEMPTS` table. Lock accounts after 5 consecutive failures with a 15-minute cooldown.

---

### SEC-04 — Timing Attack in Authentication

| Field | Value |
|-------|-------|
| **ID** | SEC-04 |
| **Severity** | HIGH |
| **File** | `plsql/packages/PKG_SECURITY.pkb:41-57` |

```sql
BEGIN
    SELECT EMP_ID INTO v_emp_id
    FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username)
    AND EMPLOYMENT_STATUS = 'ACTIVE';
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        -- Returns immediately for invalid user
        RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
```

**Description:** When the username does not exist, the function raises an error immediately. When the username exists but the password is wrong, additional processing occurs first. An attacker can measure response times to enumerate valid usernames.

**Impact:** Username enumeration enables targeted attacks against known-valid accounts.

**Recommendation:** Perform a constant-time hash comparison regardless of whether the user exists. Always hash the provided password before checking the result.

---

### SEC-05 — SQL Injection in Employee Search

| Field | Value |
|-------|-------|
| **ID** | SEC-05 |
| **Severity** | CRITICAL |
| **File** | `plsql/packages/PKG_EMPLOYEE.pkb:465-483` |

```sql
IF p_last_name IS NOT NULL THEN
    v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
END IF;
IF p_first_name IS NOT NULL THEN
    v_sql := v_sql || 'AND UPPER(e.FIRST_NAME) LIKE UPPER(''' || p_first_name || '%'') ';
END IF;
    ...
    v_sql := v_sql || 'AND e.EMPLOYMENT_STATUS = ''' || p_status || ''' ';
```

**Description:** `search_employees` constructs dynamic SQL by concatenating user-supplied parameters (`p_last_name`, `p_first_name`, `p_status`) directly into the query string without bind variables.

**Impact:** Full SQL injection — an attacker can read, modify, or delete any data in the HRMS schema, including salary records and encrypted SSNs.

**Recommendation:** Replace string concatenation with `DBMS_SQL` bind variables or `EXECUTE IMMEDIATE ... USING` syntax:
```sql
v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(:p_last_name || ''%'') ';
```

---

### SEC-06 — Cleartext Password Transmission

| Field | Value |
|-------|-------|
| **ID** | SEC-06 |
| **Severity** | CRITICAL |
| **File** | `plsql/packages/PKG_SECURITY.pkb:30-33` |

```sql
FUNCTION authenticate(
    p_username   IN VARCHAR2,
    p_password   IN VARCHAR2,       -- raw password arrives here
    p_ip_address IN VARCHAR2 DEFAULT NULL
```

**Description:** The `authenticate` function accepts the password as a plain `VARCHAR2` parameter. In Oracle Forms, this means the password traverses the Forms-to-database Net8 connection in cleartext unless Oracle Net encryption (ASO) is explicitly configured.

**Impact:** Network sniffing on the internal network exposes every user's password during login.

**Recommendation:** Enforce Oracle Advanced Security (ASO) network encryption (`SQLNET.ENCRYPTION_SERVER = REQUIRED`) or migrate to TLS-wrapped connections. Consider client-side hashing as defense-in-depth.

---

### SEC-07 — Hard-Coded SMTP Credentials

| Field | Value |
|-------|-------|
| **ID** | SEC-07 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_NOTIFICATION.pkb:7-10` |

```sql
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
c_from_name    CONSTANT VARCHAR2(100) := 'HRMS System';
```

**Description:** SMTP server hostname, port, and from-address are hard-coded as package constants. Port 25 with no authentication or TLS indicates an open relay configuration. The values already exist in `SYSTEM_PARAMETERS` (seed rows 7-8) but are not read at runtime.

**Impact:** Changing SMTP configuration requires a code change and package recompilation. The open relay can be abused for email spoofing.

**Recommendation:** Replace constants with calls to `PKG_COMMON.get_param('NOTIFICATION', 'SMTP_HOST')`, etc. Add STARTTLS and SMTP AUTH support via `UTL_SMTP` extensions.

---

### SEC-08 — No Multi-Factor Authentication

| Field | Value |
|-------|-------|
| **ID** | SEC-08 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_SECURITY.pkb:30-80` |

**Description:** Authentication is single-factor (username + password) with no MFA, no CAPTCHA, and no device fingerprinting. Combined with the MD5 hashing and lack of lockout, the attack surface is very broad.

**Impact:** Regulatory non-compliance for systems handling PII/payroll data. Modern security frameworks (NIST 800-63B) require MFA for privileged access.

**Recommendation:** Integrate TOTP-based MFA or SSO delegation (SAML/OIDC) for the next-generation authentication layer.

---

### SEC-09 — Weak Password Complexity Requirements

| Field | Value |
|-------|-------|
| **ID** | SEC-09 |
| **Severity** | LOW |
| **File** | `plsql/packages/PKG_SECURITY.pkb:217-228` |

```sql
IF LENGTH(p_new_password) < 8 THEN ...
IF NOT REGEXP_LIKE(p_new_password, '[A-Z]') THEN ...
IF NOT REGEXP_LIKE(p_new_password, '[0-9]') THEN ...
```

**Description:** Password policy requires only 8 characters, one uppercase letter, and one digit. No special character requirement, no password history check, no dictionary/breach check.

**Impact:** Passwords like `Password1` satisfy the policy. Low entropy passwords are vulnerable to dictionary attacks especially given MD5 hashing (SEC-01).

**Recommendation:** Require minimum 12 characters, at least one special character, and implement a password history table to prevent reuse. Consider checking against HaveIBeenPwned-style breach lists.

---

## 2. Race Conditions

### RACE-01 — Employee Number Generation (MAX+1 Pattern)

| Field | Value |
|-------|-------|
| **ID** | RACE-01 |
| **Severity** | HIGH |
| **File** | `plsql/packages/PKG_EMPLOYEE.pkb:39-48` |

```sql
FUNCTION generate_emp_number RETURN VARCHAR2 IS
    v_max_num NUMBER;
BEGIN
    SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
    INTO v_max_num
    FROM EMPLOYEES
    WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
    v_new_number := c_emp_number_prefix || '-' || LPAD(v_max_num, 6, '0');
```

**Description:** Employee number generation uses `MAX()+1` on the `EMPLOYEES` table without `FOR UPDATE` locking. A dedicated sequence `SEQ_EMP_NUMBER` exists (see `schema/sequences/hrms_sequences.sql:21`) but is unused.

**Impact:** Two concurrent `create_employee` calls can generate the same `EMP_NUMBER`, violating the `UK_EMP_NUMBER` unique constraint. This causes one hire transaction to fail with an unhandled ORA-00001 error.

**Recommendation:** Replace the MAX+1 pattern with `SEQ_EMP_NUMBER.NEXTVAL`:
```sql
v_new_number := c_emp_number_prefix || '-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0');
```

---

### RACE-02 — Leave Carryover Expiry Non-Idempotent

| Field | Value |
|-------|-------|
| **ID** | RACE-02 |
| **Severity** | HIGH |
| **File** | `plsql/packages/PKG_LEAVE.pkb:610-623` |

```sql
PROCEDURE expire_carryover(p_user IN VARCHAR2 DEFAULT USER) IS
BEGIN
    UPDATE LEAVE_BALANCES SET
        ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
        CARRYOVER_FROM_PREV = 0,
        MODIFIED_BY = p_user,
        MODIFIED_DATE = SYSDATE
    WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE)
    AND CARRYOVER_FROM_PREV > 0;
    COMMIT;
END expire_carryover;
```

**Description:** The `expire_carryover` procedure subtracts `CARRYOVER_FROM_PREV` from `ADJUSTMENT` and then sets `CARRYOVER_FROM_PREV` to 0. If the scheduler job fires twice on the same day (or if two sessions run concurrently), the first UPDATE subtracts the carryover amount, and the second UPDATE sees `CARRYOVER_FROM_PREV > 0` before the first commits, causing a double subtraction.

**Impact:** Employees lose twice their carryover balance, causing incorrect leave available calculations and payroll downstream errors.

**Recommendation:** Make the operation idempotent by adding a processed flag or checking that `ADJUSTMENT` hasn't already been decremented:
```sql
WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE)
AND CARRYOVER_FROM_PREV > 0
AND MODIFIED_DATE < TRUNC(SYSDATE)  -- only process once per day
```
Or use `SELECT ... FOR UPDATE SKIP LOCKED` to prevent concurrent execution.

---

## 3. Performance Issues

### PERF-01 — Day-by-Day Leave Calculation Loop

| Field | Value |
|-------|-------|
| **ID** | PERF-01 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_LEAVE.pkb:21-35` |

```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count
        FROM HOLIDAYS
        WHERE HOLIDAY_DATE = v_date
        AND ACTIVE_FLAG = 'Y'
        AND (LOCATION_CODE IS NULL OR LOCATION_CODE = p_location_code);
        IF v_holiday_count = 0 THEN
            v_count := v_count + 1;
        END IF;
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Description:** `calculate_business_days` iterates day-by-day, executing a `SELECT COUNT(*)` against `HOLIDAYS` for every single date. A 30-day leave request triggers 30 separate SQL statements.

**Impact:** O(n) queries per leave request. For bulk operations (annual accrual runs across hundreds of employees), this compounds to thousands of context switches.

**Recommendation:** Replace with set-based arithmetic:
```sql
-- Weekdays = total_days - weekend_days
-- Then subtract holidays in range via single query
SELECT COUNT(*) INTO v_holidays
FROM HOLIDAYS
WHERE HOLIDAY_DATE BETWEEN p_start AND p_end
AND TO_CHAR(HOLIDAY_DATE,'DY') NOT IN ('SAT','SUN')
AND ACTIVE_FLAG = 'Y';
```

---

### PERF-02 — Duplicate Day-by-Day Loop in PKG_COMMON

| Field | Value |
|-------|-------|
| **ID** | PERF-02 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_COMMON.pkb:139-146` |

```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        v_count := v_count + 1;
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Description:** `PKG_COMMON.business_days_between` uses the same day-by-day iteration pattern as `PKG_LEAVE.calculate_business_days` but without holiday checking. Logic is duplicated and both implementations are O(n).

**Impact:** Code duplication increases maintenance burden. Both need the same fix.

**Recommendation:** Consolidate into a single set-based function in `PKG_COMMON` and have `PKG_LEAVE` call it with an additional holiday exclusion.

---

### PERF-03 — CONNECT BY Hierarchical Query Scalability

| Field | Value |
|-------|-------|
| **ID** | PERF-03 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_EMPLOYEE.pkb:834-837`, `schema/views/hrms_views.sql:47-57` |

```sql
START WITH EMP_ID = p_root_emp_id
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
AND LEVEL <= p_max_depth
ORDER SIBLINGS BY LAST_NAME, FIRST_NAME;
```

**Description:** Both `PKG_EMPLOYEE.get_org_tree` and `VW_ORG_HIERARCHY` use `CONNECT BY` for hierarchical traversal. The view has no depth limit. Comments document known timeout with >500 employees.

**Impact:** Org chart rendering and reporting queries timeout or consume excessive PGA memory as headcount grows.

**Recommendation:** Replace with recursive CTE (`WITH RECURSIVE`) which the optimizer handles more efficiently, or materialize the hierarchy into a closure table refreshed on org changes.

---

### PERF-04 — SMTP Connection Per Notification in Loop

| Field | Value |
|-------|-------|
| **ID** | PERF-04 |
| **Severity** | HIGH |
| **File** | `plsql/packages/PKG_NOTIFICATION.pkb:88-107` |

```sql
FOR notif_rec IN (...) LOOP
    BEGIN
        v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
        UTL_SMTP.HELO(v_connection, c_smtp_host);
        ...
        UTL_SMTP.QUIT(v_connection);
```

**Description:** `process_queue` opens and closes a new SMTP connection for every notification in the batch. Each TCP handshake + HELO exchange adds ~100-500ms of latency.

**Impact:** Processing 50 notifications takes 5-25 seconds of pure connection overhead. During peak events (e.g., annual review notifications), this causes queue backup and delivery delays.

**Recommendation:** Open one SMTP connection before the loop, send all messages, then close:
```sql
v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
FOR notif_rec IN (...) LOOP
    UTL_SMTP.MAIL(v_connection, c_from_address);
    ...
END LOOP;
UTL_SMTP.QUIT(v_connection);
```

---

### PERF-05 — All Sequences Use NOCACHE

| Field | Value |
|-------|-------|
| **ID** | PERF-05 |
| **Severity** | MEDIUM |
| **File** | `schema/sequences/hrms_sequences.sql:9-48` |

```sql
CREATE SEQUENCE HRMS.SEQ_DEPARTMENT  START WITH 100 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE HRMS.SEQ_EMPLOYEE    START WITH 10000 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE HRMS.SEQ_PAYROLL_DETAIL START WITH 1 INCREMENT BY 1 NOCACHE;
-- ... 22 of 23 sequences use NOCACHE (only SEQ_AUDIT uses CACHE 100)
```

**Description:** 22 out of 23 sequences are defined with `NOCACHE`, requiring a data dictionary update for every `.NEXTVAL` call. Only `SEQ_AUDIT` has `CACHE 100`.

**Impact:** Under concurrent payroll processing, `SEQ_PAYROLL_DETAIL` becomes a serialization bottleneck causing enqueue waits (`row cache lock`). Each employee generates ~10 detail rows per payroll run.

**Recommendation:** Add `CACHE 20` (or higher for high-volume sequences like `SEQ_PAYROLL_DETAIL CACHE 100`) to all sequences:
```sql
ALTER SEQUENCE HRMS.SEQ_PAYROLL_DETAIL CACHE 100;
```

---

### PERF-06 — Row-by-Row Cursor Loop in Payroll Calculation

| Field | Value |
|-------|-------|
| **ID** | PERF-06 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_PAYROLL.pkb:296-327` |

```sql
FOR emp_rec IN (
    SELECT e.EMP_ID FROM EMPLOYEES e
    WHERE e.EMPLOYMENT_STATUS = 'ACTIVE' AND e.ACTIVE_FLAG = 'Y'
    ORDER BY e.EMP_ID
) LOOP
    calculate_employee_pay(p_run_id, emp_rec.EMP_ID, v_period_id, p_user);
    ...
    IF MOD(v_emp_count, 50) = 0 THEN
        COMMIT;
    END IF;
END LOOP;
```

**Description:** Payroll calculation iterates employee-by-employee in a cursor loop, calling `calculate_employee_pay` per row. Also commits every 50 employees mid-loop (see ARCH-06 for the integrity implications).

**Impact:** For 1000 employees, this produces ~10,000+ individual SQL statements (each employee triggers multiple pay element calculations). Bulk processing would reduce context switches by 10-100x.

**Recommendation:** Refactor to use `BULK COLLECT` with `FORALL` for the pay detail inserts. Even if per-employee calculation logic remains procedural, batch the DML.

---

## 4. Validation Drift

### DRIFT-01 — Email Validation: Client vs. Server

| Field | Value |
|-------|-------|
| **ID** | DRIFT-01 |
| **Severity** | HIGH |
| **File (Client)** | `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41` |
| **File (Server)** | `plsql/packages/PKG_COMMON.pkb:265-268` |

Client-side (Forms PLL):
```sql
v_at_pos := INSTR(p_email, '@');
v_dot_pos := INSTR(p_email, '.', v_at_pos);
-- Only checks for one dot after @, rejects valid subdomains
```

Server-side (PKG_COMMON):
```sql
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

**Description:** The client-side PLL validates email by checking for a single `@` and a single `.` after it using `INSTR`. It rejects valid addresses with subdomains (e.g., `user@mail.company.com`). The server-side uses a proper regex that accepts these addresses.

**Impact:** Users with subdomain email addresses get a validation error in the form but the value would be accepted by the server. This causes user confusion and support tickets.

**Recommendation:** Replace the PLL validation with a regex equivalent to the server-side pattern, or call the server-side `PKG_COMMON.is_valid_email` directly from the form via database procedure call.

---

### DRIFT-02 — Salary Range Enforcement Asymmetry

| Field | Value |
|-------|-------|
| **ID** | DRIFT-02 |
| **Severity** | HIGH |
| **File (Client)** | `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:108-135` |
| **File (Server)** | `plsql/packages/PKG_EMPLOYEE.pkb` (hire/promote procedures) |

Client-side:
```sql
IF p_salary < v_min THEN
    RETURN 'Below minimum (' || TO_CHAR(v_min, 'FM$999,999') || ')';
ELSIF p_salary > v_max THEN
    RETURN 'Exceeds maximum (' || TO_CHAR(v_max, 'FM$999,999') || ')';
END IF;
```

**Description:** The Forms PLL returns a hard error message when salary is outside the grade range. The server-side packages log a warning but allow the salary to proceed (no hard block). This means out-of-range salaries can be saved through any non-Forms interface (e.g., batch loads, direct SQL).

**Impact:** Salary data outside grade ranges creates compensation reporting anomalies and compa-ratio outliers.

**Recommendation:** Add server-side enforcement in `PKG_PAYROLL.create_salary_record` that raises an exception (matching the client behavior) unless an override flag is explicitly set by authorized users.

---

### DRIFT-03 — Date Range Validation Inconsistency

| Field | Value |
|-------|-------|
| **ID** | DRIFT-03 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_VALIDATION.pks:10-13`, `plsql/packages/PKG_LEAVE.pkb` |

**Description:** `PKG_VALIDATION.validate_date_range` (per its spec) validates that both dates are non-NULL and that start <= end. Leave request validation in `PKG_LEAVE` only checks `start_date > end_date` but does not reject NULL dates. This means NULL start/end dates can slip through the leave module while other modules would reject them.

**Impact:** Potential for leave requests with NULL dates entering the system through code paths that skip `PKG_VALIDATION`.

**Recommendation:** Standardize all date range checks to call `PKG_VALIDATION.validate_date_range` and add NOT NULL enforcement.

---

### DRIFT-04 — SSN Validation Depth Mismatch

| Field | Value |
|-------|-------|
| **ID** | DRIFT-04 |
| **Severity** | LOW |
| **File (Client)** | `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:69-90` |
| **File (Server)** | `plsql/packages/PKG_COMMON.pkb:277-280` |

Client-side:
```sql
IF SUBSTR(v_digits, 1, 3) = '000' OR
   SUBSTR(v_digits, 4, 2) = '00' OR
   SUBSTR(v_digits, 6, 4) = '0000' THEN
    RETURN FALSE;
END IF;
```

Server-side:
```sql
RETURN REGEXP_LIKE(REGEXP_REPLACE(p_ssn, '[^0-9]', ''), '^\d{9}$');
```

**Description:** Client-side validates SSN structure (9 digits) AND checks for invalid all-zero groups per IRS rules. Server-side only validates 9-digit format.

**Impact:** Invalid SSNs like `000-12-3456` pass server-side validation but are rejected client-side. Low severity since SSNs are stored encrypted and rarely entered outside Forms.

**Recommendation:** Add the zero-group check to the server-side validation function.

---

## 5. Circular Dependencies

### CIRC-01 — PKG_EMPLOYEE ↔ PKG_PAYROLL Cycle

| Field | Value |
|-------|-------|
| **ID** | CIRC-01 |
| **Severity** | HIGH |
| **File** | `plsql/packages/PKG_EMPLOYEE.pkb:273-281`, `plsql/packages/PKG_EMPLOYEE.pks:9`, `plsql/packages/PKG_PAYROLL.pks:9` |

```sql
-- PKG_EMPLOYEE.create_employee calls:
PKG_PAYROLL.create_salary_record(
    p_emp_id         => v_emp_id,
    p_effective_date => p_hire_date,
    p_base_salary    => p_base_salary,
    p_change_reason  => 'NEW_HIRE',
    p_user           => p_user
);
-- PKG_PAYROLL in turn calls PKG_EMPLOYEE.is_active for validation
```

**Description:** `PKG_EMPLOYEE` depends on `PKG_PAYROLL` (for salary record creation during hire), and `PKG_PAYROLL` depends on `PKG_EMPLOYEE` (for active-employee validation). Both package specs document this cycle. Oracle resolves this at runtime via late binding, but it creates compilation-order fragility and tight coupling.

**Impact:** Recompiling either package can invalidate the other, causing cascade invalidation. Schema migration scripts must handle compilation order carefully or risk ORA-04068 errors during deployment.

**Recommendation:** Extract the shared interface into a lightweight mediator package (`PKG_HR_FACADE`) or use a callback/event pattern to break the direct dependency.

---

## 6. Architectural Anti-Patterns

### ARCH-01 — Autonomous Transaction Overuse

| Field | Value |
|-------|-------|
| **ID** | ARCH-01 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_AUDIT.pkb:14`, `plsql/packages/PKG_COMMON.pkb:16,46`, `plsql/packages/PKG_NOTIFICATION.pkb:27` |

```sql
PRAGMA AUTONOMOUS_TRANSACTION;
```

**Description:** At least 4 procedures use `PRAGMA AUTONOMOUS_TRANSACTION`: `PKG_AUDIT.log_action`, `PKG_COMMON.log_error`, `PKG_COMMON.log_info`, and `PKG_NOTIFICATION.send_notification`. Each autonomous transaction opens a separate database session, commits independently, and can mask transaction boundaries.

**Impact:** Audit records persist even when the parent transaction rolls back, creating misleading audit trails. Under high concurrency, autonomous transactions compete for latches and increase session count.

**Recommendation:** Justified for audit logging (must survive rollback) but should be reviewed for notifications. Consider piping notifications through Oracle Advanced Queuing (AQ) instead of autonomous transactions.

---

### ARCH-02 — UTL_FILE Flat-File Integration

| Field | Value |
|-------|-------|
| **ID** | ARCH-02 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_INTEGRATION.pkb:16-83,90-147,153-194` |

```sql
v_file := UTL_FILE.FOPEN(c_gl_output_dir, v_filename, 'W', 32767);
```

**Description:** Three integration procedures (`generate_gl_journal`, `export_benefits_feed`, `import_time_attendance`) use `UTL_FILE` to read/write flat files on the database server filesystem. File formats are pipe-delimited and fixed-width, specific to legacy vendor systems.

**Impact:** Requires Oracle directory objects mapped to server filesystems. File-based integration has no transactional guarantees, no retry mechanism, and no real-time capability. Files must be picked up by external batch processes.

**Recommendation:** Migrate to REST API integration using `UTL_HTTP` or Oracle REST Data Services (ORDS). For the GL feed, consider Oracle Financials' native web services.

---

### ARCH-03 — Stub / TODO Implementations

| Field | Value |
|-------|-------|
| **ID** | ARCH-03 |
| **Severity** | MEDIUM |
| **File** | Multiple locations |

| Location | Stub |
|----------|------|
| `PKG_EMPLOYEE.pkb:737` | `-- TODO: Integrate with benefits system to trigger COBRA` |
| `PKG_EMPLOYEE.pkb:738` | `-- TODO: Revoke system access via PKG_SECURITY` |
| `PKG_EMPLOYEE.pkb:739` | `-- TODO: Calculate final pay via PKG_PAYROLL.calculate_final_pay` |
| `PKG_INTEGRATION.pkb:170` | `-- TODO: Implement actual parsing and database update` |
| `PKG_INTEGRATION.pkb:196-203` | `sync_org_structure` is a no-op placeholder |

**Description:** The employee termination workflow is missing COBRA notification, system access revocation, and final pay calculation. The time attendance import reads files but discards all parsed data. The org sync procedure is a complete stub.

**Impact:** Terminated employees may retain system access. COBRA notifications must be sent manually. Time attendance data is silently dropped.

**Recommendation:** Prioritize implementing access revocation (security) and COBRA notification (compliance) in Phase 1. Time attendance parsing and org sync can be addressed in Phase 4.

---

### ARCH-04 — Hard-Coded Tax Brackets (2024)

| Field | Value |
|-------|-------|
| **ID** | ARCH-04 |
| **Severity** | MEDIUM |
| **File** | `plsql/packages/PKG_PAYROLL.pkb:643-677` |

```sql
-- 2024 Federal tax brackets (Single)
-- TODO: Read from TAX_BRACKETS table instead of hard-coding
IF p_filing_status = 'SINGLE' OR p_filing_status = 'MARRIED_SEPARATE' THEN
    IF v_taxable <= 11600 THEN
        v_tax := v_taxable * 0.10;
    ELSIF v_taxable <= 47150 THEN
        v_tax := 1160 + (v_taxable - 11600) * 0.12;
```

**Description:** Federal tax bracket thresholds and rates for 2024 are hard-coded across 35 lines of IF/ELSIF logic for both SINGLE and MARRIED_JOINT filing statuses. A `TAX_BRACKETS` table exists in the schema (`schema/tables/02_payroll_tables.sql:159-173`) but is never queried.

**Impact:** Every year requires a code change, recompilation, and deployment to update tax brackets. Missing the update causes incorrect tax withholding for all employees.

**Recommendation:** Refactor to query the `TAX_BRACKETS` table:
```sql
FOR bracket IN (
    SELECT BRACKET_MIN, BRACKET_MAX, TAX_RATE, BASE_TAX
    FROM TAX_BRACKETS
    WHERE TAX_YEAR = v_year AND FILING_STATUS = p_filing_status
    ORDER BY BRACKET_MIN
) LOOP ...
```

---

### ARCH-05 — Hard-Coded Fiscal Year (October 1)

| Field | Value |
|-------|-------|
| **ID** | ARCH-05 |
| **Severity** | LOW |
| **File** | `plsql/packages/PKG_COMMON.pkb:170-179` |

```sql
FUNCTION get_fiscal_year(p_date IN DATE DEFAULT SYSDATE) RETURN NUMBER IS
BEGIN
    IF EXTRACT(MONTH FROM p_date) >= 10 THEN
        RETURN EXTRACT(YEAR FROM p_date) + 1;
    ELSE
        RETURN EXTRACT(YEAR FROM p_date);
    END IF;
END get_fiscal_year;
```

**Description:** Fiscal year start month (October) is hard-coded. A `SYSTEM_PARAMETERS` row exists (`FISCAL_YEAR_START = '10'`, seed row 4) but is not consulted.

**Impact:** If the organization changes its fiscal year, code changes are required in `PKG_COMMON` and `PKG_REPORTING`.

**Recommendation:** Read from `SYSTEM_PARAMETERS`:
```sql
v_fy_start := PKG_COMMON.get_param_number('PAYROLL', 'FISCAL_YEAR_START');
```

---

### ARCH-06 — Partial COMMIT in Batch Processing

| Field | Value |
|-------|-------|
| **ID** | ARCH-06 |
| **Severity** | HIGH |
| **File** | `plsql/packages/PKG_PAYROLL.pkb:322-326`, `plsql/packages/PKG_LEAVE.pkb:543-545` |

```sql
-- PKG_PAYROLL: commits every 50 employees
IF MOD(v_emp_count, 50) = 0 THEN
    COMMIT;
END IF;
```

**Description:** Payroll calculation commits every 50 employees. If the process fails at employee #75, the first 50 are committed and cannot be rolled back. The same pattern exists in leave accrual processing (every 100 employees).

**Impact:** A mid-run failure leaves payroll in an inconsistent state: some employees calculated, others not. The `PAYROLL_RUNS.STATUS` may show `CALCULATING` permanently. Manual cleanup is required.

**Recommendation:** Remove mid-loop commits. Use savepoints instead:
```sql
SAVEPOINT before_emp;
BEGIN
    calculate_employee_pay(...);
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK TO before_emp;
        -- log error, continue
END;
```
Commit once at the end after all employees are processed.

---

## 7. Data Integrity Risks

### DATA-01 — Trigger Column Mismatch vs. DDL (CRITICAL)

| Field | Value |
|-------|-------|
| **ID** | DATA-01 |
| **Severity** | CRITICAL |
| **File (Trigger)** | `plsql/triggers/trg_employees.sql:78-110` |
| **File (DDL)** | `schema/tables/01_core_tables.sql:152-177` |

Trigger inserts:
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

DDL defines:
```sql
CREATE TABLE HRMS.EMPLOYEE_HISTORY (
    HIST_ID         NUMBER(15)    NOT NULL,   -- trigger uses HISTORY_ID
    EMP_ID          NUMBER(10)    NOT NULL,
    CHANGE_TYPE     VARCHAR2(30)  NOT NULL,
    EFFECTIVE_DATE  DATE          NOT NULL,   -- trigger uses CHANGE_DATE
    OLD_DEPT_ID     NUMBER(10),               -- trigger uses OLD_VALUE
    NEW_DEPT_ID     NUMBER(10),               -- trigger uses NEW_VALUE
    ...
    CREATED_BY      VARCHAR2(30)  NOT NULL,   -- trigger uses CHANGED_BY
    ...
    REASON_CODE     VARCHAR2(30),             -- trigger uses CHANGE_REASON
);
```

**Description:** `TRG_EMP_BEFORE_UPDATE` references 6 columns that do not exist in the `EMPLOYEE_HISTORY` table DDL:

| Trigger Column | Actual DDL Column |
|---------------|-------------------|
| `HISTORY_ID`  | `HIST_ID`         |
| `CHANGE_DATE` | `EFFECTIVE_DATE`  |
| `OLD_VALUE`   | `OLD_DEPT_ID` (structured columns) |
| `NEW_VALUE`   | `NEW_DEPT_ID` (structured columns) |
| `CHANGED_BY`  | `CREATED_BY`      |
| `CHANGE_REASON` | `REASON_CODE`   |

**Impact:** **The trigger will raise ORA-00904 ("invalid identifier") on every employee status change, department transfer, and job change.** All three INSERT statements in the trigger (lines 78-86, 89-98, 100-110) use the wrong column names. This means no employee update history is being recorded, and the trigger error may cause UPDATE statements to fail entirely (depending on error handling in calling code).

**Recommendation:** Immediately correct the trigger to match the DDL. Replace all 3 INSERT blocks:
```sql
INSERT INTO EMPLOYEE_HISTORY (
    HIST_ID, EMP_ID, CHANGE_TYPE, EFFECTIVE_DATE,
    OLD_DEPT_ID, NEW_DEPT_ID, CREATED_BY, REASON_CODE
) VALUES (
    SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'STATUS_CHANGE', SYSDATE,
    NULL, NULL, NVL(:NEW.MODIFIED_BY, USER), 'Triggered by status update'
);
```
Also consider whether `CHANGE_TYPE = 'STATUS_CHANGE'` satisfies the CHECK constraint on `CHANGE_TYPE` (it does — the constraint includes `'STATUS_CHANGE'`).

---

### DATA-02 — Audit Log CHECK Constraint vs. Trigger Action Values

| Field | Value |
|-------|-------|
| **ID** | DATA-02 |
| **Severity** | CRITICAL |
| **File (Constraint)** | `schema/tables/04_performance_tables.sql:104` |
| **File (Trigger)** | `plsql/triggers/trg_audit.sql:51-58` |

Constraint:
```sql
CONSTRAINT CHK_AUDIT_ACTION CHECK (ACTION_TYPE IN ('INSERT', 'UPDATE', 'DELETE'))
```

Trigger:
```sql
PKG_AUDIT.log_action(
    'LEAVE_REQUESTS', :NEW.REQUEST_ID,
    'STATUS_CHANGE',   -- violates CHECK constraint
    NVL(:NEW.MODIFIED_BY, USER), ...
);
```

**Description:** The `AUDIT_LOG.ACTION_TYPE` column has a CHECK constraint allowing only `'INSERT'`, `'UPDATE'`, `'DELETE'`. However, `TRG_LEAVE_REQUEST_AUDIT` passes `'STATUS_CHANGE'` as the action type to `PKG_AUDIT.log_action`, which inserts it directly into `ACTION_TYPE`. This will raise ORA-02290 (check constraint violated).

**Impact:** Every leave request status change triggers an audit insert that fails. Because `PKG_AUDIT.log_action` uses `PRAGMA AUTONOMOUS_TRANSACTION` with a `WHEN OTHERS THEN ROLLBACK` handler, the failure is **silently swallowed** — no error is raised but no audit record is created. Leave approval/rejection audit trail is completely missing.

**Recommendation:** Either expand the CHECK constraint:
```sql
ALTER TABLE AUDIT_LOG DROP CONSTRAINT CHK_AUDIT_ACTION;
ALTER TABLE AUDIT_LOG ADD CONSTRAINT CHK_AUDIT_ACTION
    CHECK (ACTION_TYPE IN ('INSERT', 'UPDATE', 'DELETE', 'STATUS_CHANGE', 'LOGIN', 'LOGOUT'));
```
Or change the trigger to pass `'UPDATE'` instead of `'STATUS_CHANGE'` and record the semantic meaning in the JSON payload.

---

### DATA-03 — Seed Data Column Name Mismatches

| Field | Value |
|-------|-------|
| **ID** | DATA-03 |
| **Severity** | HIGH |
| **File (Seed)** | `data/seed/01_reference_data.sql` |
| **File (DDL)** | `schema/tables/01_core_tables.sql`, `schema/tables/04_performance_tables.sql` |

| Seed SQL Line | Column Used | Actual DDL Column | Table |
|--------------|------------|-------------------|-------|
| Line 11-18 | `PHONE` | `PHONE_NUMBER` | `LOCATIONS` |
| Line 23-42 | `GRADE_LEVEL` | *(does not exist)* | `JOB_GRADES` |
| Line 23-42 | *(missing)* | `GRADE_CODE` (NOT NULL) | `JOB_GRADES` |
| Line 182-201 | `DESCRIPTION` | `PARAM_DESCRIPTION` | `SYSTEM_PARAMETERS` |

**Description:** The seed data script references column names that don't match the table DDL. The `LOCATIONS` insert uses `PHONE` but the table has `PHONE_NUMBER`. The `JOB_GRADES` insert uses `GRADE_LEVEL` which doesn't exist and omits `GRADE_CODE` which is NOT NULL. The `SYSTEM_PARAMETERS` insert uses `DESCRIPTION` but the table has `PARAM_DESCRIPTION`.

**Impact:** Running the seed script will fail with ORA-00904 errors for every affected INSERT. The database cannot be seeded with reference data without manual correction.

**Recommendation:** Correct all column names in the seed script to match the DDL:
```sql
-- LOCATIONS: PHONE → PHONE_NUMBER
-- JOB_GRADES: GRADE_LEVEL → remove; add GRADE_CODE (required NOT NULL)
-- SYSTEM_PARAMETERS: DESCRIPTION → PARAM_DESCRIPTION
```

---

### DATA-04 — VW_LEAVE_SUMMARY Omits PENDING from Available Balance

| Field | Value |
|-------|-------|
| **ID** | DATA-04 |
| **Severity** | MEDIUM |
| **File (View)** | `schema/views/hrms_views.sql:96-97` |
| **File (DDL)** | `schema/tables/03_leave_tables.sql:47` |

View:
```sql
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,
```

Table virtual column:
```sql
AVAILABLE NUMBER(6,2) GENERATED ALWAYS AS
    (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL,
```

**Description:** The `VW_LEAVE_SUMMARY` view calculates `AVAILABLE` without subtracting `PENDING` leave. The `LEAVE_BALANCES` table's virtual column correctly subtracts `PENDING`. Reports using the view show a higher available balance than the actual table value.

**Impact:** Managers reviewing leave reports via the view see inflated available balances, potentially approving leave requests that would exceed the actual balance.

**Recommendation:** Add `- lb.PENDING` to the view's AVAILABLE calculation to match the table's virtual column formula.

---

### DATA-05 — VW_PAYROLL_LATEST Uses Global MAX Instead of Per-Employee

| Field | Value |
|-------|-------|
| **ID** | DATA-05 |
| **Severity** | MEDIUM |
| **File** | `schema/views/hrms_views.sql:121-125` |

```sql
WHERE pr.RUN_ID = (
    SELECT MAX(pr2.RUN_ID)
    FROM PAYROLL_RUNS pr2
    WHERE pr2.STATUS = 'APPROVED'
)
```

**Description:** The subquery finds the single globally-latest approved payroll run. This means the view only shows employees who were included in that specific run. Employees paid in a different run (e.g., supplemental, different pay frequency) are excluded entirely.

**Impact:** Payroll reports are incomplete — they only reflect the most recent single run rather than each employee's most recent pay.

**Recommendation:** Correlate the subquery to find each employee's latest run:
```sql
WHERE pr.RUN_ID = (
    SELECT MAX(pr2.RUN_ID)
    FROM PAYROLL_RUNS pr2
    JOIN PAYROLL_DETAILS pd2 ON pr2.RUN_ID = pd2.RUN_ID
    WHERE pr2.STATUS = 'APPROVED' AND pd2.EMP_ID = pd.EMP_ID
)
```

---

### DATA-06 — Soft-Delete Trigger Mismatch

| Field | Value |
|-------|-------|
| **ID** | DATA-06 |
| **Severity** | LOW |
| **File** | `plsql/triggers/trg_employees.sql:120-130` |

```sql
-- Named "TRG_EMP_INSTEAD_OF_DELETE" but is actually BEFORE DELETE
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
BEFORE DELETE ON HRMS.EMPLOYEES
FOR EACH ROW
BEGIN
    RAISE_APPLICATION_ERROR(-20504,
        'Direct deletion not allowed. Use termination process or set ACTIVE_FLAG to N.');
END TRG_EMP_INSTEAD_OF_DELETE;
```

**Description:** The trigger is named `TRG_EMP_INSTEAD_OF_DELETE` (suggesting an INSTEAD OF trigger) but is actually a `BEFORE DELETE` trigger on a table (INSTEAD OF triggers only work on views). The trigger simply raises an error, preventing all DELETEs. Comment on line 125 notes that "Forms expects DELETE to succeed" but the trigger blocks it.

**Impact:** Oracle Forms `DELETE_RECORD` triggers an error. The workaround (set `ACTIVE_FLAG = 'N'` then `CLEAR_RECORD`) is documented only in a code comment, not in user-facing documentation. New developers may waste time debugging.

**Recommendation:** Rename the trigger to `TRG_EMP_PREVENT_DELETE` for clarity. Document the soft-delete pattern in the application developer guide.

---

### DATA-07 — EMPLOYEE_HISTORY CHECK Constraint vs. Trigger Values

| Field | Value |
|-------|-------|
| **ID** | DATA-07 |
| **Severity** | HIGH |
| **File (DDL)** | `schema/tables/01_core_tables.sql:173-176` |
| **File (Trigger)** | `plsql/triggers/trg_employees.sql:78-110` |

```sql
CONSTRAINT CHK_CHANGE_TYPE CHECK (CHANGE_TYPE IN (
    'HIRE', 'TRANSFER', 'PROMOTION', 'DEMOTION', 'SALARY_CHANGE',
    'TERMINATION', 'REHIRE', 'LEAVE_START', 'LEAVE_END', 'STATUS_CHANGE'
))
```

Trigger uses: `'STATUS_CHANGE'`, `'DEPARTMENT_CHANGE'`, `'JOB_CHANGE'`

**Description:** The trigger inserts `CHANGE_TYPE` values `'DEPARTMENT_CHANGE'` (line 94) and `'JOB_CHANGE'` (line 104) that are not in the CHECK constraint's allowed list. `'STATUS_CHANGE'` is allowed, but the other two will fail with ORA-02290.

**Impact:** Department transfers and job changes through direct EMPLOYEE table updates will fail, as the trigger INSERT into EMPLOYEE_HISTORY violates the CHECK constraint. Combined with DATA-01 (wrong column names), this trigger is completely non-functional.

**Recommendation:** Expand the CHECK constraint to include all trigger-generated values:
```sql
ALTER TABLE EMPLOYEE_HISTORY DROP CONSTRAINT CHK_CHANGE_TYPE;
ALTER TABLE EMPLOYEE_HISTORY ADD CONSTRAINT CHK_CHANGE_TYPE CHECK (CHANGE_TYPE IN (
    'HIRE', 'TRANSFER', 'PROMOTION', 'DEMOTION', 'SALARY_CHANGE',
    'TERMINATION', 'REHIRE', 'LEAVE_START', 'LEAVE_END', 'STATUS_CHANGE',
    'DEPARTMENT_CHANGE', 'JOB_CHANGE'
));
```

---

### DATA-08 — Trigger Uses EMPLOYEES Email Uniqueness Check with Active-Only Filter

| Field | Value |
|-------|-------|
| **ID** | DATA-08 |
| **Severity** | HIGH |
| **File** | `plsql/triggers/trg_employees.sql:42-54` |

```sql
SELECT COUNT(*) INTO v_count
FROM EMPLOYEES
WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL)
AND ACTIVE_FLAG = 'Y';
```

**Description:** `TRG_EMP_BEFORE_INSERT` checks email uniqueness only among active employees (`ACTIVE_FLAG = 'Y'`). A terminated employee's email can be reused by a new hire. However, Oracle Forms and many queries use `EMAIL` as a login identifier (see `PKG_SECURITY.authenticate` which matches on `EMAIL`). If the terminated employee is later rehired (setting `ACTIVE_FLAG = 'Y'`), there are now two active employees with the same email.

**Impact:** The rehire flow can create a duplicate email scenario that breaks authentication (PKG_SECURITY.authenticate handles `TOO_MANY_ROWS` by using `MIN(EMP_ID)`, silently logging in as the wrong employee).

**Recommendation:** Enforce email uniqueness across all records regardless of status, or use `EMP_ID` instead of `EMAIL` for authentication lookup.

---

## Prioritized Migration Roadmap

### Phase 1 — Critical Security (Weeks 1-4)

| Priority | Item | Finding IDs |
|----------|------|-------------|
| P0 | Fix trigger column mismatches | DATA-01, DATA-07 |
| P0 | Fix audit CHECK constraint | DATA-02 |
| P0 | Fix seed data column names | DATA-03 |
| P0 | Replace MD5 with SHA-512 + salt | SEC-01 |
| P0 | Move encryption key to Oracle Wallet | SEC-02 |
| P0 | Fix SQL injection with bind variables | SEC-05 |
| P1 | Add account lockout mechanism | SEC-03 |
| P1 | Fix timing attack in authentication | SEC-04 |
| P1 | Enforce network encryption (ASO) | SEC-06 |
| P1 | Implement terminated-employee access revocation | ARCH-03 (partial) |

### Phase 2 — Data Integrity (Weeks 5-8)

| Priority | Item | Finding IDs |
|----------|------|-------------|
| P0 | Replace MAX+1 with sequence for emp numbers | RACE-01 |
| P0 | Make carryover expiry idempotent | RACE-02 |
| P0 | Fix VW_LEAVE_SUMMARY PENDING calculation | DATA-04 |
| P0 | Fix VW_PAYROLL_LATEST per-employee scoping | DATA-05 |
| P1 | Fix email uniqueness across all statuses | DATA-08 |
| P1 | Remove mid-loop COMMITs in batch processing | ARCH-06 |
| P1 | Align client/server email validation | DRIFT-01 |
| P1 | Add server-side salary range enforcement | DRIFT-02 |

### Phase 3 — Performance & Architecture (Weeks 9-16)

| Priority | Item | Finding IDs |
|----------|------|-------------|
| P1 | Replace day-by-day loops with set-based logic | PERF-01, PERF-02 |
| P1 | Add CACHE to all sequences | PERF-05 |
| P1 | Open single SMTP connection for batch | PERF-04 |
| P2 | Read SMTP config from SYSTEM_PARAMETERS | SEC-07 |
| P2 | Read tax brackets from TAX_BRACKETS table | ARCH-04 |
| P2 | Read fiscal year from SYSTEM_PARAMETERS | ARCH-05 |
| P2 | Replace CONNECT BY with recursive CTE | PERF-03 |
| P2 | Refactor payroll loop to BULK COLLECT | PERF-06 |

### Phase 4 — Modernization (Weeks 17-24)

| Priority | Item | Finding IDs |
|----------|------|-------------|
| P2 | Break PKG_EMPLOYEE ↔ PKG_PAYROLL cycle | CIRC-01 |
| P2 | Implement MFA / SSO integration | SEC-08 |
| P2 | Strengthen password policy | SEC-09 |
| P2 | Standardize date range validation | DRIFT-03 |
| P2 | Add SSN zero-group check server-side | DRIFT-04 |
| P3 | Migrate UTL_FILE integrations to REST APIs | ARCH-02 |
| P3 | Implement time attendance parsing | ARCH-03 |
| P3 | Review autonomous transaction usage | ARCH-01 |
| P3 | Rename soft-delete trigger | DATA-06 |

---

## Appendix: Files Analyzed

| File | Lines | Category |
|------|-------|----------|
| `plsql/packages/PKG_SECURITY.pkb` | 237 | Security, Auth |
| `plsql/packages/PKG_EMPLOYEE.pkb` | 897+ | Employee mgmt |
| `plsql/packages/PKG_PAYROLL.pkb` | 897 | Payroll |
| `plsql/packages/PKG_LEAVE.pkb` | 673 | Leave mgmt |
| `plsql/packages/PKG_NOTIFICATION.pkb` | 177 | Notifications |
| `plsql/packages/PKG_INTEGRATION.pkb` | 213 | External integration |
| `plsql/packages/PKG_COMMON.pkb` | 283 | Utilities |
| `plsql/packages/PKG_AUDIT.pkb` | 72 | Audit trail |
| `plsql/packages/PKG_VALIDATION.pks` | 47 | Validation spec |
| `plsql/packages/PKG_REPORTING.pks` | 63 | Reporting spec |
| `plsql/triggers/trg_employees.sql` | 130 | Employee triggers |
| `plsql/triggers/trg_audit.sql` | 84 | Audit triggers |
| `forms/libraries/HRMS_VALIDATION_LIB.pll.sql` | 135 | Client validation |
| `forms/libraries/HRMS_COMMON_LIB.pll.sql` | 151 | Client utilities |
| `schema/tables/01_core_tables.sql` | 220 | Core DDL |
| `schema/tables/02_payroll_tables.sql` | 225 | Payroll DDL |
| `schema/tables/03_leave_tables.sql` | 124 | Leave DDL |
| `schema/tables/04_performance_tables.sql` | 182 | Perf/System DDL |
| `schema/views/hrms_views.sql` | 159 | Views |
| `schema/sequences/hrms_sequences.sql` | 49 | Sequences |
| `data/seed/01_reference_data.sql` | 203 | Seed data |
