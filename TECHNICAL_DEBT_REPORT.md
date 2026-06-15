# Technical Debt Report — Oracle Forms 12c HRMS

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Generated:** 2026-06-15
**Scope:** Full codebase analysis across PL/SQL packages, Oracle Forms libraries, schema DDL, views, sequences, and seed data

---

## Executive Summary

This report documents **38 technical debt items** identified across 8 categories in the legacy Oracle Forms/PL/SQL HRMS application. The system manages employee records, payroll, leave, performance reviews, and external integrations for an Oracle Database 19c environment.

### Severity Distribution

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 5     | Immediate security/data-integrity risks requiring urgent remediation |
| HIGH     | 12    | Significant bugs or vulnerabilities with material business impact |
| MEDIUM   | 13    | Performance, maintainability, or correctness issues |
| LOW      | 8     | Code quality, modernization opportunities |

### Category Breakdown

| Category | CRITICAL | HIGH | MEDIUM | LOW | Total |
|----------|----------|------|--------|-----|-------|
| Security Vulnerabilities | 3 | 3 | 1 | 0 | 7 |
| Race Conditions | 1 | 1 | 0 | 0 | 2 |
| Performance Issues | 0 | 2 | 4 | 1 | 7 |
| Validation Drift | 0 | 1 | 2 | 0 | 3 |
| Circular Dependencies | 0 | 1 | 0 | 0 | 1 |
| Architectural Anti-Patterns | 0 | 2 | 2 | 3 | 7 |
| Data Integrity Risks | 1 | 2 | 2 | 1 | 6 |
| Cross-Cutting Concerns | 0 | 0 | 2 | 3 | 5 |

---

## 1. Security Vulnerabilities

### SEC-001: MD5 Password Hashing
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb:13-23`
- **Code:**
  ```sql
  FUNCTION hash_password(p_password IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
      RETURN RAWTOHEX(
          DBMS_CRYPTO.HASH(
              UTL_RAW.CAST_TO_RAW(p_password),
              DBMS_CRYPTO.HASH_MD5
          )
      );
  END hash_password;
  ```
- **Issue:** Passwords are hashed using MD5, which is cryptographically broken. MD5 hashes can be reversed via rainbow tables or brute-forced in seconds on modern hardware.
- **Impact:** If the database is compromised, all employee passwords are trivially recoverable. Violates NIST SP 800-63B and most compliance frameworks (SOC 2, HIPAA, PCI-DSS).
- **Recommendation:** Replace with `DBMS_CRYPTO.HASH_SH512` at minimum, or preferably implement PBKDF2/bcrypt/scrypt via a Java stored procedure. Requires a one-time password reset for all users.

### SEC-002: Hard-Coded Encryption Key
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb:6`
- **Code:**
  ```sql
  c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
  ```
- **Issue:** The AES-256 encryption key used for SSN encryption is hard-coded in the package body source code. Anyone with `SELECT` on `DBA_SOURCE` or access to the repository can read it.
- **Impact:** All encrypted SSN data (`EMPLOYEES.SSN_ENCRYPTED`, `EMPLOYEE_DEPENDENTS.SSN_ENCRYPTED`) can be decrypted by any DBA or developer. This is a PII/compliance violation.
- **Recommendation:** Store the encryption key in Oracle Wallet (`DBMS_CRYPTO` with wallet-managed keys) or an external key management service (e.g., Oracle Key Vault, HashiCorp Vault). Remove the key from source code immediately.

### SEC-003: SQL Injection in Employee Search
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:440-455`
- **Code:**
  ```sql
  IF p_last_name IS NOT NULL THEN
      -- VULNERABILITY: String concatenation instead of bind variable
      v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
  END IF;
  ```
- **Issue:** The `search_employees` procedure builds dynamic SQL using string concatenation for the `p_last_name` parameter. Although Forms LOV passes validated values, the procedure is callable from any PL/SQL context.
- **Impact:** An attacker with EXECUTE privilege on `PKG_EMPLOYEE` can inject arbitrary SQL. This could allow unauthorized data access, data modification, or privilege escalation.
- **Recommendation:** Replace string concatenation with bind variables using `DBMS_SQL` or native dynamic SQL with `USING` clause:
  ```sql
  v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(:p_last_name || ''%'') ';
  ```

### SEC-004: No Account Lockout / Brute-Force Protection
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb:28-50`
- **Code:**
  ```sql
  -- VULNERABILITY: No brute-force protection (no lockout after N failures)
  FUNCTION authenticate(p_username IN VARCHAR2, p_password IN VARCHAR2, ...) RETURN NUMBER IS
  ```
- **Issue:** The `authenticate` function has no failed-attempt tracking or account lockout mechanism. An attacker can make unlimited login attempts.
- **Impact:** Combined with SEC-001 (MD5), credential compromise is highly likely through brute-force or credential-stuffing attacks. The `USER_SESSIONS` table tracks successful logins but not failures.
- **Recommendation:** Add a `FAILED_LOGIN_COUNT` and `LOCKED_UNTIL` column to `EMPLOYEES` (or a separate `LOGIN_ATTEMPTS` table). Lock accounts after 5 failed attempts with exponential backoff.

### SEC-005: Timing Attack in Authentication
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb:46-50`
- **Code:**
  ```sql
  WHEN NO_DATA_FOUND THEN
      -- VULNERABILITY: Timing attack - different response time for
      -- invalid user vs invalid password
      RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
  ```
- **Issue:** When a username is not found, the function raises immediately without computing the password hash. When the username exists but the password is wrong, the hash computation adds measurable latency. This timing difference reveals whether a username exists.
- **Impact:** Enables username enumeration, which is a prerequisite for targeted brute-force attacks.
- **Recommendation:** Always compute the password hash before returning an error, even for non-existent users. Use a constant-time comparison for hash matching.

### SEC-006: Hard-Coded SMTP Configuration
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:6-10`
- **Code:**
  ```sql
  c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
  c_smtp_port    CONSTANT NUMBER := 25;
  c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
  c_from_name    CONSTANT VARCHAR2(100) := 'HRMS System';
  ```
- **Issue:** SMTP configuration is hard-coded in the package body. While the same values exist in `SYSTEM_PARAMETERS` (seed data rows 7-8), the package ignores them. Port 25 implies unencrypted SMTP.
- **Impact:** Configuration changes require recompilation and redeployment. Unencrypted SMTP exposes email content (including employee names and leave/termination details) to network sniffing.
- **Recommendation:** Read SMTP configuration from `SYSTEM_PARAMETERS` at runtime via `PKG_COMMON.get_param`. Migrate to port 587 with STARTTLS (`UTL_SMTP.STARTTLS`).

### SEC-007: Cleartext Password Handling in Memory
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_SECURITY.pkb:13-23, 30-34`
- **Issue:** Passwords are received as `VARCHAR2` parameters and persist in SGA shared memory until overwritten. Oracle does not provide secure memory wiping for PL/SQL variables.
- **Impact:** Database memory dumps or SGA analysis could reveal plaintext passwords. This is a defense-in-depth concern.
- **Recommendation:** Minimize password lifetime in memory. Consider client-side hashing (hash in the Forms client before transmission) so the server never sees the plaintext password.

---

## 2. Race Conditions

### RC-001: Employee Number Generation Race Condition
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:36-54`
- **Code:**
  ```sql
  FUNCTION generate_emp_number RETURN VARCHAR2 IS
      v_max_num NUMBER;
  BEGIN
      SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
      INTO v_max_num
      FROM EMPLOYEES
      WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
      v_new_number := c_emp_number_prefix || '-' || LPAD(v_max_num, 6, '0');
      RETURN v_new_number;
  ```
- **Issue:** Uses `MAX()+1` pattern without `SELECT FOR UPDATE` or any serialization. Two concurrent `create_employee` calls can generate the same employee number, causing a `UK_EMP_NUMBER` constraint violation. The fallback in the `EXCEPTION WHEN OTHERS` block silently switches to `SEQ_EMPLOYEE.NEXTVAL`, producing a different numbering format.
- **Impact:** Under concurrent load, employee creation fails or produces inconsistent employee number formats (e.g., `EMP-000042` vs `EMP-010042`). The sequence `SEQ_EMP_NUMBER` (defined in `schema/sequences/hrms_sequences.sql:21`) exists specifically for this purpose but is bypassed.
- **Recommendation:** Replace `MAX()+1` with `SEQ_EMP_NUMBER.NEXTVAL`:
  ```sql
  RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0');
  ```

### RC-002: Promote Employee Missing FOR UPDATE
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:591-603`
- **Code:**
  ```sql
  SELECT JOB_ID INTO v_old_job_id
  FROM EMPLOYEES
  WHERE EMP_ID = p_emp_id;
  -- ... later ...
  SELECT BASE_SALARY INTO v_old_salary
  FROM SALARY_RECORDS
  WHERE EMP_ID = p_emp_id AND ACTIVE_FLAG = 'Y' AND ROWNUM = 1
  ORDER BY EFFECTIVE_DATE DESC;
  ```
- **Issue:** Two `SELECT INTO` statements without `FOR UPDATE` are followed by `UPDATE` and `INSERT` operations. A concurrent salary change between the SELECT and UPDATE would cause the `CHANGE_PCT` calculation to use stale data. Note: `ROWNUM = 1` combined with `ORDER BY` is also incorrect — `ROWNUM` is applied before `ORDER BY`, so the "first" row may not be the most recent.
- **Impact:** Promotion salary change percentage may be calculated incorrectly. The `ROWNUM` bug means the old salary retrieved may not be the current active salary.
- **Recommendation:** Add `FOR UPDATE` on the EMPLOYEES select (like `transfer_employee` does at line 523). Fix the ROWNUM issue using a subquery: `SELECT * FROM (SELECT ... ORDER BY EFFECTIVE_DATE DESC) WHERE ROWNUM = 1`.

---

## 3. Performance Issues

### PERF-001: Day-by-Day Date Loop in Leave Calculation
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_LEAVE.pkb:12-37`
- **Code:**
  ```sql
  WHILE v_date <= TRUNC(p_end_date) LOOP
      IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
          SELECT COUNT(*) INTO v_holiday_count
          FROM HOLIDAYS WHERE HOLIDAY_DATE = v_date ...;
          IF v_holiday_count = 0 THEN v_count := v_count + 1; END IF;
      END IF;
      v_date := v_date + 1;
  END LOOP;
  ```
- **Issue:** `calculate_business_days` iterates day-by-day from start to end date, executing a `SELECT COUNT(*)` against the `HOLIDAYS` table on each weekday iteration. For a 30-day leave request, this issues ~22 individual queries.
- **Impact:** For bulk leave calculations (e.g., year-end reporting across 500+ employees), this becomes O(employees x days) individual SQL statements. Also does not account for "observed" holidays (e.g., if July 4 falls on Saturday, the observed Friday is not excluded).
- **Recommendation:** Replace with a set-based calculation:
  ```sql
  SELECT COUNT(*) FROM (
    SELECT TRUNC(p_start_date) + LEVEL - 1 AS d
    FROM DUAL CONNECT BY LEVEL <= p_end_date - p_start_date + 1
  ) WHERE TO_CHAR(d, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT','SUN')
    AND d NOT IN (SELECT HOLIDAY_DATE FROM HOLIDAYS WHERE ACTIVE_FLAG = 'Y');
  ```

### PERF-002: Row-by-Row Payroll Processing
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:267-300`
- **Code:**
  ```sql
  FOR emp_rec IN (SELECT e.EMP_ID FROM EMPLOYEES e
      WHERE e.EMPLOYMENT_STATUS = 'ACTIVE' AND e.ACTIVE_FLAG = 'Y'
      ORDER BY e.EMP_ID) LOOP
      calculate_employee_pay(p_run_id, emp_rec.EMP_ID, v_period_id, p_user);
      IF MOD(v_emp_count, 50) = 0 THEN COMMIT; END IF;
  END LOOP;
  ```
- **Issue:** Payroll calculation processes each employee in a cursor loop with individual procedure calls. Partial commits every 50 employees mean a mid-run failure leaves payroll half-calculated with no clean rollback path.
- **Impact:** For 500+ employees, payroll runs take significantly longer than necessary. Partial commits create an inconsistent state that requires manual investigation to resolve.
- **Recommendation:** Refactor to use `BULK COLLECT` with `FORALL` for the INSERT operations within `calculate_employee_pay`. Replace partial commits with a single commit at the end, using `SAVEPOINT` for error recovery.

### PERF-003: CONNECT BY Hierarchical Query Performance
- **Severity:** MEDIUM
- **Location:** `schema/views/hrms_views.sql:47-57`, `plsql/packages/PKG_EMPLOYEE.pkb:828-837`
- **Code:**
  ```sql
  -- VW_ORG_HIERARCHY (view)
  START WITH MANAGER_EMP_ID IS NULL
  CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
  ORDER SIBLINGS BY LAST_NAME;

  -- get_org_chart (procedure)
  CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID AND LEVEL <= p_max_depth
  ```
- **Issue:** Both the `VW_ORG_HIERARCHY` view and `get_org_chart` function use `CONNECT BY` hierarchical queries. The view has a documented warning: "Performance degrades significantly with >500 employees."
- **Impact:** As the employee base grows, these queries become progressively slower. The view is referenced by Oracle Reports and Forms LOVs, causing user-facing latency.
- **Recommendation:** For Oracle 19c, consider using recursive CTEs (`WITH RECURSIVE`) for better optimizer control, or materialize the hierarchy into a closure table that is refreshed on org structure changes.

### PERF-004: Duplicate Business Days Function
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_COMMON.pkb:131-145`
- **Code:**
  ```sql
  FUNCTION business_days_between(p_start_date IN DATE, p_end_date IN DATE) RETURN NUMBER IS
      v_date DATE := TRUNC(p_start_date);
  BEGIN
      WHILE v_date <= TRUNC(p_end_date) LOOP
          IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
              v_count := v_count + 1;
          END IF;
          v_date := v_date + 1;
      END LOOP;
  ```
- **Issue:** `PKG_COMMON.business_days_between` is a second implementation of business day counting that duplicates `PKG_LEAVE.calculate_business_days` (PERF-001) but without holiday exclusion. A third instance exists in `PKG_COMMON.add_business_days` (line 151-165).
- **Impact:** Three separate date-loop implementations that must be maintained independently. `PKG_COMMON` version silently ignores holidays, producing different results than `PKG_LEAVE` for the same date range.
- **Recommendation:** Consolidate into a single `PKG_COMMON.business_days_between` with an optional `p_exclude_holidays` parameter. Have `PKG_LEAVE` delegate to it.

### PERF-005: Per-Iteration SMTP Connection
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:78-87`
- **Code:**
  ```sql
  FOR notif_rec IN (SELECT ... FROM NOTIFICATION_QUEUE ...) LOOP
      v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
      UTL_SMTP.HELO(v_connection, c_smtp_host);
      -- ... send email ...
  END LOOP;
  ```
- **Issue:** The `process_pending_notifications` procedure opens a new SMTP connection for each notification in the queue. SMTP connection setup involves TCP handshake and HELO/EHLO negotiation.
- **Impact:** For a batch of 100 pending notifications, this creates 100 TCP connections. This can exhaust SMTP server connection limits and significantly slow processing.
- **Recommendation:** Open the SMTP connection once before the loop and reuse it for all notifications, closing it after the loop completes. Add connection pooling if available.

### PERF-006: NOCACHE on All Sequences
- **Severity:** MEDIUM
- **Location:** `schema/sequences/hrms_sequences.sql:9-48`
- **Code:**
  ```sql
  CREATE SEQUENCE HRMS.SEQ_DEPARTMENT START WITH 100 INCREMENT BY 1 NOCACHE;
  CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
  -- ... (18 of 20 sequences use NOCACHE)
  ```
- **Issue:** 18 of 20 sequences use `NOCACHE` (only `SEQ_AUDIT` uses `CACHE 100`). Each `NEXTVAL` call requires a data dictionary update, causing redo log writes and contention on the `SEQ$` table.
- **Impact:** Under concurrent load (e.g., payroll processing inserting thousands of `PAYROLL_DETAILS` rows), sequence contention becomes a bottleneck. Each `NEXTVAL` is serialized at the data dictionary level.
- **Recommendation:** Add `CACHE 20` to high-throughput sequences (`SEQ_PAYROLL_DETAIL`, `SEQ_LEAVE_ACCRUAL`, `SEQ_EMP_HISTORY`). The gaps from caching are acceptable since these are surrogate keys.

### PERF-007: Leave Accrual Partial Commits
- **Severity:** LOW
- **Location:** `plsql/packages/PKG_LEAVE.pkb:542-545`
- **Code:**
  ```sql
  IF MOD(v_total_employees, 100) = 0 THEN
      COMMIT;
  END IF;
  ```
- **Issue:** `run_monthly_accrual` commits every 100 employees. Same pattern as PERF-002 in payroll.
- **Impact:** A failure mid-run leaves some employees accrued and others not. Rerunning the procedure may double-accrue employees processed before the failure.
- **Recommendation:** Use a single commit at the end, or add an idempotency check (e.g., skip employees who already have an accrual log entry for this period).

---

## 4. Validation Drift

### VD-001: Email Validation Divergence
- **Severity:** HIGH
- **Location:**
  - Server-side: `plsql/packages/PKG_COMMON.pkb:265-268`
  - Client-side: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41`
- **Server-side code:**
  ```sql
  FUNCTION is_valid_email(p_email IN VARCHAR2) RETURN BOOLEAN IS
  BEGIN
      RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
  END is_valid_email;
  ```
- **Client-side code:**
  ```sql
  FUNCTION validate_email(p_email IN VARCHAR2) RETURN BOOLEAN IS
  BEGIN
      v_at_pos := INSTR(p_email, '@');
      v_dot_pos := INSTR(p_email, '.', v_at_pos);
      -- BUG: Only checks for one dot after @, rejects valid subdomains
  ```
- **Issue:** The server-side validation uses `REGEXP_LIKE` which accepts emails with subdomains (e.g., `user@mail.company.com`). The client-side PLL uses `INSTR`-based parsing that only checks for a single dot after `@`, rejecting valid subdomain emails. Additionally, the client-side allows `NULL` (returns `TRUE`) while server-side behavior depends on the caller.
- **Impact:** Employees with valid subdomain email addresses can be saved via direct SQL or API calls but will be rejected when entering data through Oracle Forms, creating a confusing UX. The same data may be accepted or rejected depending on the entry point.
- **Recommendation:** Replace the client-side PLL validation with the same regex pattern used server-side. Alternatively, delegate validation entirely to the server via a database round-trip from the form.

### VD-002: Salary Validation Error Message Format Inconsistency
- **Severity:** MEDIUM
- **Location:**
  - Server-side: `plsql/packages/PKG_VALIDATION.pkb:17-48`
  - Client-side: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:108-135`
- **Issue:** Both validate salary against grade ranges, but error messages differ:
  - Server: `'Salary $75,000.00 is below minimum for grade Mid-Level ($60,000.00)'`
  - Client: `'Below minimum ($60,000)'` (uses `FM$999,999` — no decimals)
  - Server returns `'Salary and grade are required'` for NULL inputs; client returns `NULL`.
- **Impact:** Users see different error messages depending on whether validation triggers client-side or server-side, causing confusion and complicating support troubleshooting.
- **Recommendation:** Standardize error message format. Ideally, have the client call `PKG_VALIDATION.validate_salary_for_grade` directly instead of reimplementing the logic.

### VD-003: SSN Validation Inconsistency
- **Severity:** MEDIUM
- **Location:**
  - Server-side: `plsql/packages/PKG_COMMON.pkb:277-280`
  - Client-side: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:69-90`
- **Issue:** The server-side `is_valid_ssn` only checks for exactly 9 digits (`REGEXP_LIKE(... '^\d{9}$')`). The client-side `validate_ssn` also checks for all-zero groups (area `000`, group `00`, serial `0000`), which are invalid per SSA rules.
- **Impact:** The server-side accepts invalid SSNs (e.g., `000-12-3456`) that the client-side correctly rejects. Data entered via non-Forms interfaces (API, direct SQL) may contain invalid SSNs.
- **Recommendation:** Add the zero-group checks to `PKG_COMMON.is_valid_ssn` to match the more thorough client-side validation.

---

## 5. Circular Dependencies

### CD-001: PKG_EMPLOYEE <-> PKG_PAYROLL Circular Dependency
- **Severity:** HIGH
- **Location:**
  - `plsql/packages/PKG_EMPLOYEE.pkb:271-275` (calls `PKG_PAYROLL.create_salary_record`)
  - `plsql/packages/PKG_EMPLOYEE.pkb:617` (calls `PKG_PAYROLL.create_salary_record` in `promote_employee`)
  - `plsql/packages/PKG_EMPLOYEE.pkb:778` (calls `PKG_PAYROLL.create_salary_record` in `rehire_employee`)
  - `plsql/packages/PKG_PAYROLL.pkb` calls `PKG_EMPLOYEE.is_active` for validation (noted in code comment at line 273-274)
- **Code (comment at PKG_EMPLOYEE.pkb:273):**
  ```sql
  -- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
  -- which in turn may call PKG_EMPLOYEE.is_active for validation
  ```
- **Issue:** `PKG_EMPLOYEE` calls `PKG_PAYROLL.create_salary_record` during employee creation, promotion, and rehire. `PKG_PAYROLL` calls back to `PKG_EMPLOYEE.is_active` for validation. This creates a compile-time dependency cycle.
- **Impact:** If either package body is invalidated, the other becomes invalid too, potentially cascading across the entire schema. Recompilation order matters and can cause `ORA-04068` errors during deployment.
- **Recommendation:** Extract the mutual dependency into a shared interface package (e.g., `PKG_EMPLOYEE_API`) that both packages depend on but which depends on neither. Alternatively, use `EXECUTE IMMEDIATE` for the cross-package call to break the compile-time dependency.

---

## 6. Architectural Anti-Patterns

### ARCH-001: Autonomous Transaction for Audit Logging
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:137-147`
- **Code:**
  ```sql
  PROCEDURE log_history(...) IS
      PRAGMA AUTONOMOUS_TRANSACTION;
  BEGIN
      INSERT INTO EMPLOYEE_HISTORY (...) VALUES (...);
      COMMIT;
  EXCEPTION
      WHEN OTHERS THEN ROLLBACK;
  END log_history;
  ```
- **Issue:** `log_history` uses `PRAGMA AUTONOMOUS_TRANSACTION` with its own `COMMIT`. If the parent transaction rolls back (e.g., a constraint violation after logging), the history record persists as an orphan — documenting a change that never happened.
- **Impact:** `EMPLOYEE_HISTORY` may contain records for transactions that were rolled back, creating a misleading audit trail. The `WHEN OTHERS THEN ROLLBACK` silently swallows logging failures.
- **Recommendation:** Remove the autonomous transaction. Let history logging participate in the parent transaction so it commits or rolls back atomically. Use autonomous transactions only for error logging (which is already done correctly in `PKG_AUDIT`).

### ARCH-002: UTL_FILE Flat-File Integration
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_INTEGRATION.pkb:16-83, 90-147`, `plsql/packages/PKG_PAYROLL.pkb:826-897`
- **Issue:** Three procedures use `UTL_FILE` for flat-file I/O:
  - `PKG_INTEGRATION.generate_gl_journal` — pipe-delimited GL journal entries
  - `PKG_INTEGRATION.export_benefits_feed` — fixed-width ADP benefits file
  - `PKG_PAYROLL.generate_pay_register` — CSV pay register
- **Impact:** Requires Oracle Directory Objects to be configured on the database server. Files are written to the DB server filesystem, requiring separate mechanisms (FTP, SCP) to transfer them. No checksums, encryption, or delivery confirmation.
- **Recommendation:** For new integrations, use REST APIs (`UTL_HTTP`/`APEX_WEB_SERVICE`) or Oracle Advanced Queuing (AQ). For the existing ADP feed, consider ADP's Workforce Now API. Keep UTL_FILE as a fallback during migration.

### ARCH-003: Hard-Coded 2024 Federal Tax Brackets
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:602-677`
- **Code:**
  ```sql
  -- 2024 Federal tax brackets (Single)
  -- TODO: Read from TAX_BRACKETS table instead of hard-coding
  IF p_filing_status = 'SINGLE' OR p_filing_status = 'MARRIED_SEPARATE' THEN
      IF v_taxable <= 11600 THEN
          v_tax := v_taxable * 0.10;
      ELSIF v_taxable <= 47150 THEN
          v_tax := 1160 + (v_taxable - 11600) * 0.12;
      -- ... 7 brackets each for SINGLE and MARRIED_JOINT
  ```
- **Issue:** Federal tax brackets for 2024 are hard-coded in the package body. The `TAX_BRACKETS` table exists in the schema (`schema/tables/02_payroll_tables.sql:159-173`) but is not used. The code contains a TODO comment acknowledging this.
- **Impact:** Every year, a developer must manually update bracket values, recompile the package, and redeploy. A missed update results in incorrect tax withholding for all employees, creating IRS compliance exposure.
- **Recommendation:** Implement `calculate_federal_tax` to read from the `TAX_BRACKETS` table. Populate the table with 2024 brackets and add a year-end process to load new brackets from IRS publications.

### ARCH-004: Hard-Coded Fiscal Year Start
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_COMMON.pkb:170-179`, `plsql/packages/PKG_REPORTING.pks:10`
- **Code:**
  ```sql
  -- PKG_COMMON.get_fiscal_year
  IF EXTRACT(MONTH FROM p_date) >= 10 THEN
      RETURN EXTRACT(YEAR FROM p_date) + 1;
  ELSE
      RETURN EXTRACT(YEAR FROM p_date);
  END IF;
  ```
- **Issue:** The fiscal year start month (October = month 10) is hard-coded in `PKG_COMMON.get_fiscal_year` and `get_fiscal_quarter`. The `SYSTEM_PARAMETERS` table contains `FISCAL_YEAR_START = '10'` (seed data row 4) but this value is not read by the code.
- **Impact:** If the organization changes its fiscal year start, multiple package bodies must be updated and recompiled. The `SYSTEM_PARAMETERS` entry is misleading because changing it has no effect.
- **Recommendation:** Read the fiscal year start month from `PKG_COMMON.get_param('PAYROLL', 'FISCAL_YEAR_START')` and use it in the calculation.

### ARCH-005: Stub/TODO Implementations
- **Severity:** LOW
- **Location:**
  - `plsql/packages/PKG_INTEGRATION.pkb:170` — `import_time_attendance` body is a stub
  - `plsql/packages/PKG_EMPLOYEE.pkb:737-739` — `terminate_employee` has 3 TODO comments
  - `plsql/packages/PKG_INTEGRATION.pkb:196-203` — `sync_org_structure` is a placeholder
  - `plsql/packages/PKG_REPORTING.pkb:200-204` — `refresh_reporting_tables` is a placeholder
- **Issue:** Several procedures are stubs or contain TODO markers for unimplemented functionality:
  - `import_time_attendance`: Reads lines but never parses or inserts data
  - `terminate_employee` TODOs: COBRA benefits integration, system access revocation, final pay calculation
  - `sync_org_structure`: Logs a success message without doing anything
  - `refresh_reporting_tables`: Same — logs success without refreshing
- **Impact:** Callers of these procedures may assume functionality exists when it does not. The time attendance import silently counts lines without actually importing, giving a misleading success count.
- **Recommendation:** Either implement the functionality or raise `RAISE_APPLICATION_ERROR(-20900, 'Not yet implemented')` so callers are aware. Track implementation as backlog items.

### ARCH-006: Denormalized Reporting Tables with Stale Data
- **Severity:** LOW
- **Location:** `plsql/packages/PKG_REPORTING.pks:8-10`
- **Code:**
  ```sql
  -- Known issues:
  --   - Denormalized reporting tables refreshed nightly; stale during business hours
  --   - Some reports use hard-coded fiscal year start (Oct 1)
  ```
- **Issue:** Reporting tables (`RPT_*`) are refreshed nightly but queried during business hours. The refresh procedure itself is a stub (ARCH-005).
- **Impact:** Reports show data that is up to 24 hours stale. Since the refresh procedure is unimplemented, the tables may never actually be refreshed.
- **Recommendation:** Implement incremental refresh using materialized views with `REFRESH ON COMMIT` for critical reporting queries. For less critical reports, implement the nightly refresh procedure and document the staleness window.

### ARCH-007: Simplified State Tax Calculation
- **Severity:** LOW
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:693-718`
- **Code:**
  ```sql
  v_rate := CASE p_state_code
      WHEN 'CA' THEN 0.0725
      WHEN 'NY' THEN 0.0685
      -- ... 10 states hard-coded
      ELSE 0.05  -- Default rate for unknown states
  END;
  RETURN ROUND(p_taxable_income * v_rate, 2);
  ```
- **Issue:** State tax uses flat rates instead of progressive brackets. Only 10 states are explicitly handled; all others default to 5%. California and New York in particular have complex progressive bracket structures.
- **Impact:** Employees in states with progressive tax brackets will have incorrect withholding. The default 5% rate may over- or under-withhold for employees in unlisted states.
- **Recommendation:** Extend the `TAX_BRACKETS` table to include state brackets (using `STATE_CODE` column which already exists) and implement bracket-based calculation per state.

---

## 7. Data Integrity Risks

### DI-001: Seed Data Column Mismatch with DDL
- **Severity:** CRITICAL
- **Location:**
  - DDL: `schema/tables/01_core_tables.sql:35-52` (LOCATIONS table)
  - Seed: `data/seed/01_reference_data.sql:11-18` (LOCATIONS inserts)
  - DDL: `schema/tables/01_core_tables.sql:57-72` (JOB_GRADES table)
  - Seed: `data/seed/01_reference_data.sql:23-42` (JOB_GRADES inserts)
- **Issue:** The seed data INSERT statements reference columns that do not exist in the table DDL:
  - **LOCATIONS**: Seed uses `PHONE` but DDL defines `PHONE_NUMBER`
  - **JOB_GRADES**: Seed uses `GRADE_LEVEL` but DDL has no such column (only `GRADE_ID`, `GRADE_CODE`, `GRADE_NAME`, `MIN_SALARY`, `MAX_SALARY`, `OVERTIME_ELIGIBLE`, `ACTIVE_FLAG`, `CREATED_BY`, `CREATED_DATE`, `MODIFIED_BY`, `MODIFIED_DATE`)
  - **JOB_GRADES seed**: Also omits `GRADE_CODE` which is defined as `NOT NULL` with a unique constraint
- **Impact:** Running the seed scripts against the actual schema will fail with `ORA-00904: invalid identifier` errors. The seed data cannot be loaded without manual correction.
- **Recommendation:** Fix the seed data to match the DDL exactly:
  - LOCATIONS: Change `PHONE` to `PHONE_NUMBER`
  - JOB_GRADES: Remove `GRADE_LEVEL`, add `GRADE_CODE` (required, unique)

### DI-002: VW_LEAVE_SUMMARY Ignores Virtual Column
- **Severity:** HIGH
- **Location:**
  - View: `schema/views/hrms_views.sql:86-103`
  - Table: `schema/tables/03_leave_tables.sql:47`
- **View code:**
  ```sql
  lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE
  ```
- **Table DDL:**
  ```sql
  AVAILABLE NUMBER(6,2) GENERATED ALWAYS AS
      (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL
  ```
- **Issue:** The `VW_LEAVE_SUMMARY` view manually calculates `AVAILABLE` as `OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT`, omitting the `- PENDING` component that is included in the table's virtual column definition.
- **Impact:** The view reports higher available leave balances than the table's computed column because it does not subtract pending leave requests. An employee with 10 days accrued and 3 pending requests would see 10 available in the view but 7 in the table.
- **Recommendation:** Replace the manual calculation with a reference to the virtual column: `lb.AVAILABLE AS AVAILABLE`.

### DI-003: Leave Carryover Double-Subtraction Risk
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_LEAVE.pkb:606-623`
- **Code:**
  ```sql
  -- BUG: If run twice on same day, can double-subtract
  PROCEDURE expire_carryover(p_user IN VARCHAR2 DEFAULT USER) IS
  BEGIN
      UPDATE LEAVE_BALANCES SET
          ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
          CARRYOVER_FROM_PREV = 0,
          ...
      WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE) AND CARRYOVER_FROM_PREV > 0;
      COMMIT;
  END expire_carryover;
  ```
- **Issue:** The code comment acknowledges the bug. However, the `CARRYOVER_FROM_PREV > 0` condition actually prevents double-subtraction because the first run sets it to 0. The real risk is if `expire_carryover` runs concurrently: two sessions could both see `CARRYOVER_FROM_PREV > 0` before either commits, causing a double-subtraction.
- **Impact:** Under concurrent execution (e.g., scheduled job overlap), an employee's leave balance could be incorrectly reduced twice, potentially going negative.
- **Recommendation:** Add `FOR UPDATE SKIP LOCKED` to the implicit cursor, or use `SELECT ... FOR UPDATE` with an explicit cursor to serialize access per row.

### DI-004: Soft-Delete Inconsistency Across Tables
- **Severity:** MEDIUM
- **Location:** Multiple tables and packages
- **Issue:** The codebase uses two different soft-delete mechanisms inconsistently:
  - **ACTIVE_FLAG pattern**: `EMPLOYEES`, `DEPARTMENTS`, `JOB_GRADES`, `JOB_TITLES`, `SALARY_RECORDS`, `PAY_ELEMENTS`, `EMPLOYEE_PAY_ELEMENTS`, `LEAVE_TYPES`, `EMPLOYEE_DEPENDENTS`, `TAX_BRACKETS`, `EMPLOYEE_TAX_INFO`
  - **STATUS pattern**: `LEAVE_REQUESTS` (CANCELLED), `PAYROLL_RUNS` (REVERSED), `NOTIFICATION_QUEUE` (CANCELLED)
  - **No soft-delete**: `EMPLOYEE_HISTORY`, `AUDIT_LOG`, `LEAVE_ACCRUAL_LOG`, `PAYROLL_DETAILS` (append-only)
  - Some queries filter on `ACTIVE_FLAG = 'Y'`, others on `EMPLOYMENT_STATUS = 'ACTIVE'`, and some check both (e.g., `PKG_PAYROLL.calculate_payroll` line 283-284: `EMPLOYMENT_STATUS = 'ACTIVE' AND ACTIVE_FLAG = 'Y'`).
- **Impact:** Inconsistent filtering means different queries may include or exclude records differently. A terminated employee with `EMPLOYMENT_STATUS = 'TERMINATED'` but `ACTIVE_FLAG = 'Y'` (if the flag update is missed) would be included in some queries but not others.
- **Recommendation:** Standardize on a single soft-delete mechanism. Add a database trigger to ensure `ACTIVE_FLAG` is always synchronized with `EMPLOYMENT_STATUS` for the `EMPLOYEES` table.

### DI-005: Payslip YTD Placeholders
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:784-785`
- **Code:**
  ```sql
  0 AS YTD_GROSS,  -- Placeholder
  0 AS YTD_NET     -- Placeholder
  ```
- **Issue:** The `get_payslip` procedure returns hard-coded zeros for YTD gross and net pay. A working `get_ytd_earnings` function exists (line 802-819) but is not called.
- **Impact:** Any payslip report or form using this procedure shows $0.00 for YTD figures, which is misleading to employees and may cause payroll inquiries.
- **Recommendation:** Replace the placeholders with calls to `get_ytd_earnings`:
  ```sql
  get_ytd_earnings(pd.EMP_ID) AS YTD_GROSS
  ```

### DI-006: SYSTEM_PARAMETERS Column Name Mismatch
- **Severity:** LOW
- **Location:**
  - DDL: `schema/tables/04_performance_tables.sql:110-124`
  - Seed: `data/seed/01_reference_data.sql:182-201`
- **Issue:** The `SYSTEM_PARAMETERS` table DDL defines `PARAM_DESCRIPTION` (line 115), but the seed INSERT statements use `DESCRIPTION` as the column name.
- **Impact:** Seed script fails with `ORA-00904` when run against the actual DDL. Same class of issue as DI-001.
- **Recommendation:** Change seed data column name from `DESCRIPTION` to `PARAM_DESCRIPTION`.

---

## 8. Cross-Cutting Concerns

### CC-001: WHEN OTHERS Exception Swallowing
- **Severity:** MEDIUM
- **Location:** Multiple packages
- **Issue:** Several procedures catch `WHEN OTHERS` and either silently swallow the error or log-and-reraise:
  - `PKG_EMPLOYEE.log_history` (line 145): `WHEN OTHERS THEN ROLLBACK` — silent
  - `PKG_INTEGRATION.import_time_attendance` (line 176-179): Logs but continues
  - `HRMS_COMMON_LIB.handle_error` (line 28): `WHEN OTHERS THEN NULL` to prevent recursive errors
- **Impact:** Silent exception handling masks bugs and makes debugging difficult. The `import_time_attendance` error counter may hide systematic parsing failures.
- **Recommendation:** For `log_history`, let the autonomous transaction propagate the error (or remove the autonomous transaction per ARCH-001). For `import_time_attendance`, collect error details and include them in the final summary.

### CC-002: Inconsistent Error Code Ranges
- **Severity:** MEDIUM
- **Location:** All packages
- **Issue:** Custom error codes are not systematically organized:
  - PKG_EMPLOYEE: -20001 to -20012
  - PKG_SECURITY: -20301
  - PKG_PAYROLL: -20101 to -20103
  - PKG_LEAVE: -20201 to -20203
  - No documented mapping or constants
- **Impact:** Error codes overlap risk as new features are added. No central reference for support staff to decode error numbers.
- **Recommendation:** Create a `PKG_ERROR_CODES` package with named constants and document the allocation ranges in the project wiki.

### CC-003: Missing NOT NULL on Critical Seed Columns
- **Severity:** LOW
- **Location:** `schema/tables/02_payroll_tables.sql:86-101`
- **Issue:** `PAY_PERIODS.PAY_FREQUENCY` has a CHECK constraint for valid values but no NOT NULL constraint, unlike most other status/type columns which combine both.
- **Impact:** A NULL `PAY_FREQUENCY` would pass the CHECK constraint (since NULL satisfies `CHECK` in Oracle) but would cause NVL/DECODE logic in payroll calculations to produce unexpected results.
- **Recommendation:** Add `NOT NULL` to `PAY_PERIODS.PAY_FREQUENCY`.

### CC-004: Missing Foreign Key Indexes
- **Severity:** LOW
- **Location:** All tables with foreign keys
- **Issue:** The DDL creates foreign key constraints but does not create indexes on the FK columns. Oracle does not automatically index FK columns (unlike some other RDBMS).
- **Impact:** Queries joining on FK columns (which are used extensively in views and package queries) may perform full table scans. Additionally, deletes on parent tables acquire table-level locks on child tables when FK columns are unindexed.
- **Recommendation:** Create indexes on all FK columns, prioritizing: `EMPLOYEES.DEPT_ID`, `EMPLOYEES.JOB_ID`, `EMPLOYEES.MANAGER_EMP_ID`, `PAYROLL_DETAILS.RUN_ID`, `PAYROLL_DETAILS.EMP_ID`, `LEAVE_REQUESTS.EMP_ID`.

### CC-005: No Database Triggers for Audit Trail
- **Severity:** LOW
- **Location:** No `plsql/triggers/` directory exists
- **Issue:** The `AUDIT_LOG` table exists but there are no database triggers to automatically populate it. All audit logging is done via explicit `PKG_AUDIT.log_action` calls within package procedures. If a developer forgets to add the call, or if data is modified outside the packages (direct SQL), no audit record is created.
- **Impact:** The audit trail has gaps for any data modification that bypasses the PL/SQL packages. This is a compliance concern for SOX/HIPAA environments.
- **Recommendation:** Add `AFTER INSERT OR UPDATE OR DELETE` triggers on critical tables (`EMPLOYEES`, `SALARY_RECORDS`, `LEAVE_REQUESTS`) that automatically insert into `AUDIT_LOG`. Keep the `PKG_AUDIT` calls for detailed context logging.

---

## Prioritized Migration Roadmap

### Phase 1: Critical Security (Weeks 1-4)
| Item | Priority | Effort | Risk |
|------|----------|--------|------|
| SEC-001: Replace MD5 with SHA-512/bcrypt | P0 | Medium | Password reset required |
| SEC-002: Move encryption key to Oracle Wallet | P0 | Medium | Requires DBA coordination |
| SEC-003: Fix SQL injection with bind variables | P0 | Low | Straightforward refactor |
| RC-001: Replace MAX()+1 with sequence | P0 | Low | Test employee creation flows |
| SEC-004: Implement account lockout | P1 | Medium | Add schema changes |
| SEC-005: Fix timing attack | P1 | Low | Constant-time hash comparison |
| DI-001: Fix seed data column mismatches | P1 | Low | Required for new environment setup |

### Phase 2: Data Integrity (Weeks 5-8)
| Item | Priority | Effort | Risk |
|------|----------|--------|------|
| DI-002: Fix VW_LEAVE_SUMMARY calculation | P1 | Low | View recompilation |
| DI-003: Add serialization to expire_carryover | P1 | Low | Concurrent access patterns |
| RC-002: Add FOR UPDATE to promote_employee | P1 | Low | Fix ROWNUM bug simultaneously |
| VD-001: Align email validation | P2 | Low | Test Forms client behavior |
| DI-004: Standardize soft-delete pattern | P2 | High | Wide-reaching schema/code changes |
| DI-005: Implement YTD in payslip | P2 | Low | Use existing get_ytd_earnings |
| DI-006: Fix SYSTEM_PARAMETERS seed | P2 | Low | Same fix pattern as DI-001 |

### Phase 3: Performance (Weeks 9-14)
| Item | Priority | Effort | Risk |
|------|----------|--------|------|
| PERF-001: Set-based business days calculation | P2 | Medium | Validate against current results |
| PERF-002: Bulk payroll processing | P2 | High | Critical path — extensive testing needed |
| PERF-005: SMTP connection reuse | P2 | Low | Test with SMTP server |
| PERF-006: Add CACHE to sequences | P2 | Low | Gaps in IDs are acceptable |
| PERF-003: Optimize CONNECT BY queries | P3 | Medium | Alternative: materialized hierarchy |
| PERF-004: Consolidate business days functions | P3 | Low | Deprecate duplicates |
| CC-004: Add FK indexes | P3 | Low | Monitor before/after performance |

### Phase 4: Modernization (Weeks 15-24)
| Item | Priority | Effort | Risk |
|------|----------|--------|------|
| ARCH-003: Data-driven tax brackets | P2 | Medium | Validate against IRS publications |
| ARCH-004: Configurable fiscal year | P2 | Low | Read from SYSTEM_PARAMETERS |
| CD-001: Break circular dependency | P3 | Medium | Careful refactoring of interfaces |
| ARCH-001: Remove autonomous transaction from log_history | P3 | Low | Audit trail implications |
| ARCH-002: API-based integrations | P3 | High | Vendor coordination required |
| SEC-006: Dynamic SMTP configuration | P3 | Low | Already in SYSTEM_PARAMETERS |
| ARCH-005: Implement or remove stubs | P3 | Medium | Feature-dependent |
| ARCH-006: Materialized view reporting | P3 | High | DBA coordination |
| ARCH-007: Progressive state tax brackets | P3 | High | Per-state research required |
| VD-002/VD-003: Standardize remaining validations | P3 | Low | Forms client testing |
| CC-001/CC-002: Error handling cleanup | P4 | Medium | Risk of changing exception behavior |
| CC-003/CC-005: Schema hardening | P4 | Low | Minimal risk |

---

## Appendix: File Index

| File | Category | Findings |
|------|----------|----------|
| `plsql/packages/PKG_SECURITY.pkb` | Security | SEC-001, SEC-002, SEC-004, SEC-005, SEC-007 |
| `plsql/packages/PKG_EMPLOYEE.pkb` | Security, Race, Circular, Architectural | SEC-003, RC-001, RC-002, CD-001, ARCH-001, ARCH-005 |
| `plsql/packages/PKG_PAYROLL.pkb` | Performance, Architectural, Data Integrity | PERF-002, ARCH-003, ARCH-004, ARCH-007, DI-005 |
| `plsql/packages/PKG_LEAVE.pkb` | Performance, Data Integrity | PERF-001, PERF-007, DI-003 |
| `plsql/packages/PKG_NOTIFICATION.pkb` | Security, Performance | SEC-006, PERF-005 |
| `plsql/packages/PKG_INTEGRATION.pkb` | Architectural | ARCH-002, ARCH-005 |
| `plsql/packages/PKG_COMMON.pkb` | Performance, Architectural | PERF-004, ARCH-004 |
| `plsql/packages/PKG_VALIDATION.pkb` | Validation | VD-001, VD-002, VD-003 |
| `plsql/packages/PKG_REPORTING.pkb` | Architectural | ARCH-005, ARCH-006 |
| `forms/libraries/HRMS_VALIDATION_LIB.pll.sql` | Validation | VD-001, VD-002, VD-003 |
| `schema/sequences/hrms_sequences.sql` | Performance | PERF-006 |
| `schema/views/hrms_views.sql` | Performance, Data Integrity | PERF-003, DI-002 |
| `schema/tables/01_core_tables.sql` | Data Integrity | DI-001, DI-004 |
| `schema/tables/02_payroll_tables.sql` | Cross-Cutting | CC-003 |
| `schema/tables/03_leave_tables.sql` | Data Integrity | DI-002 |
| `schema/tables/04_performance_tables.sql` | Data Integrity | DI-006 |
| `data/seed/01_reference_data.sql` | Data Integrity | DI-001, DI-006 |
