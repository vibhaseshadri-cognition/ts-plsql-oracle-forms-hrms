# Technical Debt Report — Oracle Forms/PL/SQL HRMS Estate

## Executive Summary

This report catalogs **36 identified technical debt items** across the Oracle Forms/PL/SQL HRMS application, including 10 security vulnerabilities, 2 race conditions, 6 performance issues, 4 validation drift items, 1 circular dependency, 6 architectural anti-patterns, and 7 data integrity risks.

| Severity | Count | Categories |
|----------|-------|------------|
| CRITICAL | 7 | Security (MD5, hard-coded key, cleartext transmission), trigger column mismatch |
| HIGH | 10 | Race conditions, timing attack, no lockout, validation drift |
| MEDIUM | 13 | Performance, architectural anti-patterns, stale data |
| LOW | 6 | Configuration, incomplete implementations |

---

## 1. Security Vulnerabilities

### SEC-01: MD5 Password Hashing (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:18-22`
```sql
RETURN RAWTOHEX(
    DBMS_CRYPTO.HASH(
        UTL_RAW.CAST_TO_RAW(p_password),
        DBMS_CRYPTO.HASH_MD5
    )
);
```

**Issue**: MD5 is cryptographically broken. Rainbow table attacks can crack MD5 hashes in seconds. No salt is applied.
**Impact**: Complete password database compromise if EMPLOYEES table is leaked.
**Recommendation**: Migrate to bcrypt, scrypt, or PBKDF2 with per-user salt. Oracle 19c supports DBMS_CRYPTO.HASH_SH256 as a minimum upgrade, but proper password hashing libraries (bcrypt) require external integration.

---

### SEC-02: Hard-Coded Encryption Key (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:7`
```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```

**Issue**: AES-256 encryption key stored as a string constant in source code. Any developer, DBA, or source control reader can decrypt all SSN and bank account data.
**Impact**: Total PII exposure. Regulatory violation (SOX, PCI-DSS, HIPAA).
**Recommendation**: Move to Oracle Wallet / Key Vault. Use Oracle Transparent Data Encryption (TDE) or externalize key management via HSM. Rotate compromised key immediately.

---

### SEC-03: Cleartext Password Transmission (CRITICAL)

**File**: `forms/xml-exports/HRMS_LOGIN.xml:75-79`
```xml
v_session_id := PKG_SECURITY.authenticate(
    :LOGIN.USERNAME,
    :LOGIN.PASSWORD,  -- Transmitted in cleartext
    GET_APPLICATION_PROPERTY(CLIENT_HOST)
);
```

**Issue**: Password sent from Forms client to database via SQL*Net without application-layer encryption. Network sniffing exposes credentials.
**Impact**: Credential theft via MITM attack on internal network.
**Recommendation**: Enable Oracle Net encryption (native network encryption or TLS), or implement client-side hashing before transmission.

---

### SEC-04: No Account Lockout (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb` (authenticate function)

**Issue**: No tracking of failed login attempts, no lockout threshold. Brute-force attacks have unlimited attempts.
**Impact**: Credential stuffing and brute-force attacks are trivial.
**Recommendation**: Add `FAILED_ATTEMPTS` counter to USER_SESSIONS or EMPLOYEES. Lock after 5 failed attempts with exponential backoff. Add CAPTCHA integration.

---

### SEC-05: Timing Attack Vulnerability (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb:48-50`
```sql
-- VULNERABILITY: Timing attack - different response time for
-- invalid user vs invalid password
RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
```

**Issue**: The authentication flow exits early on invalid username (no hash computation) vs. invalid password (hash computation required). Attackers can enumerate valid usernames by measuring response time differences.
**Impact**: Username enumeration aids targeted attacks.
**Recommendation**: Always compute the password hash regardless of whether the user exists. Use constant-time comparison for hash matching.

---

### SEC-06: No Multi-Factor Authentication (HIGH)

**File**: `forms/xml-exports/HRMS_LOGIN.xml`

**Issue**: Single-factor authentication (username + password) with no support for 2FA, CAPTCHA, or SSO integration.
**Impact**: Compromised credentials grant full access.
**Recommendation**: Integrate TOTP/SMS 2FA. Consider migration to SSO (SAML/OIDC) for enterprise authentication.

---

### SEC-07: Hard-Coded SMTP Configuration (MEDIUM)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb:7-10`
```sql
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
c_from_name    CONSTANT VARCHAR2(100) := 'HRMS System';
```

**Issue**: SMTP configuration hard-coded in package body. Changes require package recompilation and redeployment. Port 25 indicates no TLS.
**Impact**: Environment portability issues. Unencrypted email transmission.
**Recommendation**: Move to SYSTEM_PARAMETERS table. Use port 587 with STARTTLS.

---

### SEC-08: FTP Credentials in Cleartext (MEDIUM)

**File**: `plsql/packages/PKG_INTEGRATION.pks:12`

**Issue**: Per package header comment, FTP credentials for file transfers are stored in SYSTEM_PARAMETERS table in cleartext.
**Impact**: Database read access exposes integration credentials.
**Recommendation**: Use Oracle Wallet for credential storage. Migrate from FTP to SFTP/SCP.

---

### SEC-09: Session Timeout Uses DB Server Time (MEDIUM)

**File**: `plsql/packages/PKG_SECURITY.pks:9`

**Issue**: Session timeout check compares against SYSDATE (database server time), not application server or client time. Clock skew between tiers can extend or shorten sessions unpredictably.
**Impact**: Sessions may remain active longer than intended or expire prematurely.
**Recommendation**: Use consistent time source. Consider token-based session management with absolute expiry.

---

### SEC-10: JSON Construction via String Concatenation (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:24-25`, `plsql/triggers/trg_audit.sql:20-29`
```sql
'{"package":"' || p_package || '","procedure":"' || p_procedure ||
'","message":"' || REPLACE(SUBSTR(p_message, 1, 3000), '"', '\"') || '"}'
```

**Issue**: Manual JSON construction via string concatenation. While REPLACE handles double-quotes, other special characters (backslash, newlines, control characters) can break JSON validity or enable log injection.
**Impact**: Corrupted audit records; potential log injection.
**Recommendation**: Use Oracle 19c JSON_OBJECT() or JSON_SERIALIZE() functions for safe JSON construction.

---

## 2. Race Conditions

### RACE-01: Employee Number Generation (HIGH)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:37-46`
```sql
-- BUG: race condition under concurrent inserts - no SELECT FOR UPDATE
FUNCTION generate_emp_number RETURN VARCHAR2 IS
    v_max_num NUMBER;
BEGIN
    SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
    INTO v_max_num
    FROM EMPLOYEES
    WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
```

**Issue**: Uses `MAX()+1` pattern without row-level locking. Two concurrent inserts can read the same MAX value and generate duplicate employee numbers. The `SEQ_EMP_NUMBER` sequence exists but is unused.
**Impact**: Duplicate employee numbers → unique constraint violation at INSERT time, or worse, two employees sharing a number if constraint is ever relaxed.
**Recommendation**: Replace with `SEQ_EMP_NUMBER.NEXTVAL` and format as `EMP-` || LPAD(seq, 6, '0'). Remove MAX() pattern entirely.

---

### RACE-02: Payroll Run Status Check Without Locking (MEDIUM)

**File**: `plsql/packages/PKG_PAYROLL.pkb:240-248`
```sql
SELECT STATUS INTO v_status
FROM PAY_PERIODS
WHERE PERIOD_ID = p_period_id;
-- No FOR UPDATE — another session could close the period between SELECT and INSERT
```

**Issue**: `create_payroll_run` checks period status without `FOR UPDATE`. A concurrent `close_pay_period` could close the period between the status check and the run insertion.
**Impact**: Payroll run created against a closed period.
**Recommendation**: Add `FOR UPDATE` to the status check SELECT, or use a single UPDATE ... RETURNING pattern.

---

## 3. Performance Issues

### PERF-01: Day-by-Day Cursor Loop in business_days_between (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:132-145`
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        v_count := v_count + 1;
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Issue**: O(n) loop where n = number of calendar days. For multi-year ranges (e.g., tenure calculations), this iterates through hundreds or thousands of days.
**Impact**: Slow performance for date ranges > 1 year. Called frequently by PKG_LEAVE and PKG_REPORTING.
**Recommendation**: Replace with set-based arithmetic: `TRUNC((end - start + 1) * 5/7)` adjusted for weekends, or use a calendar table.

---

### PERF-02: Day-by-Day Loop in add_business_days (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:151-164`

**Issue**: Same O(n) pattern as PERF-01 for adding business days.
**Recommendation**: Same set-based calculation approach.

---

### PERF-03: CONNECT BY Performance Degradation (MEDIUM)

**File**: `schema/views/hrms_views.sql:47-57`
```sql
-- WARNING: Performance degrades significantly with >500 employees
CREATE OR REPLACE VIEW HRMS.VW_ORG_HIERARCHY AS
...
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
```

**Issue**: Hierarchical query with `CONNECT BY` has O(n²) worst-case performance. Self-documented warning about degradation >500 employees.
**Impact**: Org chart rendering becomes unusably slow at scale.
**Recommendation**: Use recursive CTE (`WITH RECURSIVE`) available in Oracle 19c, or materialize the hierarchy in a closure table with periodic refresh.

---

### PERF-04: Per-Notification SMTP Connection (MEDIUM)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb:88-107`
```sql
FOR notif_rec IN (...) LOOP
    v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
    ...
    UTL_SMTP.QUIT(v_connection);
END LOOP;
```

**Issue**: Opens and closes a new SMTP connection for every notification. TCP handshake + TLS negotiation overhead multiplied by batch size (up to 50).
**Impact**: Queue processing is 10-50x slower than necessary. 5-minute interval may not clear backlog.
**Recommendation**: Open one connection, send all messages, then close. Use connection pooling.

---

### PERF-05: NOCACHE Sequences (LOW)

**File**: `schema/sequences/hrms_sequences.sql`

**Issue**: 28 of 29 sequences use `NOCACHE`. Each NEXTVAL requires a disk I/O to update the data dictionary.
**Impact**: Contention under concurrent inserts. Only SEQ_AUDIT (CACHE 100) is optimized.
**Recommendation**: Add `CACHE 20` or higher to frequently-used sequences (SEQ_EMPLOYEE, SEQ_PAYROLL_DETAIL, SEQ_LEAVE_REQUEST).

---

### PERF-06: Stale Denormalized Reporting Tables (LOW)

**File**: `plsql/packages/PKG_REPORTING.pks:9`

**Issue**: Reporting tables are refreshed only nightly. Business-hours queries show stale data.
**Impact**: Managers see outdated headcount/payroll data during the day.
**Recommendation**: Implement materialized views with `REFRESH ON DEMAND` at shorter intervals, or switch to real-time queries with proper indexes.

---

## 4. Validation Drift (PLL vs Server-Side)

### DRIFT-01: Email Validation Mismatch (HIGH)

**Client-side** (`forms/libraries/HRMS_VALIDATION_LIB.pll.sql:39`):
```sql
-- BUG: Only checks for one dot after @, rejects valid subdomains
-- Example: user@mail.company.com would be rejected
RETURN TRUE;  -- [simplified — actual code has broken regex]
```

**Server-side** (`plsql/packages/PKG_COMMON.pkb:267`):
```sql
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

**Issue**: PLL rejects valid emails with subdomains (e.g., `user@mail.company.com`). Server-side correctly validates them. Users cannot enter valid emails through the form.
**Impact**: Data entry blocked for users with subdomain email addresses.
**Recommendation**: Align PLL validation to use the same regex as PKG_COMMON, or remove client-side email validation and rely on server-side only.

---

### DRIFT-02: Salary Range Caching Inconsistency (MEDIUM)

**File**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:62-70`

**Issue**: Comment states salary ranges are cached for performance, but implementation queries the database directly every time. Misleading documentation.
**Impact**: No functional bug, but confusing for maintainers. If caching is later added based on the comment, stale cached values could allow invalid salaries.
**Recommendation**: Either implement the caching described in the comment, or correct the comment.

---

### DRIFT-03: Triple-Layer Validation Redundancy (MEDIUM)

**Files**: Forms WHEN-VALIDATE-ITEM triggers → HRMS_VALIDATION_LIB → PKG_VALIDATION → Database triggers (TRG_EMP_BEFORE_INSERT)

**Issue**: Business rules validated in three places with subtly different implementations:
1. Forms triggers (client-side, PLL-based)
2. PL/SQL packages (server-side, in PKG_VALIDATION/PKG_COMMON)
3. Database triggers (data-tier, in trg_employees.sql)

**Impact**: Rules can diverge. Example: trigger validates hire date ≤180 days future, but PLL only checks "is future date" without the 180-day limit.
**Recommendation**: Establish single source of truth (server-side packages) and have Forms call the same validation. Remove duplicate trigger-level validation where package validation already covers it.

---

### DRIFT-04: Date Validation Differences (LOW)

**Issue**: PLL `is_valid_date_range` only checks end ≥ start. Server-side PKG_LEAVE additionally checks for business days, holidays, and half-day logic. Forms users get weaker pre-validation.
**Impact**: User submits leave request that passes client validation but fails server validation → poor UX with cryptic error.
**Recommendation**: Add business-day awareness to client-side validation, or show clear server-side error messages.

---

## 5. Circular Dependencies

### CIRC-01: PKG_EMPLOYEE ↔ PKG_PAYROLL (HIGH)

**Files**:
- `plsql/packages/PKG_EMPLOYEE.pkb:9`: `"Circular dependency with PKG_PAYROLL (salary validation)"`
- `plsql/packages/PKG_PAYROLL.pks:9`: `"Circular dependency with PKG_EMPLOYEE (is_active check)"`

**Dependency Chain**:
- PKG_EMPLOYEE calls PKG_PAYROLL.validate_salary() during hire/promote
- PKG_PAYROLL calls PKG_EMPLOYEE.is_active_employee() during payroll calculation

**Impact**:
- Compilation order dependency (must compile both specs, then both bodies)
- Cascade invalidation risk
- Cannot deploy one package independently

**Recommendation**: Extract shared validation into a new `PKG_EMPLOYEE_PAYROLL_SHARED` package, or move `is_active_employee()` to PKG_COMMON, and salary range validation to PKG_VALIDATION.

---

## 6. Architectural Anti-Patterns

### ARCH-00: TRG_EMP_BEFORE_UPDATE Column Mismatch — Runtime ORA-00904 (CRITICAL)

**File**: `plsql/triggers/trg_employees.sql:78-85`
```sql
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (...)
```

**Issue**: The trigger inserts into EMPLOYEE_HISTORY using column names (`HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON`) that do not exist in the actual table definition (`schema/tables/01_core_tables.sql:152-177`). The real columns are `HIST_ID`, `EFFECTIVE_DATE`, `OLD_DEPT_ID/NEW_DEPT_ID/...`, `CREATED_BY`, `CREATED_DATE`. This will fail at runtime with ORA-00904 (invalid identifier) any time an employee status or department change is made.
**Impact**: Employee status changes and department transfers silently fail (or raise unhandled errors), meaning EMPLOYEE_HISTORY is never populated by this trigger path.
**Recommendation**: Rewrite trigger INSERTs to use the correct column names from the EMPLOYEE_HISTORY DDL. Consider whether the generic `OLD_VALUE/NEW_VALUE` pattern should be replaced with the structured column approach (OLD_DEPT_ID/NEW_DEPT_ID, OLD_SALARY/NEW_SALARY, etc.).

---

### ARCH-01: Soft-Delete Trigger Confusion (MEDIUM)

**File**: `plsql/triggers/trg_employees.sql:120-130`
```sql
-- BUG: This actually prevents deletion, but Forms expects DELETE to succeed.
-- Workaround in Forms: set ACTIVE_FLAG = 'N' then CLEAR_RECORD instead of DELETE_RECORD.
RAISE_APPLICATION_ERROR(-20504, 'Use soft delete...');
```

**Issue**: Trigger raises error on DELETE, forcing Forms to use workaround (UPDATE + CLEAR_RECORD instead of DELETE_RECORD). Confusing for developers.
**Recommendation**: Remove the trigger. Enforce soft-delete policy in PKG_EMPLOYEE and Forms layer only. Or use an INSTEAD OF trigger on a view.

---

### ARCH-02: Autonomous Transaction Overuse (MEDIUM)

**Files**: `PKG_AUDIT.pkb:14`, `PKG_NOTIFICATION.pkb:27`, `PKG_COMMON.pkb:16,46`

**Issue**: Multiple packages use `PRAGMA AUTONOMOUS_TRANSACTION` for logging and notifications. This means audit/notification records commit independently of the business transaction — if the main transaction rolls back, the audit record persists (phantom audit entries).
**Impact**: Audit log shows operations that never actually completed.
**Recommendation**: Use savepoints within the main transaction for audit logging. Reserve autonomous transactions only for true fire-and-forget operations.

---

### ARCH-03: UTL_FILE Flat File Integration (MEDIUM)

**File**: `plsql/packages/PKG_INTEGRATION.pkb`

**Issue**: GL posting and benefits feed use file-based integration (UTL_FILE writes to server filesystem). No retry logic, no checksums, no acknowledgment mechanism.
**Impact**: Silent data loss if files are corrupted, moved, or deleted before consumption. Environment dependency on Oracle directory objects.
**Recommendation**: Migrate to REST API or message queue (Oracle Advanced Queueing). Add file checksums and acknowledgment workflow.

---

### ARCH-04: Incomplete Time/Attendance Import (LOW)

**File**: `plsql/packages/PKG_INTEGRATION.pkb:170-171`
```sql
-- TODO: Implement actual parsing and database update
v_imported := v_imported + 1;
```

**Issue**: `import_time_attendance` reads the file but never actually parses or inserts data. The procedure is a stub.
**Impact**: Time/attendance data is not imported despite the job running.
**Recommendation**: Complete the implementation or remove the stub to avoid false confidence.

---

### ARCH-05: Hard-Coded Fiscal Year Start (LOW)

**File**: `plsql/packages/PKG_COMMON.pkb:174`
```sql
IF EXTRACT(MONTH FROM p_date) >= 10 THEN  -- Oct 1 = FY start
```

**Issue**: Fiscal year start date hard-coded as October 1. Any change to fiscal year requires code modification and redeployment.
**Impact**: Inflexible for organizations that change their fiscal year.
**Recommendation**: Move fiscal year start to SYSTEM_PARAMETERS.

---

## 7. Data Integrity Risks

### DATA-01: Cross-Year Leave Balance Lookup (HIGH)

**File**: `plsql/packages/PKG_LEAVE.pkb:182`
```sql
WHERE EMP_ID = p_emp_id
AND LEAVE_TYPE_ID = p_leave_type_id
AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```

**Issue**: Leave requests spanning Dec 31 → Jan 1 use the START_DATE year for balance lookup. Days in January are deducted from the previous year's balance.
**Impact**: Incorrect balance deductions for year-boundary leave requests.
**Recommendation**: Split cross-year requests into two balance adjustments, or use the calendar year of each individual leave day.

---

### DATA-02: Overlapping Leave Half-Day Gap (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pks:8`

**Issue**: Overlap detection (`check_leave_overlap`) does not account for half-day requests. An employee with approved AM half-day leave could be blocked from requesting PM half-day on the same date.
**Impact**: Users unable to take both AM and PM half-days on the same date (or conversely, could take overlapping full + half days).
**Recommendation**: Modify overlap check to consider HALF_DAY_FLAG and HALF_DAY_PERIOD.

---

### DATA-03: Carryover Double-Expiry (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pks:11`

**Issue**: Leave carryover expiry job can double-expire balances if run twice on the same day (no idempotency check).
**Impact**: Employees lose legitimate leave balance.
**Recommendation**: Add `LAST_EXPIRY_RUN_DATE` tracking or use idempotent UPDATE with a processed flag.

---

### DATA-04: Holiday Observed Date Mismatch (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pkb:9-11`
```sql
-- BUG: Does not handle 'observed' holidays
-- Example: Christmas on Saturday -> observed Friday is not detected
```

**Issue**: Holiday check uses exact date match only. Holidays falling on weekends are not detected by their observed weekday equivalent.
**Impact**: Business day calculations include observed holiday dates as working days, understating leave usage.
**Recommendation**: Add `OBSERVED_DATE` column to HOLIDAYS table, or implement observed-date logic (Friday for Saturday holidays, Monday for Sunday holidays).

---

### DATA-05: YTD Accumulation Mid-Year Hire Issue (LOW)

**File**: `plsql/packages/PKG_PAYROLL.pks:12`

**Issue**: Per package header, YTD (year-to-date) accumulation resets incorrectly for mid-year hires in some edge cases.
**Impact**: Incorrect tax withholding for employees hired mid-year.
**Recommendation**: Initialize YTD based on prior-employer reported amounts (W-2 data) or explicitly start from zero with correct bracket calculations.

---

### DATA-06: Overtime Holiday Calculation Error (LOW)

**File**: `plsql/packages/PKG_PAYROLL.pks:11`

**Issue**: Overtime calculation does not account for holidays correctly. Holiday hours may be miscategorized as regular or overtime.
**Impact**: Incorrect overtime pay for holiday workers.
**Recommendation**: Integrate holiday calendar into overtime calculation logic.

---

### DATA-07: VW_LEAVE_SUMMARY AVAILABLE Omits PENDING (MEDIUM)

**Files**: `schema/views/hrms_views.sql:96` vs `schema/tables/03_leave_tables.sql:47`

**Issue**: The `LEAVE_BALANCES.AVAILABLE` virtual column is defined as `OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING`, but `VW_LEAVE_SUMMARY` computes AVAILABLE as `OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT` — omitting `- PENDING`. Querying the table directly returns a different available balance than querying the view.
**Impact**: Managers viewing leave summaries via the view see inflated available balances that include pending (unapproved) requests. Approval decisions may be made on incorrect availability.
**Recommendation**: Align the view calculation to include `- PENDING`, matching the virtual column definition: `lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT - lb.PENDING AS AVAILABLE`.

---

## 8. Severity Summary

| ID | Category | Description | Severity | File | Recommended Fix |
|----|----------|-------------|----------|------|----------------|
| SEC-01 | Security | MD5 password hashing | CRITICAL | PKG_SECURITY.pkb:18 | Migrate to bcrypt/scrypt |
| SEC-02 | Security | Hard-coded encryption key in source | CRITICAL | PKG_SECURITY.pkb:7 | Oracle Wallet/Key Vault |
| SEC-03 | Security | Cleartext password transmission | CRITICAL | HRMS_LOGIN.xml:75 | Enable network encryption |
| SEC-04 | Security | No account lockout | HIGH | PKG_SECURITY.pkb | Add failed attempt tracking |
| SEC-05 | Security | Timing attack on authentication | HIGH | PKG_SECURITY.pkb:48 | Constant-time comparison |
| SEC-06 | Security | No 2FA/MFA support | HIGH | HRMS_LOGIN.xml | Add TOTP/SSO |
| SEC-07 | Security | Hard-coded SMTP config | MEDIUM | PKG_NOTIFICATION.pkb:7 | Move to SYSTEM_PARAMETERS |
| SEC-08 | Security | FTP credentials in cleartext | MEDIUM | PKG_INTEGRATION.pks:12 | Oracle Wallet |
| SEC-09 | Security | Session timeout clock skew | MEDIUM | PKG_SECURITY.pks:9 | Consistent time source |
| SEC-10 | Security | JSON string concatenation (log injection) | MEDIUM | PKG_COMMON.pkb:24 | Use JSON_OBJECT() |
| RACE-01 | Race Condition | Employee number MAX()+1 | HIGH | PKG_EMPLOYEE.pkb:39 | Use sequence |
| RACE-02 | Race Condition | Payroll period status check | MEDIUM | PKG_PAYROLL.pkb:240 | Add FOR UPDATE |
| PERF-01 | Performance | Day-by-day business days loop | MEDIUM | PKG_COMMON.pkb:132 | Set-based arithmetic |
| PERF-02 | Performance | Day-by-day add_business_days loop | MEDIUM | PKG_COMMON.pkb:151 | Set-based arithmetic |
| PERF-03 | Performance | CONNECT BY org hierarchy | MEDIUM | hrms_views.sql:47 | Recursive CTE / closure table |
| PERF-04 | Performance | Per-notification SMTP connection | MEDIUM | PKG_NOTIFICATION.pkb:88 | Connection reuse |
| PERF-05 | Performance | NOCACHE sequences | LOW | hrms_sequences.sql | Add CACHE 20 |
| PERF-06 | Performance | Stale reporting tables | LOW | PKG_REPORTING.pks:9 | Materialized views |
| DRIFT-01 | Validation Drift | Email regex mismatch PLL vs server | HIGH | HRMS_VALIDATION_LIB:39 | Align to server regex |
| DRIFT-02 | Validation Drift | Salary caching comment vs code | MEDIUM | HRMS_VALIDATION_LIB:62 | Fix comment or implement |
| DRIFT-03 | Validation Drift | Triple-layer redundancy | MEDIUM | Multiple files | Single source of truth |
| DRIFT-04 | Validation Drift | Date validation differences | LOW | Multiple files | Align client/server |
| CIRC-01 | Circular Dep | PKG_EMPLOYEE ↔ PKG_PAYROLL | HIGH | PKG_EMPLOYEE.pkb:9 | Extract shared package |
| ARCH-00 | Architecture | TRG_EMP_BEFORE_UPDATE column mismatch (ORA-00904) | CRITICAL | trg_employees.sql:78 | Rewrite INSERTs with correct columns |
| ARCH-01 | Architecture | Soft-delete trigger confusion | MEDIUM | trg_employees.sql:120 | Remove or use INSTEAD OF view |
| ARCH-02 | Architecture | Autonomous transaction overuse | MEDIUM | PKG_AUDIT.pkb:14 | Savepoints |
| ARCH-03 | Architecture | UTL_FILE flat file integration | MEDIUM | PKG_INTEGRATION.pkb | REST API / message queue |
| ARCH-04 | Architecture | Stub time/attendance import | LOW | PKG_INTEGRATION.pkb:170 | Complete or remove |
| ARCH-05 | Architecture | Hard-coded fiscal year | LOW | PKG_COMMON.pkb:174 | SYSTEM_PARAMETERS |
| DATA-01 | Data Integrity | Cross-year leave balance | HIGH | PKG_LEAVE.pkb:182 | Split by calendar year |
| DATA-02 | Data Integrity | Half-day overlap gap | MEDIUM | PKG_LEAVE.pks:8 | Enhance overlap check |
| DATA-03 | Data Integrity | Carryover double-expiry | MEDIUM | PKG_LEAVE.pks:11 | Idempotency check |
| DATA-04 | Data Integrity | Holiday observed date | MEDIUM | PKG_LEAVE.pkb:9 | Add OBSERVED_DATE |
| DATA-05 | Data Integrity | YTD mid-year hire | LOW | PKG_PAYROLL.pks:12 | Init from prior W-2 |
| DATA-06 | Data Integrity | Overtime holiday calc | LOW | PKG_PAYROLL.pks:11 | Integrate holiday calendar |
| DATA-07 | Data Integrity | VW_LEAVE_SUMMARY AVAILABLE omits PENDING | MEDIUM | hrms_views.sql:96 | Add `- PENDING` to view |

---

## 9. Migration Priority Recommendation

### Phase 1: Immediate Security Hardening (1-2 weeks)

| Priority | Item | Effort | Risk if Deferred |
|----------|------|--------|-----------------|
| 1 | SEC-02: Rotate hard-coded encryption key → Oracle Wallet | 3 days | Total PII exposure |
| 2 | SEC-01: Replace MD5 with SHA-256 + salt (interim) → bcrypt (final) | 2 days | Password compromise |
| 3 | SEC-03: Enable Oracle Net encryption | 1 day | MITM credential theft |
| 4 | SEC-04: Add account lockout (5 attempts, 30-min lock) | 2 days | Brute-force |
| 5 | SEC-05: Fix timing attack (constant-time compare) | 1 day | Username enumeration |

### Phase 2: Data Integrity & Race Conditions (2-4 weeks)

| Priority | Item | Effort | Risk if Deferred |
|----------|------|--------|-----------------|
| 1 | RACE-01: Replace MAX()+1 with SEQ_EMP_NUMBER | 0.5 day | Duplicate emp numbers |
| 2 | DATA-01: Fix cross-year leave balance | 1 day | Incorrect balances |
| 3 | CIRC-01: Resolve circular dependency | 3 days | Cascade invalidation |
| 4 | DRIFT-01: Align email validation | 0.5 day | Blocked data entry |
| 5 | DATA-03: Make carryover expiry idempotent | 1 day | Lost leave balance |
| 6 | RACE-02: Add FOR UPDATE to period check | 0.5 day | Invalid payroll runs |

### Phase 3: Performance & Architecture (1-3 months)

| Priority | Item | Effort | Risk if Deferred |
|----------|------|--------|-----------------|
| 1 | PERF-04: SMTP connection reuse | 1 day | Notification delays |
| 2 | PERF-01/02: Replace date loops with arithmetic | 2 days | Slow leave calculations |
| 3 | PERF-03: Replace CONNECT BY with recursive CTE | 2 days | Slow org chart |
| 4 | ARCH-03: Migrate UTL_FILE to REST/AQ | 2 weeks | Silent data loss |
| 5 | DRIFT-03: Consolidate validation to single layer | 1 week | Maintenance burden |
| 6 | SEC-07/08: Externalize config and credentials | 3 days | Portability |

### Phase 4: Full Modernization (6-12 months)

| Priority | Item | Effort | Description |
|----------|------|--------|-------------|
| 1 | Migrate Forms to modern web framework | 3-6 months | APEX, React, or Angular frontend |
| 2 | Implement proper session management (JWT/OAuth) | 1 month | Replace USER_SESSIONS pattern |
| 3 | Add 2FA/SSO (SEC-06) | 2 weeks | Enterprise SSO integration |
| 4 | Replace PL/SQL business logic with microservices | 3-6 months | API-first architecture |
| 5 | Implement event-driven integration (replace flat files) | 1 month | Real-time GL/benefits sync |
| 6 | Add comprehensive automated testing | 2 months | utPLSQL or similar framework |
