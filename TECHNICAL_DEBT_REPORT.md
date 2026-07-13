# Technical Debt Report — Oracle Forms/PL/SQL HRMS Estate

## Executive Summary

This report catalogs **36 identified technical debt items** across the Oracle Forms/PL/SQL HRMS application, including 10 security vulnerabilities, 2 race conditions, 6 performance issues, 4 validation drift items, 1 circular dependency, 6 architectural anti-patterns, and 7 data integrity risks.

| Severity | Count | Categories |
|----------|-------|------------|
| CRITICAL | 7 | Security (MD5, hard-coded key, cleartext transmission), trigger column mismatch |
| HIGH | 10 | Race conditions, timing attack, no lockout, validation drift |
| MEDIUM | 13 | Performance, architectural anti-patterns, stale data |
| LOW | 6 | Configuration, incomplete implementations |

### Category Breakdown

| Category | Items | IDs |
|----------|-------|-----|
| Security | 10 | SEC-01 … SEC-10 |
| Race Conditions | 2 | RACE-01, RACE-02 |
| Performance | 6 | PERF-01 … PERF-06 |
| Validation Drift | 4 | DRIFT-01 … DRIFT-04 |
| Circular Dependencies | 1 | CIRC-01 |
| Architectural Anti-Patterns | 6 | ARCH-00 … ARCH-05 |
| Data Integrity | 7 | DATA-01 … DATA-07 |

---

## 1. Security Vulnerabilities

### SEC-01: MD5 Password Hashing (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:18-23`
```sql
RETURN RAWTOHEX(
    DBMS_CRYPTO.HASH(
        UTL_RAW.CAST_TO_RAW(p_password),
        DBMS_CRYPTO.HASH_MD5
    )
);
```

**Issue**: MD5 is cryptographically broken. Rainbow table attacks can crack MD5 hashes in seconds. No salt is applied.
**Impact**: Complete password database compromise if the credential store is leaked.
**Recommendation**: Migrate to bcrypt, scrypt, or PBKDF2 with per-user salt. Oracle 19c supports `DBMS_CRYPTO.HASH_SH256` as a minimum interim upgrade, but proper password hashing (bcrypt) requires external integration.

---

### SEC-02: Hard-Coded Encryption Key (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:7`
```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```

**Issue**: AES encryption key stored as a string constant in source code. Any developer, DBA, or source-control reader can decrypt all SSN data.
**Impact**: Total PII exposure. Regulatory violation (SOX, PCI-DSS, HIPAA).
**Recommendation**: Move to Oracle Wallet / Key Vault. Use Oracle Transparent Data Encryption (TDE) or externalize key management via HSM. Rotate the compromised key immediately.

---

### SEC-03: Cleartext Password Transmission (CRITICAL)

**File**: `forms/xml-exports/HRMS_LOGIN.xml`

**Issue**: The password is sent from the Forms client to the database via SQL*Net without application-layer encryption. `PKG_SECURITY.authenticate` receives `p_password` in cleartext. Network sniffing exposes credentials.
**Impact**: Credential theft via MITM attack on the internal network.
**Recommendation**: Enable Oracle Net encryption (native network encryption or TLS), or implement client-side hashing before transmission.

---

### SEC-04: No Account Lockout (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb:26-30` (authenticate), `plsql/packages/PKG_SECURITY.pks` (`e_account_locked` declared but never raised)

**Issue**: No tracking of failed login attempts, no lockout threshold. The `e_account_locked` exception is declared in the spec but no code path ever tracks failures or locks an account. Brute-force attacks have unlimited attempts.
**Impact**: Credential stuffing and brute-force attacks are trivial.
**Recommendation**: Add a `FAILED_ATTEMPTS` counter, lock after 5 failed attempts with exponential backoff, and actually raise `e_account_locked`.

---

### SEC-05: Timing Attack Vulnerability (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb` (authenticate flow)

**Issue**: The authentication flow exits early on an invalid username (no hash computation) versus an invalid password (hash computation required). Attackers can enumerate valid usernames by measuring response-time differences.
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

**Issue**: SMTP configuration hard-coded in the package body. Changes require package recompilation and redeployment. Port 25 indicates no TLS.
**Impact**: Environment portability issues. Unencrypted email transmission.
**Recommendation**: Move to the `SYSTEM_PARAMETERS` table. Use port 587 with STARTTLS.

---

### SEC-08: FTP Credentials in Cleartext (MEDIUM)

**File**: `plsql/packages/PKG_INTEGRATION.pks` (package header comment)

**Issue**: Per the package header, FTP credentials for file transfers are stored in `SYSTEM_PARAMETERS` in cleartext.
**Impact**: Database read access exposes integration credentials.
**Recommendation**: Use Oracle Wallet for credential storage. Migrate from FTP to SFTP/SCP.

---

### SEC-09: Session Timeout Uses DB Server Time (MEDIUM)

**File**: `plsql/packages/PKG_SECURITY.pks` (header note), `PKG_SECURITY.pkb` (`c_session_timeout_min`, session validity check)

**Issue**: The session timeout check compares against `SYSDATE` (database server time), not application-server or client time. Clock skew between tiers can extend or shorten sessions unpredictably.
**Impact**: Sessions may remain active longer than intended or expire prematurely.
**Recommendation**: Use a consistent time source. Consider token-based session management with absolute expiry.

---

### SEC-10: JSON Construction via String Concatenation (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:24-25`, `plsql/triggers/trg_audit.sql`
```sql
'{"package":"' || p_package || '","procedure":"' || p_procedure ||
'","message":"' || REPLACE(SUBSTR(p_message, 1, 3000), '"', '\"') || '"}'
```

**Issue**: Manual JSON construction via string concatenation. `log_info` (`PKG_COMMON.pkb:53-54`) does not even escape quotes. Backslashes, newlines, control characters, NULLs, and unformatted numerics can break JSON validity or enable log injection. The salary audit trigger builds JSON the same way with raw numeric/date interpolation.
**Impact**: Corrupted audit records; potential log injection; invalid JSON under non-American NLS settings.
**Recommendation**: Use Oracle 19c `JSON_OBJECT()` / `JSON_SERIALIZE()` for safe JSON construction.

---

## 2. Race Conditions

### RACE-01: Employee Number Generation via MAX()+1 (HIGH)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb` (generate_emp_number)
```sql
SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
INTO v_max_num
FROM EMPLOYEES
WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';

v_new_number := c_emp_number_prefix || '-' || LPAD(v_max_num, 6, '0');
```

**Issue**: Uses the `MAX()+1` pattern without row-level locking. Two concurrent inserts can read the same MAX value and generate duplicate employee numbers. The dedicated `SEQ_EMP_NUMBER` sequence exists but is unused; the `WHEN OTHERS` fallback even uses the wrong sequence (`SEQ_EMPLOYEE`). `schema/sequences/hrms_sequences.sql` explicitly documents this bug.
**Impact**: Duplicate employee numbers → unique-constraint violation at INSERT time under concurrency.
**Recommendation**: Replace with `SEQ_EMP_NUMBER.NEXTVAL` formatted as `EMP-` || `LPAD(seq, 6, '0')`. Remove the `MAX()` pattern entirely.

---

### RACE-02: Payroll Period Status Check Without Locking (MEDIUM)

**File**: `plsql/packages/PKG_PAYROLL.pkb` (create_payroll_run)
```sql
SELECT STATUS INTO v_status
FROM PAY_PERIODS
WHERE PERIOD_ID = p_period_id;
-- No FOR UPDATE — another session could close the period between SELECT and INSERT
```

**Issue**: `create_payroll_run` reads the period status without `FOR UPDATE`, then inserts a run. A concurrent state change (or another `create_payroll_run`) could occur between the check and the insert. Note that `approve_payroll` *does* correctly use `FOR UPDATE`, highlighting the inconsistency.
**Impact**: Payroll run created against a period that was concurrently closed, or duplicate runs for one period.
**Recommendation**: Add `FOR UPDATE` to the status-check SELECT, or use a single `UPDATE ... RETURNING` pattern plus an application-level uniqueness guard.

---

## 3. Performance Issues

### PERF-01: Day-by-Day Cursor Loop in business_days_between (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:132-146`
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        v_count := v_count + 1;
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Issue**: O(n) loop where n = number of calendar days. `PKG_LEAVE.calculate_business_days` compounds this by issuing a per-day `SELECT COUNT(*) FROM HOLIDAYS` inside the loop.
**Impact**: Slow performance for multi-year ranges; per-day holiday queries multiply DB round-trips.
**Recommendation**: Replace with set-based arithmetic (`TRUNC((end - start + 1) * 5/7)` adjusted for weekends) or a calendar table; join holidays once instead of per-iteration.

---

### PERF-02: Day-by-Day Loop in add_business_days (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:151-165`

**Issue**: Same O(n) day-increment pattern as PERF-01 for adding business days.
**Recommendation**: Same set-based calculation approach.

---

### PERF-03: CONNECT BY Org-Hierarchy Performance (MEDIUM)

**File**: `schema/views/hrms_views.sql:47-57`
```sql
-- WARNING: Performance degrades significantly with >500 employees
CREATE OR REPLACE VIEW HRMS.VW_ORG_HIERARCHY AS
...
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
```

**Issue**: Hierarchical query with `CONNECT BY` and `SYS_CONNECT_BY_PATH` has poor worst-case performance; a self-documented warning notes degradation above 500 employees.
**Impact**: Org-chart rendering becomes unusably slow at scale.
**Recommendation**: Use a recursive CTE (`WITH ... UNION ALL`) available in Oracle 19c, or materialize the hierarchy in a closure table with periodic refresh.

---

### PERF-04: Per-Notification SMTP Connection (MEDIUM)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb` (process_notification_queue)
```sql
FOR notif_rec IN (...) LOOP
    v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
    ...
    UTL_SMTP.QUIT(v_connection);
END LOOP;
```

**Issue**: Opens and closes a new SMTP connection for every notification — TCP handshake + HELO overhead multiplied by batch size.
**Impact**: Queue processing is many times slower than necessary; interval may not clear backlog.
**Recommendation**: Open one connection, send all queued messages, then close. Consider connection pooling. Also claim/lock queue rows before processing to avoid duplicate sends by concurrent workers.

---

### PERF-05: NOCACHE Sequences (LOW)

**File**: `schema/sequences/hrms_sequences.sql`

**Issue**: Nearly all sequences are declared `NOCACHE`. Each `NEXTVAL` requires a data-dictionary disk I/O.
**Impact**: Contention under concurrent inserts.
**Recommendation**: Add `CACHE 20` (or higher) to frequently-used sequences (`SEQ_EMPLOYEE`, `SEQ_PAYROLL_DETAIL`, `SEQ_LEAVE_REQUEST`, `SEQ_USER_SESSION`).

---

### PERF-06: Stale Denormalized Reporting Tables (LOW)

**File**: `plsql/packages/PKG_REPORTING.pks` (header), `PKG_REPORTING.pkb` (`refresh_reporting_tables`)

**Issue**: Reporting tables are refreshed only nightly, and `refresh_reporting_tables` is effectively a stub that logs success without refreshing. Business-hours queries show stale data.
**Impact**: Managers see outdated headcount/payroll data during the day.
**Recommendation**: Implement materialized views with scheduled refresh, or switch to real-time queries with proper indexes; complete or remove the stub.

---

## 4. Validation Drift (PLL vs Server-Side)

### DRIFT-01: Email Validation Mismatch (HIGH)

**Client-side** (`forms/libraries/HRMS_VALIDATION_LIB.pll.sql`): `INSTR`-based check that looks for a single dot after `@` and rejects valid subdomain addresses (e.g. `user@mail.company.com`), per its own comments.

**Server-side** (`plsql/packages/PKG_COMMON.pkb:267`):
```sql
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

**Issue**: The PLL rejects valid emails with subdomains that the server-side regex accepts. Users cannot enter valid emails through the form.
**Impact**: Data entry blocked for users with subdomain email addresses; client/server disagreement.
**Recommendation**: Align the PLL to the same regex as `PKG_COMMON.is_valid_email`, or remove client-side email validation and rely on the server.

---

### DRIFT-02: Salary Range Caching Inconsistency (MEDIUM)

**File**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql` (validate_salary_for_grade)

**Issue**: The comment states salary ranges are cached at form startup for performance, but the implementation queries `JOB_GRADES` directly on every call. Misleading documentation.
**Impact**: No functional bug today, but if caching is later added based on the comment, stale cached values could allow invalid salaries.
**Recommendation**: Either implement the caching described in the comment or correct the comment.

---

### DRIFT-03: Salary Range Enforcement Divergence (MEDIUM)

**Files**: `plsql/packages/PKG_EMPLOYEE.pkb` (create_employee) vs `plsql/packages/PKG_VALIDATION.pkb` (validate_salary_for_grade) / `HRMS_VALIDATION_LIB.pll.sql`

**Issue**: `PKG_EMPLOYEE.create_employee` treats an out-of-range salary as a *soft warning* (`-- NOTE: This is a soft warning, not an error`) and proceeds, while `PKG_VALIDATION.validate_salary_for_grade` and the PLL both *return an error* for the same condition. The three layers disagree on whether out-of-range salaries are allowed.
**Impact**: Salaries outside the grade band can be persisted through the server API even though every validation layer flags them, defeating the control.
**Recommendation**: Establish a single source of truth (server-side package) and enforce it consistently; make `create_employee` reject or explicitly override with an audit trail.

---

### DRIFT-04: Date Validation Differences (LOW)

**Files**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql` vs `plsql/packages/PKG_VALIDATION.pkb` / `PKG_LEAVE.pkb`

**Issue**: The PLL date check only verifies `date <= SYSDATE` (or end ≥ start). Server-side leave logic additionally applies business-day, holiday, and half-day rules. Forms users get weaker pre-validation, and the DB trigger enforces a 180-day future-hire limit not present client-side.
**Impact**: A request that passes client validation can fail server validation → poor UX with cryptic errors.
**Recommendation**: Add the same business-day/range awareness to client-side validation, or surface clear server-side error messages.

---

## 5. Circular Dependencies

### CIRC-01: PKG_EMPLOYEE ↔ PKG_PAYROLL (HIGH)

**Files**:
- `plsql/packages/PKG_EMPLOYEE.pks:9`: `"Circular dependency with PKG_PAYROLL (salary validation)"` (declares `PKG_PAYROLL` as a dependency)
- `plsql/packages/PKG_PAYROLL.pks:9`: `"Circular dependency with PKG_EMPLOYEE (is_active check)"` (declares `PKG_EMPLOYEE` as a dependency)

**Dependency Chain**:
- `PKG_EMPLOYEE` calls into `PKG_PAYROLL` (salary validation / salary-record creation) during hire/promote.
- `PKG_PAYROLL` calls `PKG_EMPLOYEE.is_active` during payroll calculation.

**Impact**: Compilation-order coupling (both specs, then both bodies); cascade invalidation risk; neither package can be deployed independently.
**Recommendation**: Extract shared logic — move `is_active` to `PKG_COMMON` and salary-range validation to `PKG_VALIDATION`, or introduce a dedicated shared package to break the cycle.

---

## 6. Architectural Anti-Patterns

### ARCH-00: TRG_EMP_BEFORE_UPDATE Column Mismatch — Runtime ORA-00904 (CRITICAL)

**File**: `plsql/triggers/trg_employees.sql:78-110`
```sql
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (...)
```

**Issue**: `TRG_EMP_BEFORE_UPDATE` inserts into `EMPLOYEE_HISTORY` using columns (`HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON`) that **do not exist** in the actual DDL (`schema/tables/01_core_tables.sql`). The real columns are `HIST_ID`, `EFFECTIVE_DATE`, structured `OLD_*/NEW_*` fields (`OLD_DEPT_ID`, `NEW_DEPT_ID`, `OLD_JOB_ID`, `NEW_JOB_ID`, `OLD_SALARY`, …), `REASON_CODE`/`COMMENTS`, and `CREATED_BY`/`CREATED_DATE`. All three INSERT blocks (status, department, job changes) will fail with ORA-00904. The `CHANGE_TYPE` literals (`'DEPARTMENT_CHANGE'`, `'JOB_CHANGE'`) may also violate the table's check constraint.
**Impact**: Every employee status change, department transfer, and job change raises an unhandled error — updates are blocked, and `EMPLOYEE_HISTORY` is never populated by this path.
**Recommendation**: Rewrite the trigger INSERTs to use the real `EMPLOYEE_HISTORY` columns and the structured `OLD_*/NEW_*` model, and align `CHANGE_TYPE` values with the check constraint.

---

### ARCH-01: Soft-Delete Trigger Confusion (MEDIUM)

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

**Issue**: The trigger is named `INSTEAD_OF_DELETE` but is actually a `BEFORE DELETE` trigger that simply raises an error rather than performing a soft delete. Comments describe a Forms workaround (set `ACTIVE_FLAG = 'N'` then `CLEAR_RECORD`). Naming and behavior are misleading.
**Impact**: Confusing for developers; delete semantics are enforced by exception rather than a clean soft-delete policy.
**Recommendation**: Rename and/or implement true soft delete in `PKG_EMPLOYEE` and the Forms layer, or use an `INSTEAD OF` trigger on a view.

---

### ARCH-02: Autonomous Transaction Overuse (MEDIUM)

**Files**: `PKG_AUDIT.pkb:14`, `PKG_COMMON.pkb:16` (log_error), `PKG_COMMON.pkb:46` (log_info), `PKG_NOTIFICATION.pkb`, `PKG_EMPLOYEE.pkb` (history logging)

**Issue**: Multiple packages use `PRAGMA AUTONOMOUS_TRANSACTION` for logging/notifications/history. These commit independently of the business transaction — if the main transaction rolls back, the audit/log record persists (phantom entries). Conversely, `PKG_EMPLOYEE` history logging swallows failures in `WHEN OTHERS`, so the main transaction can commit without a history row.
**Impact**: Audit log shows operations that never completed, or misses ones that did.
**Recommendation**: Use savepoints within the main transaction for audit logging; reserve autonomous transactions for true fire-and-forget operations and stop swallowing errors silently.

---

### ARCH-03: UTL_FILE Flat-File Integration (MEDIUM)

**File**: `plsql/packages/PKG_INTEGRATION.pkb` (GL feed, benefits feed), `PKG_PAYROLL.pkb` (generate_pay_register)

**Issue**: GL posting, benefits feed, and the pay register use file-based integration via `UTL_FILE` to hard-coded Oracle directory objects (`GL_FEED_OUT`, `BENEFITS_FEED_OUT`, `PAYROLL_OUTPUT`). No retry logic, checksums, or acknowledgment mechanism.
**Impact**: Silent data loss if files are corrupted, moved, or deleted before consumption; environment dependency on directory objects.
**Recommendation**: Migrate to REST API or Oracle Advanced Queueing; add checksums and an acknowledgment workflow.

---

### ARCH-04: Incomplete/Stub Implementations (LOW)

**Files**: `plsql/packages/PKG_INTEGRATION.pkb:170-171` (import_time_attendance), `PKG_INTEGRATION.pkb` (org-structure sync placeholder), `PKG_SECURITY.pkb:230-231` (change_password stub), `PKG_REPORTING.pkb` (refresh_reporting_tables)
```sql
-- TODO: Implement actual parsing and database update
v_imported := v_imported + 1;
```

**Issue**: Several procedures read inputs but never persist results, yet report success. `import_time_attendance` increments a counter without parsing/inserting; org-structure sync is a placeholder; `change_password` is a stub; `refresh_reporting_tables` logs success without refreshing.
**Impact**: Jobs report success while doing nothing — false confidence and silent data gaps.
**Recommendation**: Complete the implementations or remove the stubs so callers do not assume work was done.

---

### ARCH-05: Hard-Coded Fiscal Year & Tax Assumptions (LOW)

**Files**: `plsql/packages/PKG_COMMON.pkb:174` (fiscal year), `plsql/packages/PKG_PAYROLL.pkb:7-x, 605, 643-644` (2024 tax constants/brackets)
```sql
IF EXTRACT(MONTH FROM p_date) >= 10 THEN  -- Oct 1 = FY start
...
c_ss_wage_base_2024 CONSTANT NUMBER := 168600;
-- 2024 Federal tax brackets (Single)
-- TODO: Read from TAX_BRACKETS table instead of hard-coding
```

**Issue**: Fiscal-year start (October 1) and 2024 federal tax brackets, standard deductions, SS wage base, and Medicare thresholds are hard-coded in package source, despite an existing `TAX_BRACKETS` table.
**Impact**: Annual tax updates and any fiscal-year change require code modification and redeployment; risk of stale tax logic.
**Recommendation**: Move fiscal-year start to `SYSTEM_PARAMETERS` and read tax brackets from the `TAX_BRACKETS` table.

---

## 7. Data Integrity Risks

### DATA-01: Cross-Year Leave Balance Lookup (HIGH)

**File**: `plsql/packages/PKG_LEAVE.pkb` (get_leave_balance)
```sql
WHERE EMP_ID = p_emp_id
AND LEAVE_TYPE_ID = p_leave_type_id
AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```

**Issue**: Leave requests spanning Dec 31 → Jan 1 use the `START_DATE` year for the balance lookup, so January days are deducted from the previous year's balance.
**Impact**: Incorrect balance deductions for year-boundary leave requests.
**Recommendation**: Split cross-year requests into two balance adjustments, or use each leave day's own calendar year.

---

### DATA-02: Overlapping Leave Half-Day Gap (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pkb` (check_leave_overlap), `PKG_LEAVE.pks:8`

**Issue**: Overlap detection does not account for `HALF_DAY_FLAG`/half-day period. An employee with an approved AM half-day could be blocked from a PM half-day on the same date (or vice-versa allow invalid overlaps).
**Impact**: Users cannot take both AM and PM half-days on the same date, or overlapping full+half days slip through.
**Recommendation**: Include `HALF_DAY_FLAG`/period in the overlap check.

---

### DATA-03: Carryover Double-Expiry (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pkb:606-623` (expire_carryover)
```sql
-- BUG: If run twice on same day, can double-subtract
UPDATE LEAVE_BALANCES SET
    ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
    CARRYOVER_FROM_PREV = 0,
    ...
WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE)
AND CARRYOVER_FROM_PREV > 0;
```

**Issue**: The expiry job subtracts `CARRYOVER_FROM_PREV` from `ADJUSTMENT` and zeroes it, but has no run-tracking. The guard `CARRYOVER_FROM_PREV > 0` mitigates a same-day re-run, yet there is no idempotency/processed-flag guarantee across scenarios.
**Impact**: Risk of employees losing legitimate leave balance if the logic is altered or partially re-run.
**Recommendation**: Add `LAST_EXPIRY_RUN_DATE` tracking or a processed flag to guarantee idempotency.

---

### DATA-04: Holiday Observed-Date Mismatch (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pkb:9-11` (comments), `calculate_business_days`
```sql
-- BUG: Does not handle 'observed' holidays
-- Example: Christmas on Saturday -> observed Friday is not detected
```

**Issue**: The holiday check uses an exact date match only. Holidays falling on weekends are not detected by their observed weekday equivalent.
**Impact**: Business-day calculations count observed holiday dates as working days, understating leave usage.
**Recommendation**: Add an `OBSERVED_DATE` column to `HOLIDAYS`, or implement observed-date logic (Friday for Saturday, Monday for Sunday).

---

### DATA-05: YTD Accumulation Mid-Year Hire Issue (LOW)

**File**: `plsql/packages/PKG_PAYROLL.pks:12` (header), `PKG_PAYROLL.pkb` (get_ytd_earnings)

**Issue**: Per the package header, YTD accumulation resets incorrectly for mid-year hires in some edge cases; `get_ytd_earnings` sums by `PERIOD_START_DATE` year with no prior-employer basis.
**Impact**: Incorrect tax withholding for employees hired mid-year.
**Recommendation**: Initialize YTD from prior-employer reported amounts (W-2) or explicitly start from zero with correct bracket handling.

---

### DATA-06: Overtime Holiday Calculation Error (LOW)

**File**: `plsql/packages/PKG_PAYROLL.pks:11` (header)

**Issue**: Overtime calculation does not account for holidays correctly; holiday hours may be miscategorized as regular or overtime.
**Impact**: Incorrect overtime pay for holiday workers.
**Recommendation**: Integrate the holiday calendar into the overtime calculation logic.

---

### DATA-07: VW_LEAVE_SUMMARY AVAILABLE Omits PENDING (MEDIUM)

**Files**: `schema/views/hrms_views.sql:96` vs `schema/tables/03_leave_tables.sql:47`

**Issue**: The `LEAVE_BALANCES.AVAILABLE` virtual column is `OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING`, but `VW_LEAVE_SUMMARY` computes `AVAILABLE` as `OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT` — omitting `- PENDING`. The view and the base table return different available balances. (`PKG_REPORTING.leave_utilization_report` has the same omission.)
**Impact**: Managers viewing leave summaries see inflated available balances that include pending (unapproved) requests; approval decisions may be based on incorrect availability.
**Recommendation**: Align the view (and report) to include `- lb.PENDING`, matching the virtual-column definition.

---

## 8. Severity Summary

| ID | Category | Description | Severity | File | Recommended Fix |
|----|----------|-------------|----------|------|----------------|
| SEC-01 | Security | MD5 password hashing | CRITICAL | PKG_SECURITY.pkb:18 | Migrate to bcrypt/scrypt |
| SEC-02 | Security | Hard-coded encryption key in source | CRITICAL | PKG_SECURITY.pkb:7 | Oracle Wallet/Key Vault |
| SEC-03 | Security | Cleartext password transmission | CRITICAL | HRMS_LOGIN.xml | Enable network encryption |
| SEC-04 | Security | No account lockout | HIGH | PKG_SECURITY.pkb:26 | Add failed-attempt tracking |
| SEC-05 | Security | Timing attack on authentication | HIGH | PKG_SECURITY.pkb | Constant-time comparison |
| SEC-06 | Security | No 2FA/MFA support | HIGH | HRMS_LOGIN.xml | Add TOTP/SSO |
| SEC-07 | Security | Hard-coded SMTP config | MEDIUM | PKG_NOTIFICATION.pkb:7 | Move to SYSTEM_PARAMETERS |
| SEC-08 | Security | FTP credentials in cleartext | MEDIUM | PKG_INTEGRATION.pks | Oracle Wallet |
| SEC-09 | Security | Session timeout clock skew | MEDIUM | PKG_SECURITY.pks | Consistent time source |
| SEC-10 | Security | JSON string concatenation (log injection) | MEDIUM | PKG_COMMON.pkb:24 | Use JSON_OBJECT() |
| RACE-01 | Race Condition | Employee number MAX()+1 | HIGH | PKG_EMPLOYEE.pkb | Use SEQ_EMP_NUMBER |
| RACE-02 | Race Condition | Payroll period status check | MEDIUM | PKG_PAYROLL.pkb | Add FOR UPDATE |
| PERF-01 | Performance | Day-by-day business-days loop | MEDIUM | PKG_COMMON.pkb:132 | Set-based arithmetic |
| PERF-02 | Performance | Day-by-day add_business_days loop | MEDIUM | PKG_COMMON.pkb:151 | Set-based arithmetic |
| PERF-03 | Performance | CONNECT BY org hierarchy | MEDIUM | hrms_views.sql:47 | Recursive CTE / closure table |
| PERF-04 | Performance | Per-notification SMTP connection | MEDIUM | PKG_NOTIFICATION.pkb | Connection reuse |
| PERF-05 | Performance | NOCACHE sequences | LOW | hrms_sequences.sql | Add CACHE 20 |
| PERF-06 | Performance | Stale reporting tables / stub refresh | LOW | PKG_REPORTING.pks | Materialized views |
| DRIFT-01 | Validation Drift | Email regex mismatch PLL vs server | HIGH | HRMS_VALIDATION_LIB.pll.sql | Align to server regex |
| DRIFT-02 | Validation Drift | Salary caching comment vs code | MEDIUM | HRMS_VALIDATION_LIB.pll.sql | Fix comment or implement |
| DRIFT-03 | Validation Drift | Salary range: warning vs error | MEDIUM | PKG_EMPLOYEE.pkb | Single source of truth |
| DRIFT-04 | Validation Drift | Date validation differences | LOW | Multiple files | Align client/server |
| CIRC-01 | Circular Dep | PKG_EMPLOYEE ↔ PKG_PAYROLL | HIGH | PKG_EMPLOYEE.pks:9 | Extract shared package |
| ARCH-00 | Architecture | TRG_EMP_BEFORE_UPDATE column mismatch (ORA-00904) | CRITICAL | trg_employees.sql:78 | Rewrite INSERTs with correct columns |
| ARCH-01 | Architecture | Soft-delete trigger confusion | MEDIUM | trg_employees.sql:120 | Remove or use INSTEAD OF view |
| ARCH-02 | Architecture | Autonomous transaction overuse | MEDIUM | PKG_AUDIT.pkb:14 | Savepoints |
| ARCH-03 | Architecture | UTL_FILE flat-file integration | MEDIUM | PKG_INTEGRATION.pkb | REST API / message queue |
| ARCH-04 | Architecture | Stub/incomplete implementations | LOW | PKG_INTEGRATION.pkb:170 | Complete or remove |
| ARCH-05 | Architecture | Hard-coded fiscal year & tax | LOW | PKG_COMMON.pkb:174 | SYSTEM_PARAMETERS / TAX_BRACKETS |
| DATA-01 | Data Integrity | Cross-year leave balance | HIGH | PKG_LEAVE.pkb | Split by calendar year |
| DATA-02 | Data Integrity | Half-day overlap gap | MEDIUM | PKG_LEAVE.pkb | Enhance overlap check |
| DATA-03 | Data Integrity | Carryover double-expiry | MEDIUM | PKG_LEAVE.pkb:606 | Idempotency check |
| DATA-04 | Data Integrity | Holiday observed date | MEDIUM | PKG_LEAVE.pkb | Add OBSERVED_DATE |
| DATA-05 | Data Integrity | YTD mid-year hire | LOW | PKG_PAYROLL.pks:12 | Init from prior W-2 |
| DATA-06 | Data Integrity | Overtime holiday calc | LOW | PKG_PAYROLL.pks:11 | Integrate holiday calendar |
| DATA-07 | Data Integrity | VW_LEAVE_SUMMARY AVAILABLE omits PENDING | MEDIUM | hrms_views.sql:96 | Add `- PENDING` to view |

---

## 9. Prioritized Migration Roadmap

### Phase 1: Immediate Security Hardening (1-2 weeks)

| Priority | Item | Effort | Risk if Deferred |
|----------|------|--------|-----------------|
| 1 | SEC-02: Rotate hard-coded encryption key → Oracle Wallet | 3 days | Total PII exposure |
| 2 | SEC-01: Replace MD5 with SHA-256 + salt (interim) → bcrypt (final) | 2 days | Password compromise |
| 3 | SEC-03: Enable Oracle Net encryption | 1 day | MITM credential theft |
| 4 | SEC-04: Add account lockout (5 attempts, 30-min lock) | 2 days | Brute-force |
| 5 | SEC-05: Fix timing attack (constant-time compare) | 1 day | Username enumeration |
| 6 | SEC-10: Safe JSON construction for audit logs | 1 day | Corrupted audit / log injection |

### Phase 2: Data Integrity & Race Conditions (2-4 weeks)

| Priority | Item | Effort | Risk if Deferred |
|----------|------|--------|-----------------|
| 1 | ARCH-00: Fix TRG_EMP_BEFORE_UPDATE column mismatch | 1 day | Employee updates fail; no history |
| 2 | RACE-01: Replace MAX()+1 with SEQ_EMP_NUMBER | 0.5 day | Duplicate emp numbers |
| 3 | DATA-01: Fix cross-year leave balance | 1 day | Incorrect balances |
| 4 | DATA-07: Align VW_LEAVE_SUMMARY with virtual column | 0.5 day | Wrong availability shown |
| 5 | CIRC-01: Resolve circular dependency | 3 days | Cascade invalidation |
| 6 | DRIFT-01/DRIFT-03: Align validation layers | 1 day | Blocked entry / bypassed controls |
| 7 | DATA-03: Make carryover expiry idempotent | 1 day | Lost leave balance |
| 8 | RACE-02: Add FOR UPDATE to period check | 0.5 day | Invalid payroll runs |

### Phase 3: Performance (1-3 months)

| Priority | Item | Effort | Risk if Deferred |
|----------|------|--------|-----------------|
| 1 | PERF-04: SMTP connection reuse + queue claim | 1 day | Notification delays / duplicates |
| 2 | PERF-01/02: Replace date loops with arithmetic | 2 days | Slow leave calculations |
| 3 | PERF-03: Replace CONNECT BY with recursive CTE | 2 days | Slow org chart |
| 4 | PERF-05: Add CACHE to hot sequences | 0.5 day | Insert contention |
| 5 | PERF-06: Real materialized-view refresh | 2 days | Stale reporting |

### Phase 4: Modernization (6-12 months)

| Priority | Item | Effort | Description |
|----------|------|--------|-------------|
| 1 | ARCH-03: Migrate UTL_FILE integrations to REST/AQ | 2 weeks | Reliable GL/benefits/pay-register exchange |
| 2 | ARCH-05: Externalize fiscal year & tax brackets | 3 days | Config-driven tax/fiscal logic |
| 3 | ARCH-04: Complete/remove stub implementations | 1 week | Remove false-success jobs |
| 4 | DRIFT-03/04: Consolidate validation to single layer | 1 week | Reduce maintenance burden |
| 5 | Migrate Forms to a modern web framework (APEX/React/Angular) | 3-6 months | Replace Oracle Forms UI |
| 6 | Implement token-based session mgmt (JWT/OAuth) + 2FA/SSO | 1 month | Replace USER_SESSIONS pattern (SEC-06/SEC-09) |
| 7 | Add automated testing (utPLSQL) | 2 months | Regression safety net |
