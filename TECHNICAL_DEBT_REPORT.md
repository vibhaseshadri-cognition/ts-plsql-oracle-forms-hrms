# Technical Debt Report — Oracle Forms/PL/SQL HRMS Estate

_Repository: `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`_
_Analysis scope: `plsql/` packages & triggers, `schema/` tables/views/sequences, `forms/` libraries & XML exports, `data/seed/`_

## Executive Summary

This report catalogs **39 identified technical debt items** across the Oracle Forms/PL/SQL HRMS application: 11 security vulnerabilities, 3 race conditions, 6 performance issues, 4 validation-drift items, 1 circular dependency, 6 architectural anti-patterns, and 8 data-integrity risks.

The single most urgent class of issues is the **trigger-vs-table column mismatches** (`DATA-01`, `DATA-02`, `DATA-03`): database triggers reference columns and enumerated values that do not exist in the target tables' DDL. These are latent, guaranteed-to-fire runtime failures — every employee status/department/job update and every leave status change hits an `ORA-00904`/check-constraint violation, and in the audit path the failure is silently swallowed by an autonomous transaction.

| Severity | Count | Representative categories |
|----------|-------|---------------------------|
| CRITICAL | 5 | MD5 password hashing, hard-coded encryption key, SQL injection, `EMPLOYEE_HISTORY` trigger column mismatch, invalid `CHANGE_TYPE` values |
| HIGH | 11 | Race conditions (emp-number, leave balance), no account lockout, cleartext password, stub `change_password`, circular dependency, view "available" drift, silent audit-log loss |
| MEDIUM | 16 | Performance loops/CONNECT BY/per-iteration SMTP, validation drift, autonomous-transaction overuse, flat-file integration, hard-coded fiscal/tax constants, carryover-expiry column error, `ROWNUM`+`ORDER BY` mis-selection |
| LOW | 7 | NOCACHE sequences, hard-coded SMTP config, comment/code mismatch, stub integrations, masked-SSN edge cases |

### Findings by category

| Category | IDs | Count |
|----------|-----|-------|
| Security | SEC-01 … SEC-11 | 11 |
| Race conditions | RACE-01 … RACE-03 | 3 |
| Performance | PERF-01 … PERF-06 | 6 |
| Validation drift | DRIFT-01 … DRIFT-04 | 4 |
| Circular dependencies | CIRC-01 | 1 |
| Architecture | ARCH-01 … ARCH-06 | 6 |
| Data integrity | DATA-01 … DATA-08 | 8 |

---

## 1. Security Vulnerabilities

### SEC-01: MD5 Password Hashing, No Salt (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:14-24`
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
**Issue**: MD5 is cryptographically broken and unsalted; rainbow tables crack it in seconds. **Impact**: Full password compromise if the credential store leaks. **Recommendation**: Migrate to bcrypt/scrypt/PBKDF2 with a per-user salt (external integration), or at minimum `DBMS_CRYPTO.HASH_SH256` with salt as an interim step.

### SEC-02: Hard-Coded Encryption Key (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:7`
```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```
**Issue**: The AES-256 key used to encrypt/decrypt SSNs (`encrypt_ssn`/`decrypt_ssn`, lines 179-206) and bank account numbers is a literal in source, committed to version control. **Impact**: Anyone with source access can decrypt all PII in `EMPLOYEES.SSN_ENCRYPTED`, `EMPLOYEE_DEPENDENTS.SSN_ENCRYPTED`, `EMPLOYEE_BANK_ACCOUNTS.ACCOUNT_NUMBER_ENC`. **Recommendation**: Move key management to Oracle Wallet / TDE / an external KMS; rotate the key and re-encrypt.

### SEC-03: SQL Injection via String Concatenation (CRITICAL)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:445-498` (esp. 466-467, 478-483)
```sql
IF p_last_name IS NOT NULL THEN
    -- VULNERABILITY: String concatenation instead of bind variable
    v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
END IF;
...
OPEN p_cursor FOR v_sql;
```
**Issue**: `search_employees` builds dynamic SQL by concatenating caller-supplied `p_last_name`, `p_first_name`, `p_status`, `p_location_code`. Any non-Forms caller can inject. **Impact**: Data exfiltration / privilege escalation. **Recommendation**: Use bind variables (`OPEN … USING`) or `DBMS_ASSERT`; never concatenate input into SQL text.

### SEC-04: Cleartext Password Transmission at Login (HIGH)

**File**: `forms/xml-exports/HRMS_LOGIN.xml:11`, `:69-99`
**Issue**: The login form documents (and implements) password transmission in cleartext to `PKG_SECURITY.authenticate`; no TLS/hashing at the client tier. **Impact**: Network sniffing yields credentials. **Recommendation**: Enforce TLS end-to-end; hash/transform client-side; migrate off the Forms applet auth path.

### SEC-05: No Account Lockout / Brute-Force Protection (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb:28-80`; `schema/tables/04_performance_tables.sql:153-165` (`USER_SESSIONS`)
**Issue**: `authenticate` has no failed-attempt counter or lockout; `USER_SESSIONS` has no `FAILED_ATTEMPTS`/`LOCKED_UNTIL` columns, and the `e_account_locked` exception (`PKG_SECURITY.pks:16`) is declared but never raised. **Impact**: Unlimited credential-stuffing. **Recommendation**: Add attempt tracking + exponential backoff/lockout; wire up `e_account_locked`.

### SEC-06: Authentication Timing Attack / User Enumeration (MEDIUM)

**File**: `plsql/packages/PKG_SECURITY.pkb:41-57`
**Issue**: Invalid username raises immediately in the `NO_DATA_FOUND` handler; a valid username follows a longer code path (session insert, context set). Response-time differences (and the fact that password is never actually verified — see SEC-09) enable enumeration. **Recommendation**: Constant-time comparison; identical error/timing for invalid user vs. invalid password.

### SEC-07: Hard-Coded SMTP Configuration (LOW)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb:6-10`
```sql
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
```
**Issue**: SMTP host/port/from are compiled-in (port 25, unauthenticated, no TLS). **Recommendation**: Externalize to `SYSTEM_PARAMETERS`; use authenticated SMTP over TLS.

### SEC-08: Session Timeout Uses DB Server Clock (LOW)

**File**: `plsql/packages/PKG_SECURITY.pkb:98-127`
**Issue**: `is_session_valid` compares `SYSDATE - LOGIN_TIME`; DB/app clock skew and timezone differences make timeout enforcement unreliable. **Recommendation**: Standardize on a single authoritative time source (UTC).

### SEC-09: `change_password` Is a Non-Functional Stub (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb:211-234`
**Issue**: Enforces complexity rules but never verifies `p_old_password` and never persists the new hash ("Actual password update would go to USER_CREDENTIALS table" — a comment, not code). Combined with `authenticate` (SEC-06) which never actually checks the password hash, the credential model is effectively non-functional/insecure. **Recommendation**: Implement real credential storage + verification.

### SEC-10: `decrypt_ssn` Swallows Errors Into a Literal (LOW)

**File**: `plsql/packages/PKG_SECURITY.pkb:203-205`
```sql
EXCEPTION WHEN OTHERS THEN RETURN '***DECRYPT_ERROR***';
```
**Issue**: Any decryption failure (wrong key, corrupt data) returns a magic string that downstream code may treat as an SSN. **Recommendation**: Propagate a typed exception; never return a sentinel as data.

### SEC-11: Deterministic SSN Encryption (No IV) (MEDIUM)

**File**: `plsql/packages/PKG_SECURITY.pkb:179-190`
**Issue**: `encrypt_ssn` uses AES-CBC with a fixed key and no random IV, so identical SSNs produce identical ciphertext — leaking equality across rows and enabling dictionary attacks over the small SSN space. **Recommendation**: Prepend a per-row random IV; store IV alongside ciphertext.

---

## 2. Race Conditions

### RACE-01: `MAX()+1` Employee Number Generation (HIGH)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:39-55`; sequence noted in `schema/sequences/hrms_sequences.sql:18-21`
```sql
SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
INTO v_max_num FROM EMPLOYEES WHERE EMP_NUMBER LIKE 'EMP-%';
```
**Issue**: Concurrent hires read the same `MAX` and generate duplicate `EMP-NNNNNN`, colliding on `UK_EMP_NUMBER`. A dedicated `SEQ_EMP_NUMBER` sequence exists but is only used in the exception fallback. **Impact**: `DUP_VAL_ON_INDEX`, failed hires under load. **Recommendation**: Use `SEQ_EMP_NUMBER.NEXTVAL` directly.

### RACE-02: Leave-Balance Check-Then-Update (Double Spend) (HIGH)

**File**: `plsql/packages/PKG_LEAVE.pkb:146-182`
**Issue**: `submit_leave_request` reads the balance via `get_leave_balance` (line 148) and later `UPDATE LEAVE_BALANCES SET PENDING = PENDING + …` (line 176) with no `SELECT … FOR UPDATE` on the balance row. Two concurrent requests both pass the check and over-commit the balance. **Recommendation**: Lock the `LEAVE_BALANCES` row (`FOR UPDATE`) before the availability check, or enforce a non-negative `AVAILABLE` check constraint.

### RACE-03: Payroll-Run Period Status Check (MEDIUM)

**File**: `plsql/packages/PKG_PAYROLL.pkb:240-262`
**Issue**: `create_payroll_run` reads `PAY_PERIODS.STATUS` without `FOR UPDATE`, then inserts a run. A concurrent `close_pay_period` can close the period between the check and the insert, producing a run against a closed period. **Recommendation**: `SELECT … FOR UPDATE` on the period row.

---

## 3. Performance Issues

### PERF-01: Day-by-Day Loop With Per-Day Holiday Query (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pkb:12-40`
**Issue**: `calculate_business_days` iterates `v_date := v_date + 1` and issues a `COUNT(*)` against `HOLIDAYS` per day. Long ranges = many round-trips. **Recommendation**: Set-based calc — count weekdays arithmetically and subtract a single grouped holiday query.

### PERF-02: Business-Day Utility Loops (LOW)

**File**: `plsql/packages/PKG_COMMON.pkb:132-165`
**Issue**: `business_days_between` and `add_business_days` are day-by-day `WHILE` loops. **Recommendation**: Arithmetic based on `TRUNC(date,'IW')` week math.

### PERF-03: CONNECT BY Hierarchical Queries (MEDIUM)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:822-840` (`get_org_chart`); `schema/views/hrms_views.sql:47-57` (`VW_ORG_HIERARCHY`)
**Issue**: Both use `CONNECT BY`; the view header itself warns performance "degrades significantly with >500 employees". **Recommendation**: Recursive CTE with proper indexing on `MANAGER_EMP_ID`; materialize the hierarchy where read-heavy.

### PERF-04: SMTP Connection Opened Per Message in Loop (MEDIUM)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb:78-135`
**Issue**: `process_queue` calls `UTL_SMTP.OPEN_CONNECTION`/`HELO`/`QUIT` inside the per-notification loop. Connection setup dominates for large batches. **Recommendation**: Open one connection, reuse `MAIL`/`RCPT`/`DATA` per message, quit once.

### PERF-05: Row-by-Row Payroll Cursor Loop (MEDIUM)

**File**: `plsql/packages/PKG_PAYROLL.pkb:296-327` (and per-employee `calculate_employee_pay`)
**Issue**: Payroll processes employees one row at a time with per-row `INSERT`s (self-documented "should use BULK COLLECT + FORALL"). **Recommendation**: Bulk-collect eligible employees and `FORALL` the detail inserts; batch tax/deduction computation.

### PERF-06: NOCACHE Sequences (LOW)

**File**: `schema/sequences/hrms_sequences.sql:9-49`
**Issue**: Nearly all sequences are `NOCACHE`, forcing a dictionary update per `NEXTVAL` — a contention point for high-volume inserts (payroll details, audit). **Recommendation**: Use `CACHE 20+` for hot sequences unless strict gap-free ordering is required.

---

## 4. Validation Drift (Client PLL vs. Server Packages)

### DRIFT-01: Email Validation Diverges (MEDIUM)

**Client**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41` — `INSTR`-based; rejects valid subdomain addresses like `user@mail.company.com`.
**Server**: `plsql/packages/PKG_COMMON.pkb:265-268` — `REGEXP_LIKE(…, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')` accepts them.
**Impact**: Emails rejected client-side but accepted server-side (and vice-versa), inconsistent UX and data. **Recommendation**: Single shared validation (call the server function from the form).

### DRIFT-02: Salary-Range Enforcement Inconsistent (MEDIUM)

**Server (hard error)**: `plsql/packages/PKG_VALIDATION.pkb:17-48` returns a blocking error message when salary is outside grade min/max.
**Actual write path (soft warning)**: `plsql/packages/PKG_EMPLOYEE.pkb:220-241` — `create_employee` only logs a debug warning and inserts anyway.
**Client**: `HRMS_VALIDATION_LIB.pll.sql:108-135` returns a message but form allows override.
**Impact**: Out-of-band salaries persist despite a "validation" that appears to block. **Recommendation**: Decide one policy; enforce it in the write path.

### DRIFT-03: Date-Range Rules Diverge Three Ways (MEDIUM)

- Client `validate_date_not_future` (`HRMS_VALIDATION_LIB.pll.sql:96-99`) rejects any future date.
- Server `PKG_VALIDATION.validate_date_range` (`PKG_VALIDATION.pkb:6-15`) only requires `end >= start`.
- `PKG_LEAVE.submit_leave_request` (`PKG_LEAVE.pkb:116-126`) allows backdating up to 5 days and future dates freely.
**Impact**: Contradictory acceptance of the same input across layers. **Recommendation**: Centralize date policy.

### DRIFT-04: Comment/Code Mismatch in Salary Cache (LOW)

**File**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:101-135`
**Issue**: Header claims a startup cache "never refreshed", but the body queries `JOB_GRADES` live. Misleading documentation invites wrong assumptions. **Recommendation**: Fix the comment (or implement intended caching).

---

## 5. Circular Dependencies

### CIRC-01: `PKG_EMPLOYEE` ↔ `PKG_PAYROLL` (HIGH)

**Files**: `plsql/packages/PKG_EMPLOYEE.pks:6-9` (Dependencies: … `PKG_PAYROLL`; "Circular dependency with PKG_PAYROLL"), `plsql/packages/PKG_PAYROLL.pks:6-9` (Dependencies: `PKG_EMPLOYEE` …; "Circular dependency with PKG_EMPLOYEE"). Concrete call: `PKG_EMPLOYEE.create_employee` → `PKG_PAYROLL.create_salary_record` (`PKG_EMPLOYEE.pkb:275-282`, `617`, `778`).
**Issue**: Mutual dependency forces fragile compile ordering and makes both packages `INVALID` together on any change; complicates the modularization/migration path. **Recommendation**: Extract shared employee-state checks into a base package (e.g. `PKG_EMPLOYEE_CORE`) both depend on, breaking the cycle.

---

## 6. Architectural Anti-Patterns

### ARCH-01: Autonomous-Transaction Overuse Hiding Failures (MEDIUM)

**Files**: `PKG_EMPLOYEE.pkb:155` (`log_history`), `PKG_NOTIFICATION.pkb:27` (`send_notification`), `PKG_COMMON.pkb:16,46` (`log_error`/`log_info`), `PKG_AUDIT.pkb:14` (`log_action`).
**Issue**: Every logging/audit/notification path is `PRAGMA AUTONOMOUS_TRANSACTION` with `WHEN OTHERS THEN ROLLBACK`/`NULL`. Failures (including the `DATA-03` audit-constraint violation) vanish silently. **Recommendation**: Reserve autonomous transactions for genuine independent commits; surface/track failures instead of swallowing.

### ARCH-02: UTL_FILE Flat-File Integration (MEDIUM)

**Files**: `PKG_INTEGRATION.pkb:16-194` (GL journal, benefits feed, time import), `PKG_PAYROLL.pkb:826-894` (`generate_pay_register`).
**Issue**: Point-to-point flat files (fixed-width/pipe/CSV) via `UTL_FILE` to directory objects; no transactional guarantees, silent partial writes, brittle vendor formats (ADP). **Recommendation**: Replace with REST/AQ-based integration and structured error handling.

### ARCH-03: Stub / TODO Implementations in Production Paths (MEDIUM)

**Files**: `PKG_INTEGRATION.pkb:153-203` (`import_time_attendance` parses nothing; `sync_org_structure` is a placeholder), `PKG_REPORTING.pkb:196-204` (`refresh_reporting_tables` placeholder), `PKG_SECURITY.pkb:230-234` (`change_password` stub), `PKG_EMPLOYEE.pkb:737-739` (termination TODOs: COBRA, access revoke, final pay).
**Issue**: Callable procedures that report success while doing nothing → silent data loss / missed compliance steps. **Recommendation**: Implement or explicitly raise `NOT_IMPLEMENTED`; never log success for a no-op.

### ARCH-04: Hard-Coded Fiscal/Tax Constants (MEDIUM)

**Files**: `PKG_PAYROLL.pkb:6-14` (2024 SS wage base, standard deductions), `PKG_PAYROLL.pkb:643-677` (2024 federal brackets inline, with `-- TODO: Read from TAX_BRACKETS table`), `PKG_COMMON.pkb:170-179` (`get_fiscal_year` assumes Oct-1 fiscal start).
**Issue**: A `TAX_BRACKETS` table exists (`02_payroll_tables.sql:159`) but is unused; annual updates require code changes and redeploys; wrong withholding after year rollover. **Recommendation**: Drive rates from `TAX_BRACKETS`/`SYSTEM_PARAMETERS`.

### ARCH-05: Partial Commits Inside Batch Loops (MEDIUM)

**Files**: `PKG_PAYROLL.pkb:322-327` (`COMMIT` every 50 employees), `PKG_LEAVE.pkb:542-548` (`COMMIT` every 100).
**Issue**: A mid-batch failure leaves payroll/accruals half-applied with no clean rollback boundary (self-documented). **Recommendation**: Use restartable checkpoints with explicit run-state tracking, or a single transaction with savepoints and a resume mechanism.

### ARCH-06: Business Logic Triplicated Across Tiers (MEDIUM)

**Files**: DB triggers (`plsql/triggers/*`), packages (`plsql/packages/*`), and Forms PLLs (`forms/libraries/*`) each re-implement validation/audit/history. `trg_employees.sql:1-6` explicitly calls this out.
**Issue**: The same rule maintained in three places drifts (see all `DRIFT-*` and `DATA-*`). **Recommendation**: Consolidate to a single server-side layer; treat triggers as thin guards only.

---

## 7. Data Integrity Risks

### DATA-01: `EMPLOYEE_HISTORY` Trigger Columns Do Not Exist (CRITICAL)

**Trigger**: `plsql/triggers/trg_employees.sql:78-110`
```sql
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES ( SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'STATUS_CHANGE', SYSDATE, … );
```
**Table DDL**: `schema/tables/01_core_tables.sql:152-177`
```
HIST_ID, EMP_ID, CHANGE_TYPE, EFFECTIVE_DATE,
OLD_DEPT_ID, NEW_DEPT_ID, OLD_JOB_ID, NEW_JOB_ID,
OLD_MANAGER_ID, NEW_MANAGER_ID, OLD_SALARY, NEW_SALARY,
OLD_LOCATION, NEW_LOCATION, REASON_CODE, COMMENTS, CREATED_BY, CREATED_DATE
```
**Issue**: The trigger references **`HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON` — none of which exist** (PK is `HIST_ID`; there are no generic `OLD_VALUE`/`NEW_VALUE` columns). The compiled trigger is invalid and **any `UPDATE` to `EMPLOYEES` that changes status, department, or job raises `ORA-00904: invalid identifier`**, blocking transfers/promotions/terminations. Note `PKG_EMPLOYEE.log_history` (`PKG_EMPLOYEE.pkb:157-169`) uses the **correct** column list — so the trigger and the package disagree on the table's shape. **Recommendation**: Rewrite the trigger against the actual DDL (or drop it in favor of `PKG_EMPLOYEE.log_history`).

### DATA-02: Trigger Uses `CHANGE_TYPE` Values Outside the Check Constraint (CRITICAL)

**Trigger**: `trg_employees.sql:88-110` inserts `CHANGE_TYPE = 'DEPARTMENT_CHANGE'` and `'JOB_CHANGE'`.
**Constraint**: `01_core_tables.sql:173-176` `CHK_CHANGE_TYPE` allows only `HIRE, TRANSFER, PROMOTION, DEMOTION, SALARY_CHANGE, TERMINATION, REHIRE, LEAVE_START, LEAVE_END, STATUS_CHANGE`.
**Issue**: Even after DATA-01 is fixed, `'DEPARTMENT_CHANGE'`/`'JOB_CHANGE'` violate `CHK_CHANGE_TYPE` (`ORA-02290`). **Recommendation**: Use allowed values (`TRANSFER`, `PROMOTION`) or extend the constraint.

### DATA-03: Leave-Audit Action Violates `AUDIT_LOG` Check → Silent Loss (HIGH)

**Trigger**: `plsql/triggers/trg_audit.sql:47-59` calls `PKG_AUDIT.log_action(…, 'STATUS_CHANGE', …)` on `LEAVE_REQUESTS` status updates.
**Constraint**: `04_performance_tables.sql:104` `CHK_AUDIT_ACTION CHECK (ACTION_TYPE IN ('INSERT','UPDATE','DELETE'))`.
**Issue**: `'STATUS_CHANGE'` violates the constraint, so the `INSERT` in `PKG_AUDIT.log_action` fails — but because that procedure is `AUTONOMOUS_TRANSACTION` with `WHEN OTHERS THEN ROLLBACK` (`PKG_AUDIT.pkb:14,27-30`), the failure is **silently swallowed**. Every leave approval/rejection loses its audit record with no error. (The `PKG_EMPLOYEE`/`PKG_PAYROLL` callers pass `'UPDATE'`/`'INSERT'` and are fine.) **Recommendation**: Pass `'UPDATE'` (with the status in the JSON payload) or extend `CHK_AUDIT_ACTION`.

### DATA-04: Carryover Expiry Adjusts the Wrong Column (MEDIUM)

**Files**: `PKG_LEAVE.pkb:558-603` (`process_carryover` adds carryover to `OPENING_BALANCE` and sets `CARRYOVER_FROM_PREV`), `PKG_LEAVE.pkb:610-623` (`expire_carryover` does `ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV`).
**Issue**: Carryover is granted into `OPENING_BALANCE` but expired out of `ADJUSTMENT`. The net `AVAILABLE` happens to balance, but `OPENING_BALANCE` still shows the (now-expired) carryover and `ADJUSTMENT` goes artificially negative — corrupting the audit meaning of both columns and any report that reads them individually (e.g. `VW_LEAVE_SUMMARY`, `leave_utilization_report`). **Recommendation**: Expire from the same bucket that granted it (`OPENING_BALANCE` / `CARRYOVER_FROM_PREV`).

### DATA-05: `INSTEAD OF DELETE` Trigger Blocks Forms Deletes (MEDIUM)

**File**: `plsql/triggers/trg_employees.sql:120-129`
**Issue**: `TRG_EMP_INSTEAD_OF_DELETE` unconditionally `RAISE_APPLICATION_ERROR(-20504)` on any `DELETE`, but it is a `BEFORE DELETE` row trigger (not a soft-delete conversion). Forms `DELETE_RECORD`/`COMMIT_FORM` expect deletes to succeed; the header comment itself flags the Forms workaround required. **Impact**: Runtime errors in maintenance forms; inconsistent soft-delete story (some paths set `ACTIVE_FLAG='N'`, this one hard-blocks). **Recommendation**: Standardize on the termination/soft-delete API and remove the misleading trigger, or make it actually perform the soft delete.

### DATA-06: "Available Leave" Formula Differs Across View, Column, and Code (HIGH)

- Table virtual column: `03_leave_tables.sql:47` — `AVAILABLE = OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING`.
- Function: `PKG_LEAVE.get_leave_balance` `PKG_LEAVE.pkb:376` — **subtracts `PENDING`** (matches the column).
- View: `hrms_views.sql:96` `VW_LEAVE_SUMMARY.AVAILABLE = OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT` — **omits `PENDING`**.
- Carryover source: `PKG_LEAVE.pkb:567` also omits `PENDING`.
**Issue**: The self-service screen / reports (view) show a higher "available" than the balance check enforces, so employees see days they cannot actually book. **Recommendation**: Single canonical formula; have the view select the table's virtual `AVAILABLE`.

### DATA-07: `ROWNUM = 1` Applied Before `ORDER BY` Selects Wrong Salary (MEDIUM)

**Files**: `PKG_EMPLOYEE.pkb:597-603` (`promote_employee` current-salary lookup), `PKG_EMPLOYEE.pkb:402-408` (`get_employee` salary subquery — `ROWNUM = 1` with no ordering).
```sql
SELECT BASE_SALARY INTO v_old_salary FROM SALARY_RECORDS
WHERE EMP_ID = p_emp_id AND ACTIVE_FLAG = 'Y' AND ROWNUM = 1
ORDER BY EFFECTIVE_DATE DESC;   -- ORDER BY runs AFTER ROWNUM filter
```
**Issue**: Oracle applies `ROWNUM` before `ORDER BY`, so an arbitrary active salary row is chosen, not the most recent. Wrong `CHANGE_PCT` on promotions and wrong displayed salary. **Recommendation**: Use `FETCH FIRST 1 ROW ONLY` or an inline-view ordered before the rownum filter (as `get_current_salary`/`get_salary_as_of` already do correctly).

### DATA-08: `VW_PAYROLL_LATEST` Mislabels a Single Global Run as "Latest per Employee" (LOW)

**File**: `schema/views/hrms_views.sql:106-129`
**Issue**: The view filters `pr.RUN_ID = (SELECT MAX(RUN_ID) FROM PAYROLL_RUNS WHERE STATUS='APPROVED')` — one global run for everyone. Employees not in that run vanish, and multi-period/off-cycle runs are misrepresented despite the "latest per employee" intent. **Recommendation**: Correlate the latest approved run per employee (or per current period).

---

## 8. Prioritized Migration Roadmap

### Phase 1 — Critical Security & Guaranteed Failures (0–4 weeks)

| Priority | Item | Effort | Risk if deferred |
|----------|------|--------|------------------|
| 1 | DATA-01/DATA-02: Fix/replace `EMPLOYEES` update trigger (columns + `CHANGE_TYPE`) | 1 day | Transfers/promotions/terminations error out |
| 2 | DATA-03: Fix leave-audit action value | 0.5 day | Silent loss of leave audit trail |
| 3 | SEC-03: Parameterize `search_employees` (bind variables) | 1 day | SQL injection |
| 4 | SEC-01: Replace MD5 with salted strong hash | 3 days | Password DB compromise |
| 5 | SEC-02/SEC-11: Externalize encryption key + add IV | 3 days | PII decryption from source |
| 6 | SEC-05/SEC-09: Account lockout + real password verify/store | 1 week | Brute force; broken auth |

### Phase 2 — Data Integrity (1–2 months)

| Priority | Item | Effort | Risk if deferred |
|----------|------|--------|------------------|
| 1 | DATA-06: Unify "available leave" formula (view = column) | 1 day | Over-booked leave |
| 2 | RACE-02: Lock `LEAVE_BALANCES` before check | 0.5 day | Double-spent balances |
| 3 | RACE-01: Sequence-based employee numbers | 0.5 day | Duplicate hires |
| 4 | DATA-07: Fix `ROWNUM`+`ORDER BY` salary selection | 0.5 day | Wrong salary/`CHANGE_PCT` |
| 5 | DATA-04: Expire carryover from correct column | 1 day | Corrupted balance columns |
| 6 | DATA-05 / RACE-03: Rationalize delete trigger & period-status locking | 1 day | Runtime errors; runs vs closed periods |

### Phase 3 — Performance & Architecture (1–3 months)

| Priority | Item | Effort | Risk if deferred |
|----------|------|--------|------------------|
| 1 | PERF-04: Reuse SMTP connection | 1 day | Notification backlog |
| 2 | PERF-01/02: Set-based business-day calc | 2 days | Slow leave calcs |
| 3 | PERF-05: Bulk payroll (`BULK COLLECT`/`FORALL`) | 3 days | Slow payroll runs |
| 4 | PERF-03: Replace `CONNECT BY` with recursive CTE | 2 days | Org-chart timeouts |
| 5 | ARCH-04: Drive tax/fiscal from `TAX_BRACKETS`/params | 3 days | Wrong withholding at year rollover |
| 6 | ARCH-01/ARCH-05: Fix autonomous-txn swallowing & batch checkpoints | 1 week | Hidden failures, half-applied batches |
| 7 | DRIFT-01/02/03: Consolidate validation to one layer | 1 week | Ongoing drift |
| 8 | CIRC-01: Break `PKG_EMPLOYEE`↔`PKG_PAYROLL` cycle | 3 days | Fragile compiles, hard migration |

### Phase 4 — Full Modernization (6–12 months)

| Priority | Item | Effort | Description |
|----------|------|--------|-------------|
| 1 | Migrate Forms UI to a modern web stack | 3–6 months | APEX / React / Angular front end |
| 2 | Stateless session management (JWT/OAuth), retire `USER_SESSIONS` | 1 month | Replace applet auth (SEC-04/08) |
| 3 | Replace flat-file integrations (ARCH-02) with REST/AQ events | 1 month | Real-time GL/benefits/time sync |
| 4 | Decompose PL/SQL into API-first services | 3–6 months | Break triplicated logic (ARCH-06) |
| 5 | Add 2FA/SSO | 2 weeks | Enterprise identity |
| 6 | Automated test suite (utPLSQL) + CI | 2 months | Regression safety for all of the above |

---

_This report is generated from static analysis of the repository sources; line references are to the state of `main` at the time of analysis._
