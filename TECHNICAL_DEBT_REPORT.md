# Technical Debt Report — ts-plsql-oracle-forms-hrms

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Analysis date:** 2026-07-27
**Scope:** Static analysis of Oracle Forms 12c / Oracle Database 19c legacy HRMS codebase
(PL/SQL package specs & bodies, database triggers, table DDL, views, sequences, seed data,
and Oracle Forms library/XML source exports).

> No `DATA_DICTIONARY.md` is present in the repository, so column descriptions could not be
> cross-referenced against a data dictionary. Trigger column lists were instead cross-referenced
> directly against the table DDL in `schema/tables/`.

---

## Executive Summary

This HRMS system carries substantial technical debt spanning security, data integrity,
concurrency, performance, and architecture. A comprehensive static review surfaced **43 findings**.

The most urgent issues are:

1. **Broken employee-history triggers (DATA-01/DATA-02):** `TRG_EMP_BEFORE_UPDATE` inserts into
   `EMPLOYEE_HISTORY` using column names that do not exist in the table DDL, and uses
   `CHANGE_TYPE` values that violate the table's check constraint. **Any** update to an employee's
   status, department, or job will fail at runtime.
2. **Non-functional authentication (SEC-03):** `PKG_SECURITY.authenticate` never verifies the
   supplied password against any stored credential — it authenticates on username existence alone.
3. **Weak cryptography (SEC-01/SEC-02):** passwords are hashed with unsalted MD5, and the AES key
   used to encrypt SSNs and bank account numbers is hard-coded in the package body.
4. **SQL injection (SEC-04):** `PKG_EMPLOYEE.search_employees` concatenates user input directly
   into dynamic SQL.

### Severity counts

| Severity  | Count |
|-----------|-------|
| CRITICAL  | 6     |
| HIGH      | 10    |
| MEDIUM    | 20    |
| LOW       | 7     |
| **Total** | **43** |

### Category breakdown

| Category                        | Prefix | CRITICAL | HIGH | MEDIUM | LOW | Total |
|---------------------------------|--------|----------|------|--------|-----|-------|
| Security vulnerabilities        | SEC    | 4        | 2    | 3      | 1   | 10    |
| Race conditions                 | RACE   | 0        | 2    | 3      | 1   | 6     |
| Performance issues              | PERF   | 0        | 1    | 4      | 2   | 7     |
| Validation drift                | DRIFT  | 0        | 0    | 3      | 1   | 4     |
| Circular dependencies           | CIRC   | 0        | 1    | 0      | 0   | 1     |
| Architectural anti-patterns     | ARCH   | 0        | 2    | 4      | 1   | 7     |
| Data integrity risks            | DATA   | 2        | 2    | 3      | 1   | 8     |
| **Total**                       |        | **6**    | **10** | **20** | **7** | **43** |

---

## 1. Security Vulnerabilities

### SEC-01 — Passwords hashed with unsalted MD5 — CRITICAL
**Location:** `plsql/packages/PKG_SECURITY.pkb:11-22`

```sql
RETURN RAWTOHEX(
    DBMS_CRYPTO.HASH(
        UTL_RAW.CAST_TO_RAW(p_password),
        DBMS_CRYPTO.HASH_MD5
    )
);
```

**Issue:** Passwords are hashed with MD5 and no salt. MD5 is cryptographically broken and
extremely fast to brute-force; the absence of a salt allows rainbow-table attacks and reveals
identical passwords across users.
**Impact:** Full credential compromise if the hash store is exfiltrated. The package's own header
(`PKG_SECURITY.pks:9`) acknowledges this: *"Password stored as MD5 hash (should be bcrypt/scrypt)."*
**Recommendation:** Migrate to a memory-hard adaptive KDF (bcrypt/scrypt/Argon2 via an external
service, or PBKDF2 with a high iteration count and per-user salt). Force a password reset on
migration.

### SEC-02 — Hard-coded AES encryption key in source — CRITICAL
**Location:** `plsql/packages/PKG_SECURITY.pkb:7`

```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```

**Issue:** The AES-256 key used by `encrypt_ssn`/`decrypt_ssn` (and, by extension, protecting SSNs
and encrypted bank account numbers) is embedded in the package body and committed to source control.
**Impact:** Anyone with read access to the source or `ALL_SOURCE` can decrypt all PII. Key rotation
is impossible without a code change and redeploy. The encryption also uses a fixed key with CBC and
no per-record IV, so identical plaintext yields identical ciphertext.
**Recommendation:** Store keys in Oracle Wallet / TDE or an external KMS/HSM. Use per-record random
IVs. Rotate the key and re-encrypt existing data.

### SEC-03 — Authentication never verifies the password — CRITICAL
**Location:** `plsql/packages/PKG_SECURITY.pkb:30-90`

```sql
SELECT EMP_ID INTO v_emp_id
FROM EMPLOYEES
WHERE UPPER(EMAIL) = UPPER(p_username)
AND EMPLOYMENT_STATUS = 'ACTIVE';
...
-- v_stored_hash / v_input_hash are declared but never compared
SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
INSERT INTO USER_SESSIONS (...) VALUES (...);  -- session created regardless of password
```

**Issue:** `authenticate` looks the user up by email and, if found, creates an active session. The
declared locals `v_stored_hash` and `v_input_hash` are never populated or compared. `p_password` is
accepted but never checked.
**Impact:** Anyone who knows a valid active email address can obtain a valid session — a complete
authentication bypass.
**Recommendation:** Load the stored credential, compute the hash of the supplied password with the
per-user salt, and compare in constant time before establishing a session. Fail closed.

### SEC-04 — SQL injection via dynamic string concatenation — CRITICAL
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:445-498`

```sql
IF p_last_name IS NOT NULL THEN
    v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
END IF;
...
IF p_status IS NOT NULL THEN
    v_sql := v_sql || 'AND e.EMPLOYMENT_STATUS = ''' || p_status || ''' ';
```

**Issue:** `search_employees` builds a dynamic query by concatenating caller-supplied filter values
directly into the SQL text, then opens a ref cursor over it.
**Impact:** Classic SQL injection — attackers can exfiltrate arbitrary data (including SSNs and
salaries) or subvert the query. Also defeats cursor sharing and pollutes the shared pool.
**Recommendation:** Use bind variables via `OPEN v_cursor FOR v_sql USING ...`, or a static SQL
statement with `(:p IS NULL OR col = :p)` predicates.

### SEC-05 — `change_password` is a non-functional stub — HIGH
**Location:** `plsql/packages/PKG_SECURITY.pkb:211-234`

```sql
IF LENGTH(p_new_password) < 8 THEN ...
-- NOTE: Actual password update would go to USER_CREDENTIALS table
-- This is a stub for the legacy system model
PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
```

**Issue:** The old password (`p_old_password`) is never verified, and the new password is never
persisted. The routine only validates complexity and then writes an audit record implying a change
occurred.
**Impact:** Users believe passwords are changed when they are not; audit log is misleading. Combined
with SEC-03, password management is effectively absent.
**Recommendation:** Verify the current password, then persist the new hash+salt to the credential
store within a proper transaction. Only audit on success.

### SEC-06 — No account lockout / failed-attempt throttling — HIGH
**Location:** `plsql/packages/PKG_SECURITY.pks:8-12`; `forms/xml-exports/HRMS_LOGIN.xml:10-13`

```
-- Known issues:
--   - No account lockout after failed attempts
```

**Issue:** There is no failed-attempt counter, lockout, backoff, or IP throttling in `authenticate`
or the login form.
**Impact:** Enables unlimited online password/credential-stuffing attacks (relevant even after
SEC-03 is fixed).
**Recommendation:** Track consecutive failures per account/IP, apply exponential backoff and
temporary lockout, and log/alert on thresholds.

### SEC-07 — Hard-coded SMTP configuration — MEDIUM
**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:6-10`

```sql
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
```

**Issue:** SMTP host/port and sender identity are hard-coded (the code comment itself says
*"should be in SYSTEM_PARAMETERS"*). Port 25 with no TLS.
**Impact:** Environment coupling (cannot promote across environments without a code change);
unencrypted mail transport.
**Recommendation:** Move to `SYSTEM_PARAMETERS`/wallet-backed config; use authenticated TLS (SMTPS
or STARTTLS).

### SEC-08 — `decrypt_ssn` swallows errors and returns a sentinel — MEDIUM
**Location:** `plsql/packages/PKG_SECURITY.pkb:194-206`

```sql
EXCEPTION
    WHEN OTHERS THEN
        RETURN '***DECRYPT_ERROR***';
```

**Issue:** Any decryption failure (tampering, key mismatch, corruption) is masked and returned as a
string literal instead of raising.
**Impact:** Data corruption or tampering is silently hidden; downstream code may persist or display
the sentinel as if it were real data.
**Recommendation:** Let cryptographic failures propagate (or log and re-raise a typed exception).
Never convert crypto failures into ordinary return values.

### SEC-09 — Duplicate active accounts tolerated during login — MEDIUM
**Location:** `plsql/packages/PKG_SECURITY.pkb:46-52`

```sql
WHEN TOO_MANY_ROWS THEN
    SELECT MIN(EMP_ID) INTO v_emp_id
    FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username)
    AND EMPLOYMENT_STATUS = 'ACTIVE';
```

**Issue:** When multiple active employees share an email, login silently picks the lowest `EMP_ID`.
There is no unique constraint on `EMPLOYEES.EMAIL` (see DATA-06) to prevent this.
**Impact:** Ambiguous identity resolution; a user could be logged in as the wrong person.
**Recommendation:** Enforce email uniqueness for active accounts and reject ambiguous logins.

### SEC-10 — Password transmitted in cleartext by login form — LOW
**Location:** `forms/xml-exports/HRMS_LOGIN.xml:10-13`

```
Known Issues:
  - Password field transmitted in cleartext (Forms applet limitation)
```

**Issue:** The legacy Forms applet transmits the password field without transport encryption.
**Impact:** Credential interception on untrusted networks.
**Recommendation:** Enforce TLS end-to-end at the application server / mid-tier; longer term,
replace the Forms login with a modern authenticated web front-end.

---

## 2. Race Conditions

### RACE-01 — `MAX()+1` employee-number generation — HIGH
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:36-55`; sequence declared but unused in
`schema/sequences/hrms_sequences.sql:18-21`

```sql
-- BUG: race condition under concurrent inserts - no SELECT FOR UPDATE
SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
INTO v_max_num
FROM EMPLOYEES
WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
```

**Issue:** Employee numbers are generated with `MAX()+1` and immediately used for the `INSERT`
(`PKG_EMPLOYEE.pkb:252-281`). A dedicated `SEQ_EMP_NUMBER` sequence exists but is used only in the
exception fallback. The sequence file explicitly documents this bug.
**Impact:** Two concurrent hires can generate the same `EMP_NUMBER`, causing a `UK_EMP_NUMBER`
violation or duplicate business keys.
**Recommendation:** Generate the number from `SEQ_EMP_NUMBER` (or an identity column) on the normal
path; remove `MAX()+1`.

### RACE-02 — Leave request overlap/balance check without locking — HIGH
**Location:** `plsql/packages/PKG_LEAVE.pkb:83-182`

```sql
v_balance := get_leave_balance(p_emp_id, p_leave_type_id);
... -- overlap and balance checks
INSERT INTO LEAVE_REQUESTS (...);
UPDATE LEAVE_BALANCES SET PENDING = PENDING + v_total_days ...;
```

**Issue:** Overlap and available-balance checks read without `FOR UPDATE`, then insert the request
and increment `PENDING`. Two concurrent requests can both pass the checks.
**Impact:** Overlapping approved leave and oversubscription of leave balances (negative available
balance).
**Recommendation:** Lock the employee's balance row(s) with `SELECT ... FOR UPDATE` before checking,
or enforce constraints/serialization at the DB level.

### RACE-03 — Promotion reads salary/job before update without `FOR UPDATE` — MEDIUM
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:592-614`

```sql
SELECT JOB_ID INTO v_old_job_id FROM EMPLOYEES WHERE EMP_ID = p_emp_id;
SELECT BASE_SALARY INTO v_old_salary FROM SALARY_RECORDS
WHERE EMP_ID = p_emp_id AND ACTIVE_FLAG = 'Y' AND ROWNUM = 1
ORDER BY EFFECTIVE_DATE DESC;
...
UPDATE EMPLOYEES SET JOB_ID = p_new_job_id ... WHERE EMP_ID = p_emp_id;
```

**Issue:** Old job/salary are read without locking and then used for a history/update. (Contrast
with `transfer_employee` at `PKG_EMPLOYEE.pkb:519-550`, which correctly uses `FOR UPDATE NOWAIT`.)
The salary sub-query also relies on `ROWNUM = 1` with `ORDER BY` in the same block, which does **not**
reliably return the latest row in Oracle.
**Impact:** Concurrent promotions/transfers can record stale "old" values; the `ROWNUM/ORDER BY`
bug can capture an arbitrary salary row.
**Recommendation:** Lock the employee row with `FOR UPDATE`; use a proper `ROW_NUMBER()`/subquery to
select the latest active salary.

### RACE-04 — Notification queue processed without row claiming — MEDIUM
**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:70-143`

```sql
FOR notif_rec IN (
    SELECT NOTIFICATION_ID, ... FROM NOTIFICATION_QUEUE WHERE STATUS = 'PENDING' ...
) LOOP
    ... send ...
    UPDATE NOTIFICATION_QUEUE SET STATUS = 'SENT' ...;
```

**Issue:** Pending rows are selected without `FOR UPDATE SKIP LOCKED` and updated to `SENT` only
after sending. Two concurrent workers can select and send the same notification.
**Impact:** Duplicate emails to employees.
**Recommendation:** Claim rows atomically with `SELECT ... FOR UPDATE SKIP LOCKED` (or an atomic
`UPDATE ... RETURNING`) before sending.

### RACE-05 — Salary change ends & inserts without locking / uniqueness guard — MEDIUM
**Location:** `plsql/packages/PKG_PAYROLL.pkb:35-55`

```sql
UPDATE SALARY_RECORDS SET END_DATE = p_effective_date - 1, ACTIVE_FLAG = 'N'
WHERE EMP_ID = p_emp_id AND ACTIVE_FLAG = 'Y' AND EFFECTIVE_DATE < p_effective_date;
INSERT INTO SALARY_RECORDS (... ACTIVE_FLAG ...) VALUES (... 'Y' ...);
```

**Issue:** The active salary row is end-dated and a new active row inserted without locking the
employee's salary rows first. `SALARY_RECORDS` has no unique constraint enforcing a single active
row per employee.
**Impact:** Two concurrent salary changes can leave multiple `ACTIVE_FLAG='Y'` rows, corrupting
`VW_EMPLOYEE_COMPENSATION` and payroll (which join on `sr.ACTIVE_FLAG = 'Y'`).
**Recommendation:** Lock the employee's salary rows (`FOR UPDATE`) before mutating; add a partial/
function-based unique index enforcing one active row per employee.

### RACE-06 — Balance adjust check-then-initialize race — LOW
**Location:** `plsql/packages/PKG_LEAVE.pkb:392-451`

```sql
UPDATE LEAVE_BALANCES SET ADJUSTMENT = ADJUSTMENT + p_adjustment ...;
IF SQL%ROWCOUNT = 0 THEN
    initialize_balances(p_emp_id, EXTRACT(YEAR FROM SYSDATE), p_user);
    UPDATE LEAVE_BALANCES SET ADJUSTMENT = ADJUSTMENT + p_adjustment ...;
END IF;
```

**Issue:** If no balance row exists, the code initializes then re-updates. `initialize_balances`
catches `DUP_VAL_ON_INDEX`, which mitigates the insert race, but the pattern relies on `SYSDATE`
year rather than an explicit business year.
**Impact:** Small window for inconsistent behavior around year boundaries and concurrent first-time
adjustments.
**Recommendation:** Use an atomic `MERGE` keyed on `(EMP_ID, LEAVE_TYPE_ID, CALENDAR_YEAR)`; pass
the calendar year explicitly.

---

## 3. Performance Issues

### PERF-01 — Day-by-day loop issuing one query per day — HIGH
**Location:** `plsql/packages/PKG_LEAVE.pkb:12-39`

```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', ...) NOT IN ('SAT', 'SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count FROM HOLIDAYS WHERE HOLIDAY_DATE = v_date ...;
        ...
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Issue:** `calculate_business_days` iterates one day at a time and runs a `HOLIDAYS` query per
weekday. Cost is O(days) SQL round-trips, and this is called during every leave request.
**Impact:** Long leave ranges and high request volume produce heavy DB load and slow form response.
**Recommendation:** Compute weekdays set-based (arithmetic on date diff) and subtract holidays with a
single range query.

### PERF-02 — `CONNECT BY` org chart / hierarchy view — MEDIUM
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:819-837`; `schema/views/hrms_views.sql:47-57`

```sql
-- Recursive query - known to time out for orgs with >500 employees
... START WITH EMP_ID = p_root_emp_id
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID AND LEVEL <= p_max_depth
```

**Issue:** Both `get_org_chart` and `VW_ORG_HIERARCHY` use `CONNECT BY` over `EMPLOYEES` with no
supporting index on `MANAGER_EMP_ID` and no cycle detection. The view header itself warns
*"Performance degrades significantly with >500 employees."*
**Impact:** Timeouts / high CPU on large orgs; risk of `CONNECT BY loop` errors if data has cycles.
**Recommendation:** Index `MANAGER_EMP_ID`, add `NOCYCLE`, bound depth, and consider a materialized
hierarchy or recursive CTE with pagination.

### PERF-03 — SMTP connection opened per notification inside a loop — MEDIUM
**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:70-143`

```sql
FOR notif_rec IN (...) LOOP
    v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
    ...
    UTL_SMTP.QUIT(v_connection);
END LOOP;
```

**Issue:** A fresh SMTP connection is opened and closed for every queued message. The failure path
also calls `UTL_SMTP.QUIT` on a possibly-uninitialized connection.
**Impact:** High per-message latency and connection churn; large queues drain slowly. Potential
secondary error in the exception handler.
**Recommendation:** Open one connection per batch and reuse it; guard `QUIT` with an initialized
flag; handle transient failures with ret/backoff.

### PERF-04 — Row-by-row payroll calculation with periodic commits — MEDIUM
**Location:** `plsql/packages/PKG_PAYROLL.pkb:271-347`

```sql
FOR emp_rec IN (SELECT e.EMP_ID FROM EMPLOYEES e WHERE ... ) LOOP
    BEGIN calculate_employee_pay(...); v_emp_count := v_emp_count + 1;
    EXCEPTION WHEN OTHERS THEN v_error_count := v_error_count + 1; INSERT ... ERROR ...; END;
    IF MOD(v_emp_count, 50) = 0 THEN COMMIT; END IF;
END LOOP;
```

**Issue:** Payroll is computed employee-by-employee with intra-run `COMMIT`s every 50 successes.
`v_emp_count` increments only on success, so the commit cadence is skewed by errors.
**Impact:** A mid-run failure leaves a partially committed, non-atomic payroll run; slow row-by-row
processing at scale.
**Recommendation:** Make the run atomic (single transaction with checkpoint/restart semantics), and
prefer set-based/bulk processing. Track progress in the run header rather than committing partial work.

### PERF-05 — Nested employee × leave-type accrual loops — MEDIUM
**Location:** `plsql/packages/PKG_LEAVE.pkb:455-552`

```sql
FOR emp_rec IN (SELECT ... FROM EMPLOYEES WHERE EMPLOYMENT_STATUS = 'ACTIVE' ...) LOOP
    FOR lt_rec IN (SELECT ... FROM LEAVE_TYPES WHERE ACCRUAL_FREQUENCY = 'MONTHLY') LOOP
        v_current_balance := get_leave_balance(...);
        UPDATE LEAVE_BALANCES SET ACCRUED = ACCRUED + v_accrued ...;
```

**Issue:** Monthly accrual nests a per-employee loop over a per-leave-type loop with a balance
lookup and update each iteration.
**Impact:** O(employees × leave types) statements per run; slow at scale. Concurrent runs can
double-credit without idempotency.
**Recommendation:** Set-based `MERGE`/`UPDATE`; add a per-period idempotency guard (e.g. via
`LEAVE_ACCRUAL_LOG`).

### PERF-06 — `NOCACHE` on nearly all sequences — LOW
**Location:** `schema/sequences/hrms_sequences.sql:9-49`

```sql
CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
-- ... almost every sequence is NOCACHE (only SEQ_AUDIT uses CACHE 100)
```

**Issue:** `NOCACHE` forces a dictionary update per `NEXTVAL`, serializing on the sequence.
**Impact:** Contention and latency under concurrent inserts (e.g. bulk hires, payroll detail rows).
**Recommendation:** Use `CACHE` (e.g. 20–1000) for high-throughput sequences. Gaps are acceptable
for surrogate keys.

### PERF-07 — Additional day-by-day loops in `PKG_COMMON` — LOW
**Location:** `plsql/packages/PKG_COMMON.pkb:131-165`

```sql
WHILE v_date <= TRUNC(p_end_date) LOOP ... v_date := v_date + 1; END LOOP;  -- business_days_between
WHILE v_added < p_days LOOP v_result := v_result + 1; ... END LOOP;         -- add_business_days
```

**Issue:** `business_days_between` and `add_business_days` iterate day by day.
**Impact:** Same O(days) inefficiency as PERF-01 (and see DRIFT-04 for a correctness gap).
**Recommendation:** Replace with set-based arithmetic.

---

## 4. Validation Drift (Forms PLL vs server-side packages)

### DRIFT-01 — Email validation differs between Forms and server — MEDIUM
**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41` vs
`plsql/packages/PKG_COMMON.pkb:265-280` (used by `PKG_VALIDATION.validate_email_format`)

```sql
-- Forms (client): manual INSTR checks for '@' and a following '.'
-- Server:
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

**Issue:** The Forms library uses hand-rolled `INSTR` logic while the server uses a regex. They
accept/reject different strings (e.g. handling of subdomains, plus-addressing, TLD length), and the
Forms version treats `NULL` as valid.
**Impact:** Data accepted by one layer and rejected by the other; inconsistent UX and possible
"valid in form, rejected on save" errors.
**Recommendation:** Centralize email validation in a single server-side function and have the Forms
layer call it, or share one canonical regex.

### DRIFT-02 — Date validation has inconsistent NULL semantics — MEDIUM
**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:96-99` vs
`plsql/packages/PKG_VALIDATION.pkb:6-15`

```sql
-- Forms: validate_date_not_future -> NULL is valid, only rejects future dates
RETURN p_date IS NULL OR TRUNC(p_date) <= TRUNC(SYSDATE);
-- Server: validate_date_range -> NULL is INVALID
IF p_start_date IS NULL OR p_end_date IS NULL THEN RETURN FALSE; END IF;
```

**Issue:** Client-side date validation permits NULL and only checks the future boundary; the
server-side range validation rejects NULLs and checks ordering. The two encode different rules.
**Impact:** Divergent acceptance of NULL/boundary dates across layers.
**Recommendation:** Define one canonical date-validation contract (NULL policy, future policy,
ordering) and enforce it in both layers via shared server-side functions.

### DRIFT-03 — Salary-range validation differs in required-ness and messages — MEDIUM
**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:108-135` vs
`plsql/packages/PKG_VALIDATION.pkb:17-48`

```sql
-- Forms: NULL salary/grade -> returns NULL (treated as OK); short messages
IF p_salary IS NULL OR p_grade_id IS NULL THEN RETURN NULL; END IF;
-- Server: NULL salary/grade -> hard error; richer messages
IF p_salary IS NULL OR p_grade_id IS NULL THEN RETURN 'Salary and grade are required'; END IF;
```

**Issue:** The Forms library treats missing salary/grade as valid and returns terse messages; the
server requires both and returns detailed, grade-qualified messages.
**Impact:** A record may pass the form yet fail server validation (or vice versa); inconsistent
error text.
**Recommendation:** Delegate salary validation to the server function from the form; standardize
messages.

### DRIFT-04 — Business-day calculations disagree on holidays — LOW
**Location:** `plsql/packages/PKG_COMMON.pkb:131-165` vs `plsql/packages/PKG_LEAVE.pkb:12-39`

**Issue:** `PKG_LEAVE.calculate_business_days` excludes weekends **and** `HOLIDAYS`, while
`PKG_COMMON.business_days_between` excludes only weekends.
**Impact:** Two "business days" definitions in the codebase produce different results depending on
which is called.
**Recommendation:** Consolidate into one holiday-aware business-day function used everywhere.

---

## 5. Circular Dependencies

### CIRC-01 — `PKG_EMPLOYEE` ↔ `PKG_PAYROLL` mutual dependency — HIGH
**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:273-275`; declared in both specs
(`PKG_EMPLOYEE.pks:6-9`, `PKG_PAYROLL.pks:6-9`)

```sql
-- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
-- which in turn may call PKG_EMPLOYEE.is_active for validation
PKG_PAYROLL.create_salary_record(...);
```

**Issue:** `PKG_EMPLOYEE` depends on `PKG_PAYROLL` (salary creation) and `PKG_PAYROLL` depends on
`PKG_EMPLOYEE` (`is_active` check). Both package headers explicitly document the cycle.
**Impact:** Fragile recompilation order (changing one invalidates the other), harder unit testing,
and risk of `INVALID` package states after DDL. Tight coupling impedes modularization/migration.
**Recommendation:** Break the cycle — extract shared validation into `PKG_COMMON`/a new
`PKG_EMPLOYEE_RULES`, or invert one dependency via an interface/callback so the two packages no
longer reference each other directly.

---

## 6. Architectural Anti-Patterns

### ARCH-01 — Overuse of `PRAGMA AUTONOMOUS_TRANSACTION` — MEDIUM
**Location:** `plsql/packages/PKG_COMMON.pkb:6-35, 40-61` (`log_error`, `log_info`);
`plsql/packages/PKG_AUDIT.pkb:6-31` (`log_action`);
`plsql/packages/PKG_NOTIFICATION.pkb:16-63` (`send_notification`)

```sql
PROCEDURE log_action(...) IS
    PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
    INSERT INTO AUDIT_LOG (...); COMMIT;
EXCEPTION WHEN OTHERS THEN ROLLBACK;  -- failures silently swallowed
```

**Issue:** Logging, auditing, and notification queuing all run in autonomous transactions that
commit independently of the caller and swallow errors. `send_notification` commits a queue row even
if the business transaction later rolls back.
**Impact:** Audit/notification state can diverge from business state (audit rows for rolled-back
work; notifications for actions that never committed). Swallowed errors hide failures.
**Recommendation:** Reserve autonomous transactions for true fire-and-forget diagnostics; for audit
and notification-enqueue, participate in the caller's transaction (enqueue in-transaction, deliver
out-of-band). Stop discarding exceptions.

### ARCH-02 — `UTL_FILE` flat-file integration in the database tier — MEDIUM
**Location:** `plsql/packages/PKG_INTEGRATION.pkb:16-83, 90-147`;
`plsql/packages/PKG_PAYROLL.pkb:821-894` (`generate_pay_register`)

```sql
v_file := UTL_FILE.FOPEN('PAYROLL_OUTPUT', v_filename, 'W', 32767);
... UTL_FILE.PUT_LINE(v_file, ...); ... UTL_FILE.FCLOSE(v_file);
```

**Issue:** GL journals, benefits feeds, and pay registers are written directly to Oracle directory
objects with no checksums, atomic publication (temp-then-rename), idempotency keys, or delivery
acknowledgement. Directory object names are hard-coded (`PKG_INTEGRATION.pkb:6-9`).
**Impact:** Fragile, environment-coupled batch integration; partial files can be consumed
downstream; no audit of delivery.
**Recommendation:** Move integration to a dedicated middle tier / message bus, or at minimum write
to temp files and atomically rename, add checksums/manifests, and externalize directory config.

### ARCH-03 — `import_time_attendance` is a stub that reports success — HIGH
**Location:** `plsql/packages/PKG_INTEGRATION.pkb:153-203`

```sql
IF v_line IS NOT NULL AND SUBSTR(v_line, 1, 1) != '#' THEN
    -- TODO: Implement actual parsing and database update
    v_imported := v_imported + 1;
END IF;
```

**Issue:** The importer counts lines and logs a successful import but never parses the data or
updates any table.
**Impact:** Time-and-attendance data is silently discarded while the system reports success —
directly affecting payroll correctness.
**Recommendation:** Implement real parsing/validation/persistence with error reporting, or disable
the entry point until implemented.

### ARCH-04 — `sync_org_structure` is a placeholder reporting success — MEDIUM
**Location:** `plsql/packages/PKG_INTEGRATION.pkb:196-203`

```sql
-- Placeholder for org structure sync with external directory (LDAP/AD)
PKG_COMMON.log_info(..., 'Org structure sync completed', p_user);
```

**Issue:** Logs "completed" without performing any synchronization.
**Impact:** Operators believe org structure is synced with LDAP/AD when nothing happens.
**Recommendation:** Implement the sync or remove/flag the stub; do not log success for no-ops.
(See also `PKG_REPORTING.refresh_reporting_tables` at `PKG_REPORTING.pkb:196-204`, ARCH-07.)

### ARCH-05 — Hard-coded 2024 tax brackets / FICA constants; `TAX_BRACKETS` table unused — HIGH
**Location:** `plsql/packages/PKG_PAYROLL.pkb:602-680` (`calculate_federal_tax`),
`723-735` (`calculate_fica`)

```sql
-- NOTE: Hard-coded 2024 brackets - should read from TAX_BRACKETS table
-- TODO: Read from TAX_BRACKETS table instead of hard-coding
IF p_ytd_gross >= c_ss_wage_base_2024 THEN RETURN 0; END IF;
```

**Issue:** Federal tax brackets, standard deduction, allowance amounts, and the Social Security wage
base are hard-coded to 2024 values, even though a `TAX_BRACKETS` table exists
(`schema/tables/02_payroll_tables.sql:159-173`) with a `TAX_YEAR` column intended to drive this.
**Impact:** Payroll computes incorrect tax in any year other than 2024; annual changes require code
edits and redeploys.
**Recommendation:** Drive all tax parameters from `TAX_BRACKETS`/config keyed by `TAX_YEAR` and
`FILING_STATUS`.

### ARCH-06 — Hard-coded fiscal-year start (October) — MEDIUM
**Location:** `plsql/packages/PKG_COMMON.pkb:168-195`

```sql
IF EXTRACT(MONTH FROM p_date) >= 10 THEN RETURN EXTRACT(YEAR FROM p_date) + 1;
ELSE RETURN EXTRACT(YEAR FROM p_date); END IF;
```

**Issue:** `get_fiscal_year` assumes an October–September fiscal year with no configuration.
**Impact:** Wrong fiscal-year attribution for any organization not on an Oct–Sep calendar.
**Recommendation:** Externalize the fiscal-year start month to `SYSTEM_PARAMETERS`.

### ARCH-07 — `refresh_reporting_tables` is a no-op placeholder — LOW
**Location:** `plsql/packages/PKG_REPORTING.pkb:196-204`

```sql
-- Placeholder for nightly refresh of denormalized reporting tables
PKG_COMMON.log_info('PKG_REPORTING', 'refresh_reporting_tables', 'Reporting tables refreshed', p_user);
```

**Issue:** Logs a successful nightly refresh without doing anything.
**Impact:** Reporting tables may be assumed fresh when they are not.
**Recommendation:** Implement the refresh or remove the misleading success log.

---

## 7. Data Integrity Risks

### DATA-01 — Employee-history trigger references non-existent columns — CRITICAL
**Location:** `plsql/triggers/trg_employees.sql:78-110` vs
`schema/tables/01_core_tables.sql:152-177`

```sql
-- Trigger inserts:
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (...);

-- EMPLOYEE_HISTORY DDL actually defines:
--   HIST_ID (not HISTORY_ID), EFFECTIVE_DATE (not CHANGE_DATE),
--   OLD_DEPT_ID/NEW_DEPT_ID/OLD_JOB_ID/... , REASON_CODE (not CHANGE_REASON),
--   COMMENTS, CREATED_BY NOT NULL, CREATED_DATE NOT NULL.
--   There are NO columns named OLD_VALUE, NEW_VALUE, CHANGED_BY, HISTORY_ID, CHANGE_DATE, CHANGE_REASON.
```

**Issue:** `TRG_EMP_BEFORE_UPDATE` inserts into columns that do not exist in the `EMPLOYEE_HISTORY`
table, and omits the `NOT NULL` `CREATED_BY`/`CREATED_DATE` columns. The trigger cannot compile/
execute successfully against the actual DDL (`ORA-00904: invalid identifier`).
**Impact:** **Every** update that changes employment status, department, or job — the exact events
the trigger fires on — fails. This blocks core employee lifecycle operations. Note `PKG_EMPLOYEE`'s
own history writes use the correct columns, so the trigger and the package disagree.
**Recommendation:** Rewrite the trigger to use the real columns (`HIST_ID`, `EFFECTIVE_DATE`,
`OLD_*/NEW_*`, `REASON_CODE`, `CREATED_BY`, `CREATED_DATE`), or drop the trigger and rely on
`PKG_EMPLOYEE` history logging. Add a compile/validity check to CI.

### DATA-02 — Trigger writes `CHANGE_TYPE` values that violate the check constraint — CRITICAL
**Location:** `plsql/triggers/trg_employees.sql:82, 94, 106` vs
`schema/tables/01_core_tables.sql:173-176`

```sql
-- Trigger uses: 'STATUS_CHANGE', 'DEPARTMENT_CHANGE', 'JOB_CHANGE'
CONSTRAINT CHK_CHANGE_TYPE CHECK (CHANGE_TYPE IN (
    'HIRE','TRANSFER','PROMOTION','DEMOTION','SALARY_CHANGE',
    'TERMINATION','REHIRE','LEAVE_START','LEAVE_END','STATUS_CHANGE'));
```

**Issue:** Even if the column names were fixed (DATA-01), `'DEPARTMENT_CHANGE'` and `'JOB_CHANGE'`
are not in `CHK_CHANGE_TYPE` (only `'STATUS_CHANGE'` is allowed).
**Impact:** Department/job updates would violate the check constraint (`ORA-02290`) once column names
are corrected.
**Recommendation:** Use allowed values (`'TRANSFER'` for dept, `'PROMOTION'`/`'DEMOTION'` for job) or
extend `CHK_CHANGE_TYPE` to include the new codes — and keep trigger and constraint in sync.

### DATA-03 — Insert trigger queries its own mutating table — HIGH
**Location:** `plsql/triggers/trg_employees.sql:42-54`

```sql
SELECT COUNT(*) INTO v_count FROM EMPLOYEES
WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL) AND ACTIVE_FLAG = 'Y';
IF v_count > 0 THEN RAISE_APPLICATION_ERROR(-20502, 'Email address already in use: ' || :NEW.EMAIL); END IF;
```

**Issue:** A row-level `BEFORE INSERT` trigger selects from the same `EMPLOYEES` table it is firing
on. This raises `ORA-04091 (table is mutating)` for multi-row inserts, and even for single-row
inserts the check is race-prone. The comment claims a unique constraint also enforces this, but none
exists (see DATA-06).
**Impact:** Multi-row inserts fail; concurrent single-row inserts can both pass, allowing duplicate
active emails.
**Recommendation:** Enforce active-email uniqueness with a function-based unique index (e.g. on
`UPPER(EMAIL)` filtered by active status) rather than a query inside the trigger.

### DATA-04 — Soft-delete inconsistency: delete is blocked, not softened — HIGH
**Location:** `plsql/triggers/trg_employees.sql:114-129`

```sql
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
BEFORE DELETE ON HRMS.EMPLOYEES FOR EACH ROW
BEGIN
    -- BUG: This actually prevents deletion, but Forms expects DELETE to succeed.
    RAISE_APPLICATION_ERROR(-20504, 'Direct deletion not allowed. ...');
```

**Issue:** The trigger is named `INSTEAD_OF_DELETE` but is actually a `BEFORE DELETE` trigger that
raises instead of converting the delete into an `ACTIVE_FLAG='N'` soft delete. The comment notes
Forms expects `DELETE` to succeed, requiring a per-form workaround.
**Impact:** Inconsistent soft-delete policy: some paths set `ACTIVE_FLAG='N'`, others rely on
`EMPLOYMENT_STATUS`, and direct deletes error out — divergent behavior across Forms and packages.
**Recommendation:** Standardize a single soft-delete/termination path; either implement a true
`INSTEAD OF` trigger on a view or handle soft-delete in the application layer consistently.

### DATA-05 — `VW_LEAVE_SUMMARY.AVAILABLE` disagrees with the table's computed column — MEDIUM
**Location:** `schema/views/hrms_views.sql:96` vs `schema/tables/03_leave_tables.sql:47`

```sql
-- View AVAILABLE (omits PENDING):
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE
-- Table virtual column AVAILABLE (subtracts PENDING):
AVAILABLE ... GENERATED ALWAYS AS (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL
```

**Issue:** The reporting view computes "available" leave without subtracting `PENDING`, but the base
table's virtual `AVAILABLE` column subtracts `PENDING`. Two different "available" numbers exist for
the same row.
**Impact:** Reports and forms can show more available leave than the authoritative column, enabling
over-booking and reconciliation confusion.
**Recommendation:** Make the view reference the table's `AVAILABLE` column (or align the formula) so
there is one definition of available leave.

### DATA-06 — Claimed email unique constraint does not exist — MEDIUM
**Location:** `plsql/triggers/trg_employees.sql:40-41` vs `schema/tables/01_core_tables.sql:98-143`

```sql
-- Trigger comment: "Validate email uniqueness (also enforced by unique constraint...)"
-- EMPLOYEES DDL: EMAIL VARCHAR2(100)  -- nullable, no UNIQUE constraint present
```

**Issue:** The insert trigger's comment asserts a backing unique constraint on email, but the
`EMPLOYEES` DDL defines `EMAIL` as a plain nullable column with only `PK_EMPLOYEES` and
`UK_EMP_NUMBER` as keys. The only uniqueness "enforcement" is the mutating-table query (DATA-03).
**Impact:** Duplicate emails are possible (see SEC-09), and login identity resolution is ambiguous.
**Recommendation:** Add the intended unique index (function-based, active-only) and update the
comment to match reality.

### DATA-07 — Audit trigger builds JSON by manual string concatenation — MEDIUM
**Location:** `plsql/triggers/trg_audit.sql:10-40`

```sql
v_new_json := '{"emp_id":' || :NEW.EMP_ID ||
              ',"salary":' || :NEW.BASE_SALARY ||
              ',"effective":"' || TO_CHAR(:NEW.EFFECTIVE_DATE, 'YYYY-MM-DD') || '"}';
```

**Issue:** `TRG_SALARY_AUDIT` constructs JSON by hand. Values are not escaped and numbers use the
session's `NLS` settings, so a comma decimal separator or special characters would produce invalid
JSON. The trigger also adds overhead to every high-volume salary DML.
**Impact:** Corrupt/unparseable audit payloads; audit overhead on salary operations.
**Recommendation:** Use `JSON_OBJECT`/`JSON_ARRAY` (19c) to build well-formed JSON; force
locale-independent number formatting.

### DATA-08 — Login identity column (`EMAIL`) is nullable — LOW
**Location:** `schema/tables/01_core_tables.sql:98-143`; used by `PKG_SECURITY.authenticate:41-44`

**Issue:** `EMAIL` is used as the login username but is defined nullable with no unique/`NOT NULL`
constraint.
**Impact:** Employees without email cannot log in and NULL emails complicate uniqueness/identity.
**Recommendation:** Decide the identity policy: if email is the login, make it `NOT NULL` + unique
for active accounts, or introduce a dedicated username column.

---

## 8. Prioritized Migration Roadmap

### Phase 1 — Critical Security (immediate)
- **SEC-03:** Implement real password verification in `authenticate` (fail closed).
- **SEC-01/SEC-02:** Replace MD5 with a salted adaptive KDF; move the AES key to Wallet/KMS, add
  per-record IVs, re-encrypt PII.
- **SEC-04:** Parameterize `search_employees` with bind variables.
- **SEC-05/SEC-06:** Implement functional `change_password` and account lockout/throttling.
- **SEC-08/SEC-09/SEC-10:** Stop masking decrypt errors, enforce single active identity, enforce TLS.

### Phase 2 — Data Integrity (weeks 1–4)
- **DATA-01/DATA-02:** Fix or drop `TRG_EMP_BEFORE_UPDATE` so employee updates succeed; align
  `CHANGE_TYPE` values with `CHK_CHANGE_TYPE`. Add package/trigger validity checks to CI.
- **DATA-03/DATA-06:** Replace the mutating-table email check with a function-based unique index.
- **DATA-04:** Standardize the soft-delete/termination path.
- **DATA-05:** Reconcile `VW_LEAVE_SUMMARY.AVAILABLE` with the table's computed column.
- **DATA-07:** Use native JSON generation in the audit trigger.
- **RACE-01/RACE-02/RACE-05:** Add sequence-based key generation and row locking / uniqueness for
  employee numbers, leave balances, and active salary rows.

### Phase 3 — Performance (weeks 4–8)
- **PERF-01/PERF-07/DRIFT-04:** Replace day-by-day loops with a single holiday-aware, set-based
  business-day function.
- **PERF-03/RACE-04:** Reuse SMTP connections per batch and claim queue rows with
  `FOR UPDATE SKIP LOCKED`.
- **PERF-04/PERF-05:** Move payroll and accrual to atomic, set-based processing.
- **PERF-02:** Index `MANAGER_EMP_ID`, add `NOCYCLE`/bounds to hierarchy queries.
- **PERF-06:** Enable sequence caching on high-throughput sequences.

### Phase 4 — Modernization (months 2–6)
- **ARCH-05/ARCH-06:** Drive tax and fiscal-year parameters from tables/config (`TAX_BRACKETS`,
  `SYSTEM_PARAMETERS`).
- **ARCH-03/ARCH-04/ARCH-07:** Implement (or remove) the stub integrations and stop logging false
  success.
- **ARCH-01:** Rework autonomous-transaction logging/audit/notification to align with business
  transactions.
- **ARCH-02:** Replace `UTL_FILE` batch integration with a middle-tier/message-bus solution with
  atomic publication and delivery guarantees.
- **CIRC-01:** Break the `PKG_EMPLOYEE ↔ PKG_PAYROLL` cycle by extracting shared rules.
- **DRIFT-01/DRIFT-02/DRIFT-03:** Consolidate validation into shared server-side functions invoked
  by both Forms and packages.
