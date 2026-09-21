# Technical Debt Report — Oracle Forms / PL/SQL HRMS Estate

**Repository**: `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Analysis date**: 2026-09-21
**Scope**: `plsql/packages/*.pks|pkb`, `plsql/triggers/*.sql`, `schema/**`, `forms/libraries/*.pll.sql`, `forms/xml-exports/*.xml`, `data/seed/*.sql` (~7,200 lines)
**Method**: Static analysis of every package, trigger, table, view and Forms export. Each finding was verified directly against the source; line numbers refer to the current `main` revision. Where a code comment claims a defect that the code does not actually exhibit, the report says so.

---

## Executive Summary

The HRMS estate is a classic three-tier Oracle Forms application whose business logic is spread across Forms triggers, PLL libraries, PL/SQL packages and database triggers. The analysis identified **50 technical debt items**. The most urgent are not the well-known "MD5 / hard-coded key" items but two defects that break the system outright:

1. **`PKG_SECURITY.authenticate` never compares the password** (SEC-00). Any string authenticates any active employee email.
2. **`TRG_EMP_BEFORE_UPDATE` references six columns that do not exist on `EMPLOYEE_HISTORY`** (DATA-00). The trigger cannot compile, and an invalid trigger blocks *every* UPDATE on `EMPLOYEES` with ORA-04098.

### Severity counts

| Severity | Count | Representative items |
|----------|-------|----------------------|
| CRITICAL | 10 | Authentication bypass, trigger/DDL column mismatch, MD5 hashing, hard-coded AES key, SQL injection, cleartext password transmission, payroll error-handler FK violation |
| HIGH | 14 | MAX()+1 race, missing lockout, timing attack, hire-date drift across 4 layers, cross-year leave balance, autonomous-transaction audit, swallowed audit failures |
| MEDIUM | 18 | Row-by-row loops, CONNECT BY, per-row SMTP connections, COMMIT inside packages, hard-coded tax brackets, view/virtual-column mismatch |
| LOW | 8 | NOCACHE sequences, stale reporting tables, hard-coded fiscal year, stub implementations |

### Category breakdown

| Category | Items | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| 1. Security | 14 | 6 | 4 | 4 | 0 |
| 2. Race conditions | 3 | 0 | 1 | 2 | 0 |
| 3. Performance | 8 | 0 | 0 | 6 | 2 |
| 4. Validation drift | 6 | 0 | 2 | 3 | 1 |
| 5. Circular dependencies | 2 | 0 | 1 | 1 | 0 |
| 6. Architectural anti-patterns | 8 | 0 | 2 | 2 | 4 |
| 7. Data integrity | 9 | 4 | 4 | 0 | 1 |
| **Total** | **50** | **10** | **14** | **18** | **8** |

---

## 1. Security Vulnerabilities

### SEC-00: Authentication Does Not Verify the Password (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:30-80`
```sql
FUNCTION authenticate(p_username IN VARCHAR2, p_password IN VARCHAR2, ...) RETURN NUMBER IS
    v_stored_hash VARCHAR2(200);
    v_input_hash  VARCHAR2(200);
BEGIN
    SELECT EMP_ID INTO v_emp_id FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
    ...
    -- NOTE: In the real system, passwords are stored in a separate
    -- USER_CREDENTIALS table. For this legacy codebase, we simulate
    -- authentication against a simplified model.
    SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
    INSERT INTO USER_SESSIONS (...)
```
**Issue**: `p_password` is never read. `v_stored_hash`/`v_input_hash` are declared but never assigned; `hash_password` is never called from `authenticate`. Any non-null string logs in as any active employee. `change_password` (lines 211-234) is likewise a stub that only writes an audit row. The `HRMS_LOGIN` form (`HRMS_LOGIN.xml:69-72`) only checks that the password field is non-null.
**Impact**: Complete authentication bypass. Every downstream control (`has_permission`, session validation, audit `CHANGED_BY`) is built on an unauthenticated identity.
**Recommendation**: Introduce a `USER_CREDENTIALS` table (salted hash, `FAILED_ATTEMPTS`, `LOCKED_UNTIL`), compute and compare the hash in `authenticate` using constant-time comparison, and implement `change_password` end-to-end. Treat this as a release blocker.

---

### SEC-01: MD5 Password Hashing, Unsalted (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:14-24`
```sql
RETURN RAWTOHEX(
    DBMS_CRYPTO.HASH(
        UTL_RAW.CAST_TO_RAW(p_password),
        DBMS_CRYPTO.HASH_MD5
    )
);
```
**Issue**: MD5 without salt. Precomputed/rainbow tables recover the majority of real-world passwords in seconds; identical passwords produce identical hashes across users.
**Impact**: Full credential compromise if the credential store is exfiltrated.
**Recommendation**: Per-user random salt + PBKDF2/bcrypt/scrypt (via Java stored procedure or external auth). If a pure-PL/SQL interim is required, iterate `DBMS_CRYPTO.HASH_SH512` ≥100k rounds with a per-user salt. Force password reset on migration.

---

### SEC-02: Hard-Coded AES-256 Encryption Key (CRITICAL)

**File**: `plsql/packages/PKG_SECURITY.pkb:7`, used at `:184-188` and `:197-201`
```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('<redacted literal key>');
```
**Issue**: The key protecting `EMPLOYEES.SSN_ENCRYPTED`, `EMPLOYEE_DEPENDENTS.SSN_ENCRYPTED` and bank details is a literal in source control, readable by any developer, DBA (`DBA_SOURCE`) or repository reader. Additionally, no IV is supplied to `DBMS_CRYPTO.ENCRYPT` in CBC mode, so identical SSNs encrypt to identical ciphertext (enables equality inference). `decrypt_ssn` swallows all errors and returns `'***DECRYPT_ERROR***'` (line 203-205), masking tampering.
**Impact**: Total PII exposure for every employee and dependent; SOX/PCI/HIPAA/GDPR exposure.
**Recommendation**: Move key material to Oracle Wallet / OKV or use TDE column encryption; generate a random IV per record and store it alongside the ciphertext; rotate the compromised key and re-encrypt; raise decryption failures instead of masking them.

---

### SEC-03: SQL Injection via String Concatenation in `search_employees` (CRITICAL)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:445-499`
```sql
IF p_last_name IS NOT NULL THEN
    -- VULNERABILITY: String concatenation instead of bind variable
    v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
END IF;
IF p_first_name IS NOT NULL THEN
    v_sql := v_sql || 'AND UPPER(e.FIRST_NAME) LIKE UPPER(''' || p_first_name || '%'') ';
END IF;
...
IF p_status IS NOT NULL THEN
    v_sql := v_sql || 'AND e.EMPLOYMENT_STATUS = ''' || p_status || ''' ';
END IF;
IF p_location_code IS NOT NULL THEN
    v_sql := v_sql || 'AND e.LOCATION_CODE = ''' || p_location_code || ''' ';
END IF;
OPEN p_cursor FOR v_sql;
```
**Issue**: Four `VARCHAR2` parameters (`p_last_name`, `p_first_name`, `p_status`, `p_location_code`) are concatenated into dynamic SQL with no `DBMS_ASSERT.ENQUOTE_LITERAL` or bind variables. The package is `HRMS`-owned and executes with definer's rights, so a payload such as `x') UNION SELECT ... FROM EMPLOYEES WHERE SSN_ENCRYPTED IS NOT NULL --` returns arbitrary data.
**Impact**: Read of any HRMS data (including encrypted SSN + the hard-coded key = plaintext SSN); with `EXECUTE IMMEDIATE`-capable helper functions, write access. The comment "Forms LOV passes validated values" is not a control — the package is callable from any session with EXECUTE privilege.
**Recommendation**: Rewrite with bind variables (`USING`) or a static SQL with `NVL(:p, col) = col` predicates; add `DBMS_ASSERT` as defence-in-depth; audit all other `OPEN ... FOR <string>` usages (this is the only one in the estate today).

---

### SEC-04: Cleartext Password Transmission Forms → DB (CRITICAL)

**File**: `forms/xml-exports/HRMS_LOGIN.xml:74-79`
```sql
v_session_id := PKG_SECURITY.authenticate(
    :LOGIN.USERNAME,
    :LOGIN.PASSWORD,
    GET_APPLICATION_PROPERTY(CLIENT_HOST)
);
```
**Issue**: The password is passed as a plain PL/SQL argument over SQL*Net. Header comment (`HRMS_LOGIN.xml:11`) acknowledges "Password field transmitted in cleartext". Nothing in the repository configures Oracle Native Network Encryption or TLS.
**Impact**: Credential capture by anyone on the network path between WebLogic/Forms server and the database.
**Recommendation**: Enforce `SQLNET.ENCRYPTION_SERVER=REQUIRED` + `SQLNET.CRYPTO_CHECKSUM_SERVER=REQUIRED` or TCPS; longer term delegate authentication to SSO (SAML/OIDC) so the password never reaches the database tier.

---

### SEC-05: Payroll Error Handler Violates FK/CHECK, Aborting the Whole Run (CRITICAL)

**Files**: `plsql/packages/PKG_PAYROLL.pkb:306-320` vs `schema/tables/02_payroll_tables.sql:136-154`
```sql
EXCEPTION
    WHEN OTHERS THEN
        v_error_count := v_error_count + 1;
        INSERT INTO PAYROLL_DETAILS (DETAIL_ID, RUN_ID, EMP_ID, ELEMENT_ID,
            ELEMENT_TYPE, AMOUNT, STATUS, ERROR_MESSAGE, CREATED_BY, CREATED_DATE)
        VALUES (SEQ_PAYROLL_DETAIL.NEXTVAL, p_run_id, emp_rec.EMP_ID, 0,
            'ERROR', 0, 'ERROR', SUBSTR(SQLERRM, 1, 4000), p_user, SYSDATE);
```
**Issue**: `PAYROLL_DETAILS.ELEMENT_ID` has `FK_PD_ELEMENT → PAY_ELEMENTS(ELEMENT_ID)`. No `PAY_ELEMENTS` row with `ELEMENT_ID = 0` exists in `data/seed/01_reference_data.sql`. The "log and continue" INSERT therefore raises ORA-02291 *inside the exception handler*, which propagates out of the cursor loop after a `COMMIT` at line 292 has already left the run in `CALCULATING`.
**Impact**: A single employee calculation failure aborts the entire payroll run and strands it in `CALCULATING` status. (Classified under Security because it is an availability failure of the payment path; also a data-integrity defect.)
**Recommendation**: Log errors to a dedicated `PAYROLL_RUN_ERRORS` table with no FK to `PAY_ELEMENTS`, or make `ELEMENT_ID` nullable for `STATUS='ERROR'` rows. Add a run-level `EXCEPTION` handler that sets `PAYROLL_RUNS.STATUS='ERROR'`.

---

### SEC-06: No Account Lockout / Brute-Force Protection (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb:26-80`; `PKG_SECURITY.pks:8-11` ("No account lockout after failed attempts")

**Issue**: `e_account_locked` (-20302) is declared in the spec but never raised. There is no failed-attempt counter, delay or lockout. `SYSTEM_PARAMETERS` seeds `PASSWORD_MIN_LENGTH` (`data/seed/01_reference_data.sql:193`) but nothing reads it — `change_password` hard-codes `8`.
**Impact**: Unlimited online guessing once SEC-00 is fixed.
**Recommendation**: `FAILED_ATTEMPTS` + `LOCKED_UNTIL` on `USER_CREDENTIALS`; lock after N attempts (read N from `SYSTEM_PARAMETERS`); exponential back-off; alert via `PKG_NOTIFICATION`.

---

### SEC-07: Username Enumeration via Timing / Error Path (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb:41-57`
```sql
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        -- VULNERABILITY: Timing attack - different response time for
        -- invalid user vs invalid password
        RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
```
**Issue**: Unknown users short-circuit before any hashing/session work; known users proceed through sequence fetch, INSERT, `set_session_context` and audit logging. Response-time differential reveals which emails are active employees.
**Impact**: Enumeration of the staff directory; targeted phishing/credential stuffing.
**Recommendation**: Always compute a dummy hash on the unknown-user path; use constant-time comparison; return identical error text and timing.

---

### SEC-08: Duplicate Active Emails Resolved by `MIN(EMP_ID)` (HIGH)

**File**: `plsql/packages/PKG_SECURITY.pkb:51-56`
```sql
WHEN TOO_MANY_ROWS THEN
    -- Multiple employees with same email - use first active one
    SELECT MIN(EMP_ID) INTO v_emp_id ...
```
**Issue**: `EMPLOYEES.EMAIL` is intended unique (trigger `TRG_EMP_BEFORE_INSERT:40-54` enforces it for `ACTIVE_FLAG='Y'` only). If two active-status employees share an email, the login silently binds to the lowest `EMP_ID` — an account-takeover vector when an inactive-flag record is re-activated.
**Impact**: Identity confusion; wrong employee's permissions and PII exposed.
**Recommendation**: Enforce a function-based unique index on `UPPER(EMAIL)` where `EMPLOYMENT_STATUS='ACTIVE'`; treat `TOO_MANY_ROWS` as a hard failure and alert.

---

### SEC-09: No Multi-Factor / SSO Support (HIGH)

**File**: `forms/xml-exports/HRMS_LOGIN.xml:10-13`

**Issue**: Single-factor username/password; header lists "No CAPTCHA or 2FA support" as known.
**Impact**: A phished or reused password grants full access.
**Recommendation**: Integrate enterprise SSO (Oracle Access Manager / SAML / OIDC) via Forms SSO mode; fall back to TOTP for local accounts.

---

### SEC-10: Hard-Coded SMTP Configuration, Port 25, No AUTH/TLS (MEDIUM)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb:6-10`, `:90-91`
```sql
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
```
**Issue**: Config baked into the body; `UTL_SMTP.OPEN_CONNECTION` on port 25 with `HELO`, no STARTTLS, no AUTH. Env promotion requires recompiling.
**Impact**: Cleartext email containing salary/termination/leave details; environment-specific builds.
**Recommendation**: Read host/port/from-address from `SYSTEM_PARAMETERS` via `PKG_COMMON.get_param`; use `UTL_SMTP.STARTTLS` with a wallet; port 587.

---

### SEC-11: SMTP Header Injection via Unsanitised Subject/Recipient (MEDIUM)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb:96-105`
```sql
UTL_SMTP.WRITE_DATA(v_connection, 'To: ' || notif_rec.RECIPIENT_EMAIL || UTL_TCP.CRLF);
UTL_SMTP.WRITE_DATA(v_connection, 'Subject: ' || notif_rec.SUBJECT || UTL_TCP.CRLF);
```
**Issue**: Subjects are built from user-entered data (e.g. leave `REASON`, employee names in `PKG_LEAVE.pkb:189-194`, `PKG_EMPLOYEE.pkb:729-733`). A CRLF in any of these injects additional headers (`Bcc:`, additional recipients).
**Impact**: Notification spam/exfiltration via the corporate relay.
**Recommendation**: Strip `CHR(10)`/`CHR(13)` from all header values; validate `RECIPIENT_EMAIL` with `PKG_COMMON.is_valid_email` before queuing.

---

### SEC-12: Integration Credentials in Cleartext `SYSTEM_PARAMETERS` (MEDIUM)

**File**: `plsql/packages/PKG_INTEGRATION.pks:8-12` ("FTP credentials stored in SYSTEM_PARAMETERS table (cleartext)")

**Issue**: Vendor/FTP credentials live in a general-purpose config table readable by anyone with SELECT on `SYSTEM_PARAMETERS`; FTP itself is unencrypted.
**Impact**: Lateral movement to the GL and benefits providers.
**Recommendation**: Oracle Wallet / external secret store; SFTP or HTTPS APIs.

---

### SEC-13: Hand-Rolled JSON in Audit Payloads (MEDIUM)

**Files**: `plsql/packages/PKG_COMMON.pkb:22-26`, `plsql/triggers/trg_audit.sql:20-29`
```sql
v_old_json := '{"salary":' || :OLD.BASE_SALARY || ',"active":"' || :OLD.ACTIVE_FLAG || '"}';
v_new_json := '{"salary":' || :NEW.BASE_SALARY || ',"active":"' || :NEW.ACTIVE_FLAG || '"}';
```
**Issue**: JSON produced by concatenation; only `PKG_COMMON.log_error` escapes `"` and nothing escapes `\` or control characters. A NULL `BASE_SALARY` yields `"salary":,` — invalid JSON.
**Impact**: Unparseable audit records; log-injection into downstream SIEM.
**Recommendation**: Use `JSON_OBJECT(...)` (19c) everywhere.

---

## 2. Race Conditions

### RACE-01: `MAX()+1` Employee Number Generation (HIGH)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:34-55`; `schema/sequences/hrms_sequences.sql:18-21`
```sql
-- BUG: race condition under concurrent inserts - no SELECT FOR UPDATE
SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
INTO v_max_num FROM EMPLOYEES WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
...
EXCEPTION WHEN OTHERS THEN
    RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMPLOYEE.NEXTVAL, 6, '0');
```
**Issue**: Two concurrent hires read the same MAX and produce the same `EMP-NNNNNN`. `SEQ_EMP_NUMBER` exists (`START WITH 1000`) but is unused. Worse, the fallback uses `SEQ_EMPLOYEE` (the `EMP_ID` sequence, `START WITH 10000`) — a different number space that will eventually collide with MAX()+1 values.
**Impact**: `ORA-00001` on `UK_EMP_NUMBER` at commit, or duplicate business identifiers if the constraint is ever relaxed.
**Recommendation**: `SEQ_EMP_NUMBER.NEXTVAL` only; delete the MAX() path and the mismatched fallback.

---

### RACE-02: Pay-Period Status Checked Without Lock (MEDIUM)

**File**: `plsql/packages/PKG_PAYROLL.pkb:240-260`
```sql
SELECT STATUS INTO v_status FROM PAY_PERIODS WHERE PERIOD_ID = p_period_id;
IF v_status = 'CLOSED' THEN RAISE_APPLICATION_ERROR(-20102, ...); END IF;
...
INSERT INTO PAYROLL_RUNS (...)
```
**Issue**: No `FOR UPDATE`; `close_pay_period` can commit between the check and the INSERT.
**Impact**: Payroll run created against a closed period; GL feed double-posts.
**Recommendation**: `SELECT ... FOR UPDATE`, or a deferrable check constraint / trigger on `PAYROLL_RUNS` verifying period status.

---

### RACE-03: Leave Balance Check-Then-Update Without Lock (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pkb:67-182` (`submit_leave_request`)

**Issue**: Available balance and overlap (`check_leave_overlap`, lines 45-62) are evaluated with plain SELECTs; the `UPDATE LEAVE_BALANCES SET PENDING = PENDING + ...` at line 176 happens later. Two simultaneous submissions from the same employee (self-service portal + Forms) can both pass and overdraw. Approval paths at lines 223/279/329 do use `FOR UPDATE`, so the gap is only in submission.
**Impact**: Negative available balances; overlapping approved leave.
**Recommendation**: Lock the `LEAVE_BALANCES` row (`FOR UPDATE`) at the start of `submit_leave_request`.

---

## 3. Performance Issues

### PERF-01: Day-by-Day Loop in `PKG_COMMON.business_days_between` (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:132-146`
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        v_count := v_count + 1;
    END IF;
    v_date := v_date + 1;
END LOOP;
```
**Issue**: O(days) with a `TO_CHAR` per iteration. Tenure and multi-year reporting calls iterate thousands of times.
**Recommendation**: Closed-form weekday arithmetic (`TRUNC(days/7)*5 + remainder adjustment`) or a `CALENDAR` dimension table.

---

### PERF-02: Day-by-Day Loop in `PKG_COMMON.add_business_days` (MEDIUM)

**File**: `plsql/packages/PKG_COMMON.pkb:151-165`

**Issue**: Same pattern as PERF-01.
**Recommendation**: Same closed-form approach.

---

### PERF-03: Day-by-Day Loop with a Query per Day in `PKG_LEAVE.calculate_business_days` (MEDIUM)

**File**: `plsql/packages/PKG_LEAVE.pkb:12-40`
```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', ...) NOT IN ('SAT', 'SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count FROM HOLIDAYS
        WHERE HOLIDAY_DATE = v_date AND ACTIVE_FLAG = 'Y' ...
```
**Issue**: Worse than PERF-01 — one SQL round-trip per weekday. A 3-month sabbatical = ~65 context switches.
**Impact**: Leave submission latency; `HOLIDAYS` becomes a hot block under batch accrual.
**Recommendation**: Single set-based query: weekday count minus `COUNT(*) FROM HOLIDAYS WHERE HOLIDAY_DATE BETWEEN ... AND weekday`.

---

### PERF-04: `CONNECT BY` Org Hierarchy View (MEDIUM)

**File**: `schema/views/hrms_views.sql:42-57`
```sql
-- WARNING: Performance degrades significantly with >500 employees
CREATE OR REPLACE VIEW HRMS.VW_ORG_HIERARCHY AS
SELECT ..., SYS_CONNECT_BY_PATH(FIRST_NAME || ' ' || LAST_NAME, ' > ') AS ORG_PATH
FROM EMPLOYEES WHERE EMPLOYMENT_STATUS = 'ACTIVE'
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
ORDER SIBLINGS BY LAST_NAME;
```
**Issue**: Full-tree traversal with string path construction on every query; the view cannot be filtered to a sub-tree without materialising the whole hierarchy. No `NOCYCLE`, so a bad `MANAGER_EMP_ID` loop (guarded only in `PKG_EMPLOYEE.validate_manager`) raises ORA-01436.
**Recommendation**: Recursive `WITH` CTE parameterised by root, or a maintained closure table; add `NOCYCLE` as a safety net.

---

### PERF-05: Row-by-Row Payroll Calculation with Per-Employee COMMIT (MEDIUM)

**File**: `plsql/packages/PKG_PAYROLL.pkb:265-346`
```sql
-- BUG: Cursor loop - should use BULK COLLECT + FORALL
FOR emp_rec IN (SELECT e.EMP_ID FROM EMPLOYEES e WHERE ...) LOOP
    calculate_employee_pay(p_run_id, emp_rec.EMP_ID, v_period_id, p_user);
    ...
    COMMIT;   -- line 325, every N rows
```
**Issue**: `calculate_employee_pay` executes several statements per employee; intermediate COMMITs make the run non-atomic and non-restartable.
**Impact**: Payroll runtime scales linearly with headcount; partial runs after failure.
**Recommendation**: Set-based INSERT...SELECT for standard elements, `FORALL` for the rest; one transaction per run with a restart marker.

---

### PERF-06: New SMTP Connection per Notification (MEDIUM)

**File**: `plsql/packages/PKG_NOTIFICATION.pkb:78-107`
```sql
FOR notif_rec IN (... FETCH FIRST p_batch_size ROWS ONLY) LOOP
    v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
    UTL_SMTP.HELO(...); ... UTL_SMTP.QUIT(v_connection);
END LOOP;
```
**Issue**: TCP + SMTP handshake for each of up to 50 messages. Additionally, `FAILED` rows (line 123) are only re-queued if a separate `retry_failed` procedure (lines 148-159) is scheduled; `process_queue` itself selects only `STATUS='PENDING'`.
**Impact**: Slow drain; failures stay dead-lettered unless a second job is configured.
**Recommendation**: One connection per batch with `RSET` between messages; fold retry into `process_queue`.

---

### PERF-07: `NOCACHE` on 28 of 29 Sequences (LOW)

**File**: `schema/sequences/hrms_sequences.sql:9-45`

**Issue**: Every `NEXTVAL` on `SEQ_EMPLOYEE`, `SEQ_PAYROLL_DETAIL`, `SEQ_LEAVE_REQUEST` etc. updates `SEQ$` on disk. Only `SEQ_AUDIT` has `CACHE 100`.
**Impact**: `row cache lock` / `DFS lock handle` contention during payroll and batch accrual.
**Recommendation**: `CACHE 20`–`100` on all high-volume sequences; gaps are acceptable for surrogate keys.

---

### PERF-08: Nightly-Refreshed Denormalised Reporting Tables (LOW)

**File**: `plsql/packages/PKG_REPORTING.pks:8-10`

**Issue**: Reporting reads stale copies during business hours.
**Recommendation**: Materialised views with fast refresh, or query the base tables with appropriate indexes.

---

## 4. Validation Drift (Forms / PLL vs Server-Side)

### DRIFT-01: Hire-Date Future Limit Differs in Every Layer (HIGH)

| Layer | File | Rule |
|-------|------|------|
| PLL | `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:96-99` `validate_date_not_future` | must be ≤ today |
| Forms trigger | `forms/xml-exports/HRMS_EMPLOYEE.xml:382-386` | ≤ SYSDATE + **90** days |
| DB trigger | `plsql/triggers/trg_employees.sql:34-38` | ≤ SYSDATE + **180** days |
| Package | `plsql/packages/PKG_EMPLOYEE.pkb:185-330` `hire_employee` | **no check** |

**Issue**: Four different answers to "how far in the future can a hire date be". A batch or API caller of `hire_employee` bypasses the 90/180-day limits entirely, and a Forms user is limited to 90 days while the database would accept 180.
**Impact**: Inconsistent data; support tickets when the same record is accepted in one path and rejected in another.
**Recommendation**: Single `PKG_VALIDATION.validate_hire_date` reading the limit from `SYSTEM_PARAMETERS`; Forms and trigger call it.

---

### DRIFT-02: Email Validation — PLL Hand-Rolled vs Server Regex (HIGH)

**Client** (`forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41`):
```sql
v_at_pos := INSTR(p_email, '@');
IF v_at_pos = 0 OR v_at_pos = 1 OR v_at_pos = LENGTH(p_email) THEN RETURN FALSE; END IF;
v_dot_pos := INSTR(p_email, '.', v_at_pos);
IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN RETURN FALSE; END IF;
-- BUG: Only checks for one dot after @, rejects valid subdomains
RETURN TRUE;
```
**Server** (`plsql/packages/PKG_COMMON.pkb:265-268`):
```sql
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```
**Issue**: The PLL comment claims it *rejects* subdomains; tracing the code shows the opposite — `user@mail.company.com` passes (first dot after `@` is at position 9, not adjacent, not last). The real drift is that the PLL is far *more permissive* than the server: it accepts `a b@c.d`, `user@@host.com`, `user@host.c`, and multiple `@` signs, all of which the server regex rejects. `HRMS_EMPLOYEE.xml:377` calls the server `PKG_VALIDATION.validate_email_format`, while other forms using the PLL get different behaviour. The misleading comment will drive a future "fix" in the wrong direction.
**Impact**: Users see a green field client-side, then a server rejection with a cryptic error; comment/code mismatch.
**Recommendation**: Delete `validate_email` from the PLL; call `PKG_VALIDATION.validate_email_format` everywhere.

---

### DRIFT-03: SSN Validation — PLL Rejects All-Zero Groups, Server Does Not (MEDIUM)

**Client** (`HRMS_VALIDATION_LIB.pll.sql:69-90`): 9 digits **and** area/group/serial not all zeros.
**Server** (`PKG_COMMON.pkb:277-280`): `REGEXP_LIKE(..., '^\d{9}$')` only.
**Issue**: `000-12-3456` is rejected in Forms but accepted by any server-side path (data import, API).
**Recommendation**: Move the SSA structural rules (no `000`/`666`/`9xx` area, no `00` group, no `0000` serial) into `PKG_COMMON.is_valid_ssn`.

---

### DRIFT-04: Salary-Range Validation Comment Contradicts Code (MEDIUM)

**File**: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:102-135`
```sql
-- BUG: Uses a hard-coded cache that's populated at form startup and never refreshed...
    -- Direct DB query (not cached - contradicts the comment above)
    SELECT MIN_SALARY, MAX_SALARY INTO v_min, v_max FROM JOB_GRADES WHERE GRADE_ID = p_grade_id;
```
**Issue**: `validate_salary_range` (PLL) duplicates `PKG_VALIDATION.validate_salary_for_grade` (`PKG_VALIDATION.pkb:17-48`) with different message text and different NULL handling (PLL returns NULL = valid for NULL inputs; server returns "Salary and grade are required"). Meanwhile `PKG_EMPLOYEE.hire_employee` treats an out-of-range salary as a soft warning only (`PKG_EMPLOYEE.pkb:230-238`).
**Impact**: Out-of-grade salaries can be persisted server-side even though Forms blocks them.
**Recommendation**: One implementation in `PKG_VALIDATION`; decide whether out-of-range is a hard error and apply it consistently.

---

### DRIFT-05: Phone Validation Character Sets Differ (MEDIUM)

**Client** (`HRMS_VALIDATION_LIB.pll.sql:47-63`): `TRANSLATE(p_phone, '0123456789()-. +x', '0123456789')` — strips only a fixed set, so `555/123/4567` fails.
**Server** (`PKG_COMMON.pkb:270-275`): `REGEXP_REPLACE(p_phone, '[^0-9]', '')` — strips everything.
**Recommendation**: Call the server function from Forms.

---

### DRIFT-06: Date-Range Validation Lacks Business-Day Awareness Client-Side (LOW)

**Files**: `PKG_VALIDATION.pkb:6-15` (`validate_date_range` = end ≥ start) vs `PKG_LEAVE.submit_leave_request` (business days, holidays, half-days).

**Issue**: Forms pre-validation passes zero-business-day requests (e.g. Saturday–Sunday) that the server rejects.
**Recommendation**: Expose `PKG_LEAVE.calculate_business_days` to the form and reject 0-day requests before submit.

---

## 5. Circular Dependencies

### CIRC-01: Declared PKG_EMPLOYEE ↔ PKG_PAYROLL Cycle (HIGH)

**Files**:
- `plsql/packages/PKG_EMPLOYEE.pks:8-9` — "Circular dependency with PKG_PAYROLL (salary validation)"
- `plsql/packages/PKG_PAYROLL.pks:6,9` — "Dependencies: PKG_EMPLOYEE ..." / "Circular dependency with PKG_EMPLOYEE (is_active check)"
- `plsql/packages/PKG_EMPLOYEE.pkb:273-282`, `:617`, `:778` — calls `PKG_PAYROLL.create_salary_record`

**Actual reference graph** (from body analysis):
```
PKG_SECURITY    -> PKG_AUDIT, PKG_EMPLOYEE
PKG_EMPLOYEE    -> PKG_AUDIT, PKG_COMMON, PKG_NOTIFICATION, PKG_PAYROLL
PKG_PAYROLL     -> PKG_AUDIT, PKG_COMMON            (no PKG_EMPLOYEE reference)
PKG_LEAVE       -> PKG_AUDIT, PKG_NOTIFICATION
PKG_PERFORMANCE -> PKG_AUDIT, PKG_NOTIFICATION
PKG_NOTIFICATION, PKG_INTEGRATION, PKG_REPORTING, PKG_VALIDATION -> PKG_COMMON
```
**Issue**: The cycle documented in both specs does **not** exist in the current bodies — `PKG_PAYROLL.pkb` never references `PKG_EMPLOYEE`. The spec headers are stale, and the "is_active check" they describe was either removed or never written (so payroll does not verify active status through the employee package at all). The one-way coupling is still problematic: `PKG_EMPLOYEE` (a master-data package) depends on `PKG_PAYROLL` (a transactional package), inverting the natural layering, and `PKG_SECURITY` depends on `PKG_EMPLOYEE` for session context.
**Impact**: Misleading documentation drives wrong deployment ordering; invalidation of `PKG_PAYROLL` cascades into `PKG_EMPLOYEE` and then `PKG_SECURITY` — a payroll deploy can break login.
**Recommendation**: Move `create_salary_record` into a low-level `PKG_COMPENSATION` (or `SALARY_RECORDS` DAO) that both packages call; move `set_session_context` into `PKG_SECURITY`; regenerate the dependency comments from `DBA_DEPENDENCIES`.

---

### CIRC-02: Trigger ↔ Package Mutual Dependencies (MEDIUM)

**Files**: `plsql/triggers/trg_audit.sql` (calls `PKG_AUDIT.log_action`), `plsql/packages/PKG_EMPLOYEE.pkb` (DML on `EMPLOYEES`, `SALARY_RECORDS` which fire those triggers and also call `PKG_AUDIT` directly)

**Issue**: `PKG_EMPLOYEE.hire_employee` calls `PKG_AUDIT.log_action` explicitly *and* fires `TRG_SALARY_AUDIT` via `create_salary_record` → two audit rows per event. `TRG_EMP_BEFORE_UPDATE` writes `EMPLOYEE_HISTORY` while `PKG_EMPLOYEE.log_history` also writes it → duplicate history once DATA-00 is fixed.
**Recommendation**: Audit in exactly one tier (triggers *or* packages).

---

## 6. Architectural Anti-Patterns

### ARCH-01: Autonomous Transactions for Audit/History (HIGH)

**Files**: `PKG_AUDIT.pkb:14`, `PKG_EMPLOYEE.pkb:155` (`log_history`), `PKG_NOTIFICATION.pkb:27` (`send_notification`), `PKG_COMMON.pkb:16,46` (`log_error`/`log_info`)

**Issue**: Audit, history and notification rows commit independently of the business transaction. If `hire_employee` rolls back after `log_history`, `EMPLOYEE_HISTORY` and `AUDIT_LOG` record a hire that never happened, and the manager is emailed about a non-existent employee (`send_notification` queues autonomously).
**Impact**: Audit log cannot be trusted for compliance; phantom notifications.
**Recommendation**: Keep audit rows in the caller's transaction (they roll back together); reserve `AUTONOMOUS_TRANSACTION` for `log_error` only.

---

### ARCH-02: Audit Failures Silently Swallowed (HIGH)

**File**: `plsql/packages/PKG_AUDIT.pkb:27-31`; `PKG_EMPLOYEE.pkb:171-179`
```sql
EXCEPTION
    WHEN OTHERS THEN
        -- Audit logging must never fail the calling transaction
        ROLLBACK;
```
**Issue**: Any audit failure (tablespace full, invalid JSON length, constraint) is discarded with no error log. `log_history` only prints to `DBMS_OUTPUT` when `g_debug_mode` is TRUE.
**Impact**: Compliance-relevant gaps with no alert. `purge_old_records` defaults to 365-day retention (`PKG_AUDIT.pkb:33-40`), shorter than typical 7-year payroll retention requirements.
**Recommendation**: At minimum write to `ERROR_LOG` via `PKG_COMMON.log_error`; raise for audit-mandatory tables; align retention with policy.

---

### ARCH-03: `COMMIT`/`ROLLBACK` Inside Business Packages (MEDIUM)

**Files**: `PKG_PAYROLL.pkb:181,292,325,346`; `PKG_LEAVE.pkb:544,548,602,622`; `PKG_NOTIFICATION.pkb:137,159`; `PKG_PERFORMANCE.pkb:315`; `PKG_AUDIT.pkb:43`

**Issue**: Packages decide transaction boundaries, so Forms `COMMIT_FORM`/`CLEAR_FORM` semantics and any orchestrating caller cannot roll back partial work. `calculate_payroll` commits status `CALCULATING` before doing any work (line 292).
**Recommendation**: Transaction control belongs to the outermost caller (Form or scheduler job wrapper); remove COMMITs from package bodies.

---

### ARCH-04: UTL_FILE Flat-File Integration with No Reliability Controls (MEDIUM)

**File**: `plsql/packages/PKG_INTEGRATION.pkb:20-145`; `PKG_INTEGRATION.pks:8-12`

**Issue**: GL journal and benefits feeds are pipe-delimited files written via `UTL_FILE` to directory objects; "No retry logic for failed file transfers". No checksum, sequence number, or acknowledgement.
**Impact**: Silent loss or duplicate posting when a file is partially written or picked up twice.
**Recommendation**: Oracle AQ / REST with idempotency keys; if files must remain, add trailer checksums and an `INTEGRATION_LOG` handshake.

---

### ARCH-05: Stub `import_time_attendance` (LOW)

**File**: `plsql/packages/PKG_INTEGRATION.pkb:153-190`
```sql
-- Parse CSV: emp_number,date,hours_regular,hours_overtime
-- TODO: Implement actual parsing and database update
v_imported := v_imported + 1;
```
**Issue**: Counts lines and logs success without writing anything.
**Impact**: Scheduler reports "N records imported" while no hours reach payroll.
**Recommendation**: Implement or disable the job; make the log message honest.

---

### ARCH-06: Stubbed Termination Side-Effects (LOW)

**File**: `plsql/packages/PKG_EMPLOYEE.pkb:736-739`
```sql
-- TODO: Integrate with benefits system to trigger COBRA
-- TODO: Revoke system access via PKG_SECURITY
-- TODO: Calculate final pay via PKG_PAYROLL.calculate_final_pay
```
**Issue**: `terminate_employee` does not close `USER_SESSIONS` or revoke access; a terminated employee's open session remains valid until the 30-minute timeout, and there is no `calculate_final_pay`.
**Recommendation**: Implement access revocation immediately (security); schedule the others.

---

### ARCH-07: Hard-Coded Fiscal Year and Tax Brackets (LOW)

**Files**: `PKG_COMMON.pkb:167-179` (`get_fiscal_year`: month ≥ 10 → FY+1); `PKG_PAYROLL.pkb:602-690` (`calculate_federal_tax`: literal 2024 brackets); `PKG_REPORTING.pks:10`

**Issue**: `TAX_BRACKETS` table exists (`schema/tables/02_payroll_tables.sql:157-172`) but `calculate_federal_tax` ignores it ("TODO: Read from TAX_BRACKETS table"). Fiscal year start is a literal.
**Impact**: Every tax year requires a code release; `HEAD_OF_HOUSEHOLD` filers fall through to the single-filer bracket logic.
**Recommendation**: Drive both from data (`TAX_BRACKETS` with effective dates; `SYSTEM_PARAMETERS.FISCAL_YEAR_START_MONTH`).

---

### ARCH-08: Business Rules Duplicated Across Four Tiers (LOW)

**Files**: `plsql/triggers/trg_employees.sql:1-6` (self-described "common anti-pattern"), `HRMS_VALIDATION_LIB.pll.sql:8-11`, `PKG_VALIDATION`, Forms `WHEN-VALIDATE-ITEM` triggers

**Issue**: See DRIFT-01…06 for concrete divergences. Each rule exists in 2–4 places.
**Recommendation**: `PKG_VALIDATION` as the single source; PLL functions become thin wrappers; DB triggers limited to audit-column defaults.

---

## 7. Data Integrity Risks

### DATA-00: `TRG_EMP_BEFORE_UPDATE` Column List Does Not Match `EMPLOYEE_HISTORY` DDL (CRITICAL)

**Files**: `plsql/triggers/trg_employees.sql:76-110` vs `schema/tables/01_core_tables.sql:152-177`

| Trigger column (INSERT list) | Exists in DDL? | Actual DDL column |
|------------------------------|----------------|-------------------|
| `HISTORY_ID` | No | `HIST_ID` |
| `EMP_ID` | Yes | `EMP_ID` |
| `CHANGE_TYPE` | Yes | `CHANGE_TYPE` |
| `CHANGE_DATE` | No | `EFFECTIVE_DATE` |
| `OLD_VALUE` / `NEW_VALUE` | No | `OLD_DEPT_ID/NEW_DEPT_ID`, `OLD_JOB_ID/NEW_JOB_ID`, … |
| `CHANGED_BY` | No | `CREATED_BY` |
| `CHANGE_REASON` | No | `REASON_CODE` / `COMMENTS` |

```sql
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'STATUS_CHANGE', SYSDATE, ...)
```
**Issue**: Six of eight columns do not exist. The trigger fails compilation with PLS-00904/ORA-00904 and is created `INVALID`. Oracle then rejects **every** `UPDATE HRMS.EMPLOYEES` with `ORA-04098: trigger 'HRMS.TRG_EMP_BEFORE_UPDATE' is invalid and failed re-validation` — including the audit-column defaults at lines 66-67 that every other code path relies on. `PKG_EMPLOYEE.log_history` (`PKG_EMPLOYEE.pkb:157-169`) uses the correct column names, confirming the trigger is the outlier.
**Impact**: Employee updates (transfer, promotion, termination, salary change, status change) all fail at the database. In environments where the trigger happens to be disabled, no status/department history is captured by this path.
**Recommendation**: Rewrite the INSERTs using `HIST_ID, EMP_ID, CHANGE_TYPE, EFFECTIVE_DATE, OLD_DEPT_ID, NEW_DEPT_ID, OLD_JOB_ID, NEW_JOB_ID, CREATED_BY, CREATED_DATE, COMMENTS`; or delete the history logic from the trigger and rely on `PKG_EMPLOYEE.log_history` (see CIRC-02). Add a CI step that compiles all objects against a scratch schema and fails on `INVALID` status.

---

### DATA-01: Trigger Uses `CHANGE_TYPE` Values Rejected by `CHK_CHANGE_TYPE` (CRITICAL)

**Files**: `plsql/triggers/trg_employees.sql:94,106` vs `schema/tables/01_core_tables.sql:173-176`
```sql
CONSTRAINT CHK_CHANGE_TYPE CHECK (CHANGE_TYPE IN (
    'HIRE', 'TRANSFER', 'PROMOTION', 'DEMOTION', 'SALARY_CHANGE',
    'TERMINATION', 'REHIRE', 'LEAVE_START', 'LEAVE_END', 'STATUS_CHANGE'))
```
**Issue**: The trigger inserts `'DEPARTMENT_CHANGE'` and `'JOB_CHANGE'`, neither of which is in the CHECK list. Even after fixing DATA-00 column names, department and job changes would raise ORA-02290.
**Impact**: Second latent failure hidden behind the first.
**Recommendation**: Use `'TRANSFER'` and `'PROMOTION'/'DEMOTION'` (or extend the constraint) and add a test that exercises every `CHANGE_TYPE` literal in code against the constraint.

---

### DATA-02: `PAYROLL_DETAILS` Error Rows Violate FK and Type Domain (CRITICAL)

**Files**: `plsql/packages/PKG_PAYROLL.pkb:311-319` vs `schema/tables/02_payroll_tables.sql:140-153`

**Issue**: See SEC-05. `ELEMENT_ID = 0` violates `FK_PD_ELEMENT`; `ELEMENT_TYPE = 'ERROR'` is outside the domain used by `PAY_ELEMENTS.CHK_ELEM_TYPE` (`02_payroll_tables.sql:57`) and by every aggregate in the package, which filters `STATUS != 'ERROR'` rather than `ELEMENT_TYPE`.
**Recommendation**: Separate error table (see SEC-05).

---

### DATA-03: `VW_LEAVE_SUMMARY.AVAILABLE` Contradicts the `LEAVE_BALANCES.AVAILABLE` Virtual Column (CRITICAL)

**Files**: `schema/views/hrms_views.sql:96` vs `schema/tables/03_leave_tables.sql:47`
```sql
-- table (virtual column)
AVAILABLE NUMBER(6,2) GENERATED ALWAYS AS (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL
-- view
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,
```
**Issue**: The view omits `- PENDING`. `VW_LEAVE_SUMMARY` is the manager-facing balance; it over-reports availability by the sum of pending requests. The table's `COMMENT` and the seed data both describe `AVAILABLE` as net of pending.
**Impact**: Approvals granted against balance that is already committed; negative balances after approval.
**Recommendation**: `SELECT lb.AVAILABLE` directly from the virtual column instead of re-deriving it.

---

### DATA-04: Cross-Year Leave Requests Debit the Wrong Year (HIGH)

**File**: `plsql/packages/PKG_LEAVE.pkb:176-182`
```sql
UPDATE LEAVE_BALANCES SET PENDING = PENDING + v_total_days
WHERE EMP_ID = p_emp_id AND LEAVE_TYPE_ID = p_leave_type_id
AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```
**Issue**: A Dec 29 → Jan 3 request charges all days to the start year. If no balance row exists for that year, the UPDATE affects 0 rows and no error is raised — the request is created with nothing debited.
**Recommendation**: Split by calendar year; check `SQL%ROWCOUNT` and raise when no balance row exists.

---

### DATA-05: Half-Day Requests Not Considered in Overlap Check (HIGH)

**File**: `plsql/packages/PKG_LEAVE.pkb:45-62`; `PKG_LEAVE.pks:9`

**Issue**: `check_leave_overlap` compares date ranges only; `HALF_DAY_FLAG`/`HALF_DAY_PERIOD` are ignored. AM + PM half-days on the same date are rejected as overlapping, while two AM half-days would also be rejected but a full day plus an AM half-day is (correctly) rejected — the check is coarser than the data model.
**Recommendation**: Include `HALF_DAY_PERIOD` in the overlap predicate.

---

### DATA-06: `expire_carryover` Is Not Idempotent (HIGH)

**File**: `plsql/packages/PKG_LEAVE.pkb:606-623`
```sql
-- BUG: If run twice on same day, can double-subtract
UPDATE LEAVE_BALANCES SET ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV, CARRYOVER_FROM_PREV = 0 ...
WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE) AND CARRYOVER_FROM_PREV > 0;
```
**Issue**: As written, the second run finds `CARRYOVER_FROM_PREV = 0` and does nothing — the update itself is idempotent. The real hazard is `process_carryover` (lines ~560-603), which recomputes and re-adds carryover into the *next* year without an "already processed" marker; running it twice doubles `CARRYOVER_FROM_PREV`, which `expire_carryover` then correctly removes twice. The spec comment points at the wrong procedure.
**Recommendation**: Add `CARRYOVER_PROCESSED_DATE` to `LEAVE_BALANCES` and guard `process_carryover`; correct the comment.

---

### DATA-07: Observed Holidays Not Recognised (HIGH)

**File**: `plsql/packages/PKG_LEAVE.pkb:9-11,25-29`; `PKG_VALIDATION.pkb:90-94`

**Issue**: Holiday match is exact-date. A holiday on Saturday/Sunday observed on Friday/Monday is treated as a working day, inflating leave consumption by one day per such holiday.
**Recommendation**: Add `OBSERVED_DATE` to `HOLIDAYS` and match on it.

---

### DATA-08: Soft-Delete Semantics Inconsistent (LOW)

**Files**: `plsql/triggers/trg_employees.sql:114-130` (`TRG_EMP_INSTEAD_OF_DELETE` — actually a `BEFORE DELETE` that raises -20504), `forms/xml-exports/HRMS_EMPLOYEE.xml` (Forms `DELETE_RECORD` → error → workaround), `PKG_EMPLOYEE.terminate_employee` (sets `EMPLOYMENT_STATUS='TERMINATED'` but leaves `ACTIVE_FLAG='Y'`), `PKG_SECURITY.authenticate:45` (filters on `EMPLOYMENT_STATUS`), `TRG_EMP_BEFORE_INSERT:48` (email uniqueness filters on `ACTIVE_FLAG`)

**Issue**: Two soft-delete indicators (`ACTIVE_FLAG` and `EMPLOYMENT_STATUS`) are used interchangeably by different code paths. A terminated employee with `ACTIVE_FLAG='Y'` still blocks re-use of their email address; an `ACTIVE_FLAG='N'` employee with `EMPLOYMENT_STATUS='ACTIVE'` can still log in (SEC-00 aside). The trigger is named `INSTEAD_OF_DELETE` but is a `BEFORE DELETE` on a table, and its comment says it "converts DELETE into an UPDATE" while it actually just raises.
**Recommendation**: Define one authoritative liveness predicate (`fn_is_active_employee`) and use it everywhere; rename/fix the trigger; drop `DeleteAllowed` in the Form instead of relying on a runtime error.

---

## 8. Consolidated Findings Table

| ID | Category | Severity | File:Line | Summary | Fix |
|----|----------|----------|-----------|---------|-----|
| SEC-00 | Security | CRITICAL | PKG_SECURITY.pkb:30-80 | Password never verified | Implement credential check |
| SEC-01 | Security | CRITICAL | PKG_SECURITY.pkb:18-22 | Unsalted MD5 | Salted PBKDF2/bcrypt |
| SEC-02 | Security | CRITICAL | PKG_SECURITY.pkb:7 | Hard-coded AES key, no IV | Wallet/TDE, random IV |
| SEC-03 | Security | CRITICAL | PKG_EMPLOYEE.pkb:466-484 | SQL injection in search_employees | Bind variables |
| SEC-04 | Security | CRITICAL | HRMS_LOGIN.xml:75-79 | Cleartext password over SQL*Net | Net encryption / SSO |
| SEC-05 | Security | CRITICAL | PKG_PAYROLL.pkb:311-319 | Error-handler INSERT violates FK, aborts run | Separate error table |
| SEC-06 | Security | HIGH | PKG_SECURITY.pkb:26-80 | No lockout | Failed-attempt tracking |
| SEC-07 | Security | HIGH | PKG_SECURITY.pkb:47-50 | Timing-based enumeration | Constant-time path |
| SEC-08 | Security | HIGH | PKG_SECURITY.pkb:51-56 | Duplicate email → MIN(EMP_ID) | Unique FBI, hard fail |
| SEC-09 | Security | HIGH | HRMS_LOGIN.xml:10-13 | No MFA/SSO | SSO integration |
| SEC-10 | Security | MEDIUM | PKG_NOTIFICATION.pkb:6-10 | Hard-coded SMTP, port 25 | SYSTEM_PARAMETERS + STARTTLS |
| SEC-11 | Security | MEDIUM | PKG_NOTIFICATION.pkb:96-105 | SMTP header injection | Strip CRLF |
| SEC-12 | Security | MEDIUM | PKG_INTEGRATION.pks:12 | Cleartext FTP creds | Wallet, SFTP |
| SEC-13 | Security | MEDIUM | PKG_COMMON.pkb:25; trg_audit.sql:20-29 | Hand-built JSON | JSON_OBJECT |
| RACE-01 | Race | HIGH | PKG_EMPLOYEE.pkb:43-54 | MAX()+1 emp number, wrong fallback seq | SEQ_EMP_NUMBER |
| RACE-02 | Race | MEDIUM | PKG_PAYROLL.pkb:241-260 | Period status without lock | FOR UPDATE |
| RACE-03 | Race | MEDIUM | PKG_LEAVE.pkb:67-182 | Balance check-then-update | FOR UPDATE |
| PERF-01 | Performance | MEDIUM | PKG_COMMON.pkb:139-144 | Day loop | Closed form |
| PERF-02 | Performance | MEDIUM | PKG_COMMON.pkb:158-163 | Day loop | Closed form |
| PERF-03 | Performance | MEDIUM | PKG_LEAVE.pkb:21-39 | Day loop + query per day | Set-based |
| PERF-04 | Performance | MEDIUM | hrms_views.sql:47-57 | CONNECT BY, no NOCYCLE | Recursive CTE |
| PERF-05 | Performance | MEDIUM | PKG_PAYROLL.pkb:296-325 | Row-by-row payroll + COMMITs | Bulk, single txn |
| PERF-06 | Performance | MEDIUM | PKG_NOTIFICATION.pkb:88-107 | SMTP connect per message; retry needs separate job | Reuse connection; retry |
| PERF-07 | Performance | LOW | hrms_sequences.sql:9-44 | NOCACHE sequences | CACHE 20+ |
| PERF-08 | Performance | LOW | PKG_REPORTING.pks:9 | Stale reporting tables | MVs |
| DRIFT-01 | Drift | HIGH | 4 files (see §4) | Hire-date limit: none/90/180/≤today | Single rule |
| DRIFT-02 | Drift | HIGH | HRMS_VALIDATION_LIB:21-41 vs PKG_COMMON:267 | Email rule permissive client, strict server; wrong comment | Use server fn |
| DRIFT-03 | Drift | MEDIUM | HRMS_VALIDATION_LIB:69-90 vs PKG_COMMON:279 | SSN zero-group rule client-only | Move to server |
| DRIFT-04 | Drift | MEDIUM | HRMS_VALIDATION_LIB:101-135 | Salary range duplicated; soft-warn server side | Single rule |
| DRIFT-05 | Drift | MEDIUM | HRMS_VALIDATION_LIB:47-63 vs PKG_COMMON:273 | Phone strip sets differ | Use server fn |
| DRIFT-06 | Drift | LOW | PKG_VALIDATION.pkb:6-15 | No business-day awareness client-side | Expose calc |
| CIRC-01 | Circular | HIGH | PKG_EMPLOYEE.pks:9; PKG_PAYROLL.pks:6,9 | Declared cycle is stale; one-way inverted dependency remains | Extract PKG_COMPENSATION |
| CIRC-02 | Circular | MEDIUM | trg_audit.sql; PKG_EMPLOYEE.pkb | Trigger + package double-audit | Audit in one tier |
| ARCH-01 | Architecture | HIGH | PKG_AUDIT.pkb:14 et al. | Autonomous audit/history/notify | In-transaction audit |
| ARCH-02 | Architecture | HIGH | PKG_AUDIT.pkb:27-31 | Audit errors swallowed; 365-day purge | Log/raise; retention |
| ARCH-03 | Architecture | MEDIUM | PKG_PAYROLL.pkb:292 et al. | COMMIT inside packages | Caller-owned txn |
| ARCH-04 | Architecture | MEDIUM | PKG_INTEGRATION.pkb:20-145 | UTL_FILE feeds, no retry/checksum | AQ/REST |
| ARCH-05 | Architecture | LOW | PKG_INTEGRATION.pkb:170 | Stub import reports success | Implement/disable |
| ARCH-06 | Architecture | LOW | PKG_EMPLOYEE.pkb:736-739 | Termination doesn't revoke access | Implement |
| ARCH-07 | Architecture | LOW | PKG_PAYROLL.pkb:643-690; PKG_COMMON.pkb:174 | Hard-coded tax brackets, fiscal year | Data-driven |
| ARCH-08 | Architecture | LOW | trg_employees.sql:1-6 | Rules in 4 tiers | PKG_VALIDATION SoT |
| DATA-00 | Data | CRITICAL | trg_employees.sql:78-109 vs 01_core_tables.sql:152-177 | 6 nonexistent columns → trigger INVALID → all EMPLOYEES updates fail | Fix column list |
| DATA-01 | Data | CRITICAL | trg_employees.sql:94,106 vs 01_core_tables.sql:173-176 | CHANGE_TYPE literals violate CHECK | Use allowed values |
| DATA-02 | Data | CRITICAL | PKG_PAYROLL.pkb:311-319 | ELEMENT_ID=0 FK violation | Error table |
| DATA-03 | Data | CRITICAL | hrms_views.sql:96 vs 03_leave_tables.sql:47 | View AVAILABLE omits PENDING | Select virtual column |
| DATA-04 | Data | HIGH | PKG_LEAVE.pkb:176-182 | Cross-year balance; silent 0-row update | Split by year |
| DATA-05 | Data | HIGH | PKG_LEAVE.pkb:45-62 | Half-day overlap | Include period |
| DATA-06 | Data | HIGH | PKG_LEAVE.pkb:560-623 | process_carryover not idempotent (comment blames wrong proc) | Processed marker |
| DATA-07 | Data | HIGH | PKG_LEAVE.pkb:25-29 | Observed holidays | OBSERVED_DATE |
| DATA-08 | Data | LOW | trg_employees.sql:120-129; PKG_EMPLOYEE.pkb | ACTIVE_FLAG vs EMPLOYMENT_STATUS | One predicate |

---

## 9. Migration Roadmap

Effort is expressed in engineering days for a small team familiar with the estate. Items are ordered so that each phase leaves the system in a strictly safer state.

### Phase 1 — Critical Security & Blocking Defects (release blocker; ~2 weeks)

| # | Item | Effort | Risk if deferred |
|---|------|--------|------------------|
| 1 | SEC-00 Implement real credential verification (`USER_CREDENTIALS`, salted hash, constant-time compare) | 3 d | Anyone can log in as anyone |
| 2 | DATA-00 / DATA-01 Fix `TRG_EMP_BEFORE_UPDATE` column list and `CHANGE_TYPE` values; add compile-all CI gate | 1 d | All employee updates fail |
| 3 | SEC-03 Rewrite `search_employees` with binds | 0.5 d | Data exfiltration |
| 4 | SEC-02 Move AES key to Wallet/TDE, add IV, rotate and re-encrypt SSNs | 3 d | PII exposure |
| 5 | SEC-01 Replace MD5 (bundled with #1) | — | Password compromise |
| 6 | SEC-05 / DATA-02 Payroll error logging to a dedicated table | 1 d | Payroll runs abort |
| 7 | SEC-04 Enforce Oracle Net encryption | 1 d | Credential sniffing |
| 8 | SEC-06 / SEC-07 / SEC-08 Lockout, constant-time path, unique active email | 2 d | Brute force, enumeration |
| 9 | ARCH-06 Revoke sessions on termination | 0.5 d | Ex-employee access |

### Phase 2 — Data Integrity & Concurrency (~3 weeks)

| # | Item | Effort |
|---|------|--------|
| 1 | DATA-03 `VW_LEAVE_SUMMARY` uses virtual `AVAILABLE` | 0.5 d |
| 2 | RACE-01 `SEQ_EMP_NUMBER` only | 0.5 d |
| 3 | DATA-04 Cross-year leave split + `SQL%ROWCOUNT` guard | 1 d |
| 4 | RACE-02 / RACE-03 `FOR UPDATE` on period and balance checks | 1 d |
| 5 | DATA-06 Idempotent `process_carryover` | 1 d |
| 6 | DATA-05 / DATA-07 Half-day overlap; observed holidays | 2 d |
| 7 | ARCH-01 / ARCH-02 In-transaction audit; surface audit failures; retention policy | 3 d |
| 8 | CIRC-02 Audit in one tier (remove duplicate trigger/package logging) | 1 d |
| 9 | DRIFT-01…05 Consolidate validation into `PKG_VALIDATION`; PLL wrappers | 4 d |
| 10 | DATA-08 Single liveness predicate | 1 d |

### Phase 3 — Performance & Structure (~4–6 weeks)

| # | Item | Effort |
|---|------|--------|
| 1 | PERF-05 / ARCH-03 Set-based payroll; caller-owned transactions | 5 d |
| 2 | PERF-01/02/03 Closed-form business-day math + calendar table | 2 d |
| 3 | PERF-06 SMTP connection reuse; retry `FAILED` | 1 d |
| 4 | PERF-04 Recursive CTE / closure table for org chart | 2 d |
| 5 | CIRC-01 Extract `PKG_COMPENSATION`; move `set_session_context`; regenerate dependency docs from `DBA_DEPENDENCIES` | 3 d |
| 6 | ARCH-07 `TAX_BRACKETS` and fiscal-year parameters data-driven | 2 d |
| 7 | SEC-10/11/12 Externalise SMTP/FTP config; STARTTLS; header sanitising; SFTP | 3 d |
| 8 | PERF-07 / PERF-08 Sequence caching; materialised reporting | 1 d |
| 9 | SEC-13 `JSON_OBJECT` for audit payloads | 1 d |

### Phase 4 — Modernisation (~3–6 months, parallelisable)

| # | Item | Notes |
|---|------|-------|
| 1 | SEC-09 Enterprise SSO/MFA | Removes password handling from the estate entirely |
| 2 | Replace Oracle Forms UI | APEX for fastest path; or REST (ORDS) + web SPA |
| 3 | ARCH-04 Replace UTL_FILE feeds with AQ / REST with idempotency keys | Unblocks real-time GL and benefits sync |
| 4 | ARCH-05 Implement or retire time & attendance import | Depends on vendor format |
| 5 | Automated testing (utPLSQL) covering every finding in this report as a regression test | Compile-all + constraint-literal tests in CI first |
| 6 | Token-based session management replacing `USER_SESSIONS` polling | Pairs with #1 |

---

## Appendix A — Verification Notes

- **Trigger vs DDL cross-reference**: every INSERT column list in `plsql/triggers/*.sql` and `plsql/packages/*.pkb` was checked against `schema/tables/*.sql`. Only `TRG_EMP_BEFORE_UPDATE` (DATA-00/01) and the `PAYROLL_DETAILS` error INSERT (DATA-02) mismatch. `TRG_SALARY_AUDIT`, `TRG_LEAVE_REQUEST_AUDIT`, `TRG_DEPARTMENT_AUDIT` reference only existing columns.
- **View vs table semantics**: `VW_LEAVE_SUMMARY` (DATA-03) is the only view whose derived column contradicts a table-level definition. `VW_ORG_HIERARCHY`, `VW_EMPLOYEE_COMPENSATION`, `VW_PAYROLL_LATEST` match their base tables.
- **Comment/code mismatches found**: DRIFT-02 (PLL email comment claims the opposite of the code), DRIFT-04 (cache comment vs direct query), DATA-06 (spec blames `expire_carryover`; hazard is in `process_carryover`), CIRC-01 (declared cycle does not exist in bodies), DATA-08 (trigger named/described as INSTEAD OF / convert-to-update but is BEFORE DELETE / raise).
- `DATA_DICTIONARY.md` does not exist in the repository; column-description cross-referencing used `COMMENT ON` statements in `schema/tables/*.sql` instead.
- Dynamic SQL inventory: `OPEN ... FOR <string>` occurs once (`PKG_EMPLOYEE.search_employees`); no `EXECUTE IMMEDIATE` in the estate.
