# Technical Debt Report — Oracle Forms / PL/SQL HRMS Estate

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Analysis date:** 2026-09-28
**Baseline commit:** `main` @ `origin/main` (clean checkout)
**Scope:** `plsql/packages/*.pks|*.pkb`, `plsql/triggers/*.sql`, `schema/tables|views|sequences/*.sql`, `data/seed/*.sql`, `forms/libraries/*.pll.sql`, `forms/xml-exports/*.xml`
**Method:** Manual source review plus scripted cross-reference of every `INSERT INTO <table> (<columns>)` / `UPDATE <table> SET` statement against the `CREATE TABLE` DDL, and of literal values against `CHECK` constraints. Every line number below was verified against the current tree.

> `DATA_DICTIONARY.md` does not exist in this repository, so the column-description cross-reference step was not applicable. Column semantics were cross-referenced against `COMMENT ON` statements, package/view header comments and `CHECK` constraints instead.

---

## Executive Summary

The HRMS estate has **69 technical-debt findings**. Seven are **CRITICAL** and block a production-safe release:

1. **Authentication never checks the password** (`PKG_SECURITY.authenticate`). Anyone who knows an active employee's email address can log in.
2. **The AES-256 key that protects every SSN is hard-coded** in the `PKG_SECURITY` body.
3. **SQL injection** in `PKG_EMPLOYEE.search_employees`, which builds dynamic SQL by concatenating parameters.
4. **`TRG_EMP_BEFORE_UPDATE` writes to `EMPLOYEE_HISTORY` columns that do not exist** (`HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON`). The trigger compiles invalid, so **every `UPDATE` on `EMPLOYEES` fails with ORA-04098**. That stops termination, transfer, promotion, rehire and Forms edits.
5. **The same trigger emits `CHANGE_TYPE` values** (`DEPARTMENT_CHANGE`, `JOB_CHANGE`) **that `CHK_CHANGE_TYPE` rejects**.
6. **The reference seed script does not match the DDL** (`LOCATIONS.PHONE`, `JOB_GRADES.GRADE_LEVEL`, `SYSTEM_PARAMETERS.DESCRIPTION`, and the NOT NULL `JOB_GRADES.GRADE_CODE` is never supplied). Locations, grades and system parameters never load, and every dependent seed row then fails its foreign key.
7. **The payroll error handler inserts `ELEMENT_ID = 0`**, which violates `FK_PD_ELEMENT`. The first per-employee error aborts the whole run after some batches have already been committed.

Beyond the blockers, the main themes are these:

- **Race conditions:** check-then-act logic with no row locks, and `MAX()+1` identifier generation.
- **Silent data loss:** autonomous-transaction audit writes and a catch-all `WHEN OTHERS THEN ROLLBACK`. Together these hide constraint violations, for example the leave-status audit rows that can never be written.
- **Inconsistent financial totals:** `PAYROLL_RUNS.TOTAL_NET` ignores `BENEFIT` deductions.
- **Performance:** day-by-day loops, row-by-row payroll, and **no secondary indexes anywhere in the schema**.
- **Validation drift:** the same rules are implemented differently in four tiers (Forms triggers, PLL, packages, DB triggers).

### Severity counts

| Severity | Count |
|----------|------:|
| CRITICAL | 7 |
| HIGH | 22 |
| MEDIUM | 29 |
| LOW | 11 |
| **Total** | **69** |

### Category breakdown

| Category | ID prefix | CRITICAL | HIGH | MEDIUM | LOW | Total |
|----------|-----------|---------:|-----:|-------:|----:|------:|
| Security vulnerabilities | SEC | 3 | 5 | 5 | 2 | 15 |
| Race conditions | RACE | 0 | 4 | 2 | 0 | 6 |
| Performance | PERF | 0 | 3 | 4 | 2 | 9 |
| Validation drift | VAL | 0 | 1 | 3 | 3 | 7 |
| Circular / layering dependencies | DEP | 0 | 0 | 2 | 1 | 3 |
| Architectural anti-patterns | ARCH | 0 | 4 | 6 | 2 | 12 |
| Data integrity | DATA | 4 | 5 | 7 | 1 | 17 |
| **Total** | | **7** | **22** | **29** | **11** | **69** |

### Changes since the previous report (2026-09-21)

- **New findings in this pass:**
  - DATA-03: seed script vs DDL mismatch.
  - DATA-05: `rehire_employee` is always rejected by `TRG_EMP_BEFORE_UPDATE`.
  - DATA-06: the leave audit trigger violates `CHK_AUDIT_ACTION` and the `VARCHAR2(10)` column length.
  - DATA-08: `PAYROLL_RUNS` totals omit `BENEFIT` deductions.
  - DATA-14: `USER_SESSIONS.USERNAME` and `AUDIT_LOG.CHANGED_BY` are shorter than `EMPLOYEES.EMAIL`.
  - RACE-04: `calculate_payroll` can re-run on an approved run.
  - RACE-05: `reverse_payroll` has no state check.
  - RACE-06: the notification queue is not claimed with a lock.
  - PERF-07: no secondary or function-based indexes exist.
  - SEC-06 extended: the login form resolves the employee with `ROWNUM = 1`, while `authenticate` uses `MIN(EMP_ID)`.
- **Re-classified:** the declared `PKG_EMPLOYEE` ↔ `PKG_PAYROLL` cycle is **not present in the current package bodies**. Only `PKG_EMPLOYEE → PKG_PAYROLL` exists. It is reported as a layering violation (DEP-01) rather than a live cycle.
- **Corrected stale source comments:**
  - The PLL email comment says subdomains are rejected. They are accepted (VAL-01).
  - The "INSTEAD OF DELETE" trigger is really a `BEFORE DELETE` that raises an error (DATA-11).
  - The `expire_carryover` double-run hazard comes from re-running `process_carryover` after expiry. `expire_carryover` on its own is guarded by `CARRYOVER_FROM_PREV > 0` (DATA-13).

---

## 1. Security Vulnerabilities

### SEC-01: Authentication Never Verifies the Password (CRITICAL)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:30-80`; caller `forms/xml-exports/HRMS_LOGIN.xml:69-79`
- **Code:**
  ```sql
  FUNCTION authenticate(p_username IN VARCHAR2, p_password IN VARCHAR2, ...) RETURN NUMBER IS
      v_stored_hash VARCHAR2(200);   -- never assigned
      v_input_hash  VARCHAR2(200);   -- never assigned
  BEGIN
      SELECT EMP_ID INTO v_emp_id FROM EMPLOYEES
      WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
      -- NOTE: In the real system, passwords are stored in a separate
      -- USER_CREDENTIALS table. ...
      SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
      INSERT INTO USER_SESSIONS (...) VALUES (v_session_id, v_emp_id, p_username, ...);
  ```
- **Issue:** `p_password` is never hashed or compared, and `hash_password` is never called. A session is issued for any active employee email. The login form only checks that the password field is non-null (`HRMS_LOGIN.xml:69`), and it sends the password to the database in cleartext over the Forms/SQL*Net channel.
- **Impact:** Complete authentication bypass. Anyone who knows or guesses a colleague's email address gets full HRMS access as that user, including payroll, SSNs and bank accounts. Every audit trail becomes unreliable because the session identity cannot be trusted.
- **Recommendation:** Add a `USER_CREDENTIALS` table (salted adaptive hash, failed-attempt counter, lockout timestamp, password history). Verify the password with a constant-time comparison before any session is created. Better still, move to SSO or LDAP (Oracle Access Manager / OID) and remove local passwords. Enforce SQL*Net native encryption or TLS (`SQLNET.ENCRYPTION_SERVER=REQUIRED`).

### SEC-02: Hard-Coded AES-256 Encryption Key (CRITICAL)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:7` (used at `:184-188`, `:197-201`)
- **Code:**
  ```sql
  c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('<REDACTED — literal key in source>');
  ```
- **Issue:** The symmetric key for SSN encryption is a string literal in the package body. It is in version control, in `ALL_SOURCE` / `DBA_SOURCE`, in every export and backup, and visible to anyone with `SELECT_CATALOG_ROLE`. The source also contains no rotation mechanism.
- **Impact:** Anyone who can read the code or the data dictionary can decrypt every `EMPLOYEES.SSN_ENCRYPTED` value. This is a reportable PII breach under GLBA and state privacy laws, and the key cannot be rotated without re-encrypting all data by hand.
- **Recommendation:** Treat the key as compromised and rotate it immediately. Move SSN protection to TDE column encryption or to a key kept in an Oracle Wallet / OCI Vault / HSM and fetched at runtime. Wrap or obfuscate the package source as defence-in-depth, and purge the literal from Git history.

### SEC-03: SQL Injection in `PKG_EMPLOYEE.search_employees` (CRITICAL)

- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:445-498`
- **Code:**
  ```sql
  -- VULNERABILITY: String concatenation instead of bind variable
  v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
  ...
  v_sql := v_sql || 'AND e.EMPLOYMENT_STATUS = ''' || p_status || ''' ';
  v_sql := v_sql || 'AND e.LOCATION_CODE = ''' || p_location_code || ''' ';
  ...
  OPEN p_cursor FOR v_sql;
  ```
- **Issue:** Five parameters are concatenated into dynamic SQL (`:467`, `:471`, `:475`, `:479`, `:483`, plus the date filters at `:487-493`). The header comment (`:442-443`) says Forms LOVs validate the input, but the procedure is public in the package spec and anything with `EXECUTE` can call it directly.
- **Impact:** An attacker can run arbitrary `UNION SELECT` statements under the HRMS schema owner's privileges and read salaries, bank accounts and encrypted SSNs. Combined with SEC-02, that means plaintext SSNs.
- **Recommendation:** Rewrite with bind variables (`OPEN p_cursor FOR v_sql USING ...`, with the `(:x IS NULL OR col = :x)` pattern), or build it with `DBMS_SQL` and binds. Wrap `LIKE` values in `DBMS_ASSERT.ENQUOTE_LITERAL` only if binds are impossible. Add a code-scan rule that fails CI on `OPEN ... FOR <varchar>` without `USING`.

### SEC-04: Unsalted MD5 Password Hashing (HIGH)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:14-24`; documented at `PKG_SECURITY.pks:9`
- **Code:**
  ```sql
  RETURN RAWTOHEX(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(p_password), DBMS_CRYPTO.HASH_MD5));
  ```
- **Issue:** MD5 is cryptographically broken and fast to brute-force, and there is no salt or work factor. The function is public in the spec, so any caller can use it as a hashing oracle.
- **Impact:** Once a credential store exists (SEC-01), a leaked hash table falls to rainbow tables in seconds. Identical passwords produce identical hashes.
- **Recommendation:** Use PBKDF2 (`DBMS_CRYPTO.HASH_SH512` with ≥ 310k iterations and a per-user random salt from `DBMS_CRYPTO.RANDOMBYTES`), or delegate to the IdP. Remove `hash_password` from the public spec. Rehash on next successful login.

### SEC-05: No Account Lockout or Brute-Force Throttling (HIGH)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:28`, `:46-50`; `PKG_SECURITY.pks:11`; `forms/xml-exports/HRMS_LOGIN.xml:69-79`
- **Code:**
  ```sql
  -- VULNERABILITY: No brute-force protection (no lockout after N failures)
  ...
  WHEN NO_DATA_FOUND THEN
      RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
  ```
- **Issue:** Failed attempts are neither counted nor logged. `SYSTEM_PARAMETERS` has no lockout threshold, and the form allows unlimited retries.
- **Impact:** Unlimited online password guessing once SEC-01 is fixed, and no detection of credential-stuffing campaigns.
- **Recommendation:** Track `FAILED_ATTEMPTS` / `LOCKED_UNTIL` per credential. Lock after N failures (configurable in `SYSTEM_PARAMETERS`), add exponential back-off, and audit every failure together with `CLIENT_HOST`.

### SEC-06: Ambiguous Identity Resolution for Duplicate Emails (HIGH)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:51-56`; `forms/xml-exports/HRMS_LOGIN.xml:86-90`
- **Code:**
  ```sql
  -- PKG_SECURITY.authenticate
  WHEN TOO_MANY_ROWS THEN
      SELECT MIN(EMP_ID) INTO v_emp_id FROM EMPLOYEES
      WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
  -- HRMS_LOGIN WHEN-BUTTON-PRESSED
  SELECT EMP_ID INTO :GLOBAL.current_emp_id FROM EMPLOYEES
  WHERE UPPER(EMAIL) = UPPER(:LOGIN.USERNAME) AND EMPLOYMENT_STATUS = 'ACTIVE' AND ROWNUM = 1;
  ```
- **Issue:** Email is the login identifier, but it is not unique (DATA-12). The server picks `MIN(EMP_ID)` for the session, while the form picks an arbitrary row (`ROWNUM = 1`) for `:GLOBAL.current_emp_id`. The two can disagree.
- **Impact:** A user can be logged in as one employee (the session and audit identity) while the Forms UI shows and edits another employee's data (the `:GLOBAL` identity). This is privilege confusion and cross-employee data exposure.
- **Recommendation:** Add a unique function-based index on `UPPER(EMAIL)` (after cleaning up the data), fail authentication on duplicates, and have the form use the `EMP_ID` returned by the server session instead of re-querying.

### SEC-07: `change_password` Is a Stub That Reports Success (HIGH)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:211-234`
- **Code:**
  ```sql
  PROCEDURE change_password(p_emp_id IN NUMBER, p_old_password IN VARCHAR2, p_new_password IN VARCHAR2) IS
  BEGIN
      IF LENGTH(p_new_password) < 8 THEN ...
      -- NOTE: Actual password update would go to USER_CREDENTIALS table
      -- This is a stub for the legacy system model
      PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
  END change_password;
  ```
- **Issue:** `p_old_password` is never verified, nothing is persisted, and an `UPDATE` audit row is still written. Any caller can "change" any employee's password.
- **Impact:** Users believe a compromised password has been rotated when it has not, and the audit trail records a credential change that never happened. This is a compliance falsification risk.
- **Recommendation:** Implement the change together with SEC-01. Verify the old password, check the new one against policy and history, persist the hash, invalidate existing sessions, and audit only after a successful write.

### SEC-08: Hard-Coded SMTP Relay on Port 25 with No TLS or AUTH (HIGH)

- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:7-10`, `:90-93`; `PKG_NOTIFICATION.pks:9`
- **Code:**
  ```sql
  -- Hard-coded SMTP config (should be in SYSTEM_PARAMETERS)
  c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
  c_smtp_port    CONSTANT NUMBER := 25;
  ...
  v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
  ```
- **Issue:** The host and port are compiled in, and `SYSTEM_PARAMETERS.SMTP_HOST` (seeded at `data/seed/01_reference_data.sql:194`) is ignored. There is no `STARTTLS` and no `AUTH`. Termination notices, salary and leave details travel in cleartext.
- **Impact:** HR data can be intercepted on the network, the relay cannot be moved without recompiling, and an open relay is needed.
- **Recommendation:** Read the SMTP settings from configuration or the wallet. Use `UTL_SMTP.STARTTLS` with a wallet-stored certificate and `AUTH`. Better, hand delivery to an enterprise mail API or queue (see ARCH-04).

### SEC-09: SSN Encryption Lacks an Explicit IV and Integrity Check; Decrypt Failures Are Masked (MEDIUM)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:179-206`
- **Code:**
  ```sql
  typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
  key => c_encryption_key
  ...
  EXCEPTION WHEN OTHERS THEN RETURN '***DECRYPT_ERROR***';
  ```
- **Issue:** No `iv` argument is passed, so CBC uses a zero IV and identical SSNs produce identical ciphertexts. There is no MAC, so ciphertext can be tampered with undetected. `WHEN OTHERS` turns key and corruption errors into a string that looks like a value.
- **Impact:** Duplicate SSNs can be found by comparing ciphertexts. Corrupted or tampered data flows into reports and integrations (the benefits feed) as a literal string.
- **Recommendation:** Use a random IV per value, stored with the ciphertext, plus an HMAC (or move to TDE). Raise a typed exception on decrypt failure and alert on it.

### SEC-10: SMTP Header Injection (MEDIUM)

- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:96-101`
- **Code:**
  ```sql
  UTL_SMTP.WRITE_DATA(v_connection, 'To: ' || notif_rec.RECIPIENT_EMAIL || UTL_TCP.CRLF);
  UTL_SMTP.WRITE_DATA(v_connection, 'Subject: ' || notif_rec.SUBJECT || UTL_TCP.CRLF);
  ```
- **Issue:** `SUBJECT` is built from employee names (for example `PKG_EMPLOYEE.pkb:320`, `:730`), and `RECIPIENT_EMAIL` comes from `EMPLOYEES.EMAIL`. Neither is stripped of CR/LF.
- **Impact:** A crafted name or email can inject `Bcc:` headers or a whole forged message body, which enables phishing from the trusted HRMS sender.
- **Recommendation:** Strip `CHR(10)`/`CHR(13)` from all header values, RFC 2047-encode the subject, and validate recipients against the server-side regex.

### SEC-11: Integration (FTP) Credentials Stored in Cleartext `SYSTEM_PARAMETERS` (MEDIUM)

- **Location:** `plsql/packages/PKG_INTEGRATION.pks:12`; generic reader `PKG_INTEGRATION.pkb:209`, `PKG_COMMON.get_param`
- **Code:**
  ```sql
  --   - FTP credentials stored in SYSTEM_PARAMETERS table (cleartext)
  ...
  RETURN PKG_COMMON.get_param('INTEGRATION', p_integration_name || '_STATUS');
  ```
- **Issue:** The package header documents that external-transfer credentials live in `SYSTEM_PARAMETERS.PARAM_VALUE` (`VARCHAR2(4000)`, no encryption). `get_param` returns any parameter to any caller and has no sensitivity flag.
- **Impact:** Anyone with read access to the table, or with `EXECUTE` on `PKG_COMMON`, can harvest partner credentials.
- **Recommendation:** Move secrets to an Oracle Wallet or vault, add a `SENSITIVE_FLAG` to `SYSTEM_PARAMETERS`, and block `get_param` from returning sensitive values. Replace FTP with SFTP or managed file transfer.

### SEC-12: Predictable Session IDs and a Weak Session Model (MEDIUM)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:64`, `:85-121`; `schema/sequences/hrms_sequences.sql:47`; `forms/xml-exports/HRMS_LOGIN.xml:82`
- **Code:**
  ```sql
  SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;   -- 1, 2, 3 ...
  IF (SYSDATE - v_login_time) * 24 * 60 > c_session_timeout_min THEN
  ```
- **Issue:** Session tokens are sequential integers held in `:GLOBAL.session_id`. The timeout is absolute from login rather than idle-based, uses DB server time (`PKG_SECURITY.pks:10`), and hard-codes the value instead of reading `SESSION_TIMEOUT_MIN` (seed `:190`). `logout` does not check that the session belongs to the caller.
- **Impact:** Anyone who can call `logout` or `is_session_valid` can enumerate or terminate other sessions. Active users are force-logged-out mid-transaction.
- **Recommendation:** Use random 128-bit tokens (`DBMS_CRYPTO.RANDOMBYTES`), track `LAST_ACTIVITY` for idle timeouts, read the timeout from configuration, and bind sessions to `SYS_CONTEXT('USERENV','SESSIONID')`.

### SEC-13: Terminated Employees Keep Active Sessions (MEDIUM)

- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:737-739`; `plsql/packages/PKG_SECURITY.pkb:98-123`
- **Code:**
  ```sql
  -- TODO: Revoke system access via PKG_SECURITY
  ```
- **Issue:** `terminate_employee` never closes `USER_SESSIONS`, and `is_session_valid` does not re-check `EMPLOYMENT_STATUS`.
- **Impact:** A terminated employee's open Forms session keeps working until timeout, which is a classic insider-threat window.
- **Recommendation:** Close all `ACTIVE` sessions on termination, and check employment status in `is_session_valid`. Implement this without a package cycle (see DEP-02), for example with an event or queue.

### SEC-14: User Enumeration via Timing Difference (LOW)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:46-50`
- **Code:**
  ```sql
  -- VULNERABILITY: Timing attack - different response time for
  -- invalid user vs invalid password
  ```
- **Issue:** Unknown users fail fast on `NO_DATA_FOUND`. Once password checks exist, valid users will take measurably longer.
- **Impact:** Attackers can confirm valid employee emails before brute-forcing.
- **Recommendation:** Always run a dummy hash on unknown users, and return a uniform error and latency.

### SEC-15: Hand-Built JSON in Audit Payloads (LOW)

- **Location:** `plsql/triggers/trg_audit.sql:20-29`, `:56-57`; `plsql/packages/PKG_COMMON.pkb:24-25`, `:53-54`
- **Code:**
  ```sql
  '{"status":"' || :OLD.STATUS || '"}'
  '","message":"' || SUBSTR(p_message, 1, 3000) || '"}'   -- log_info: no escaping at all
  ```
- **Issue:** JSON is built by string concatenation. `log_info` does not escape quotes or backslashes, and `log_error` escapes only `"`. NULL numerics produce invalid JSON (`"salary":}`).
- **Impact:** Audit payloads cannot be parsed reliably, and crafted messages can forge audit fields.
- **Recommendation:** Use `JSON_OBJECT(...)` (19c) or `JSON_OBJECT_T` and add an `IS JSON` check constraint to `OLD_VALUES` / `NEW_VALUES`.

---

## 2. Race Conditions

### RACE-01: `MAX()+1` Employee Number Generation (HIGH)

- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:39-55`; `schema/sequences/hrms_sequences.sql:19-21`
- **Code:**
  ```sql
  SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1 INTO v_max_num
  FROM EMPLOYEES WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
  ...
  EXCEPTION WHEN OTHERS THEN
      RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMPLOYEE.NEXTVAL, 6, '0');
  ```
- **Issue:** Two concurrent hires read the same `MAX` and generate the same `EMP_NUMBER`. `SEQ_EMP_NUMBER` exists for this purpose but is unused. The fallback draws from `SEQ_EMPLOYEE` (the `EMP_ID` sequence), which mixes two numbering domains. Any non-numeric suffix raises in `TO_NUMBER` and silently switches to the fallback.
- **Impact:** `UK_EMP_NUMBER` violations surface as "Duplicate employee number generated. Please retry." (`:331-332`), and the MAX query does a full table scan on every hire.
- **Recommendation:** `RETURN 'EMP-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0');` (or an identity column), and remove the `WHEN OTHERS` fallback.

### RACE-02: Pay-Period Status Checked Without a Lock; No Duplicate-Run Guard (HIGH)

- **Location:** `plsql/packages/PKG_PAYROLL.pkb:232-263` (vs. `close_pay_period` at `:187-208`, which does lock)
- **Code:**
  ```sql
  SELECT STATUS INTO v_status FROM PAY_PERIODS WHERE PERIOD_ID = p_period_id;   -- no FOR UPDATE
  IF v_status = 'CLOSED' THEN RAISE_APPLICATION_ERROR(-20102, ...);
  ...
  INSERT INTO PAYROLL_RUNS (RUN_ID, PERIOD_ID, RUN_TYPE, ...) VALUES (...);
  ```
- **Issue:** `close_pay_period` can commit between the check and the insert. Nothing prevents two `REGULAR` runs for the same period.
- **Impact:** Payroll runs are created against closed periods, and employees can be paid twice for one period.
- **Recommendation:** Use `SELECT ... FOR UPDATE` on `PAY_PERIODS`, add a unique partial index on `(PERIOD_ID, RUN_TYPE)` for non-reversed runs, and make status transitions a single guarded `UPDATE ... WHERE STATUS = 'OPEN'`.

### RACE-03: Leave Balance Check-Then-Act Without a Lock (HIGH)

- **Location:** `plsql/packages/PKG_LEAVE.pkb:141-182` (balance read at `:369-383`)
- **Code:**
  ```sql
  v_balance := get_leave_balance(p_emp_id, p_leave_type_id);
  IF v_balance < v_total_days THEN RAISE_APPLICATION_ERROR(-20201, ...);
  ...
  INSERT INTO LEAVE_REQUESTS (...);
  UPDATE LEAVE_BALANCES SET PENDING = PENDING + v_total_days ...
  ```
- **Issue:** Both the overlap check and the balance check read without locking. Two concurrent submissions (Forms plus self-service) both pass.
- **Impact:** Leave balances go negative and overlapping requests are approved, which creates payroll liability and compliance issues for statutory leave.
- **Recommendation:** Lock the `LEAVE_BALANCES` row first (`SELECT ... FOR UPDATE`), then check overlap and balance in the same transaction. Add a `CHECK (AVAILABLE >= 0)` or a deferred validation.

### RACE-04: `calculate_payroll` Does Not Lock or Validate Run Status (HIGH)

- **Location:** `plsql/packages/PKG_PAYROLL.pkb:271-292`
- **Code:**
  ```sql
  SELECT PERIOD_ID, RUN_TYPE INTO v_period_id, v_run_type FROM PAYROLL_RUNS WHERE RUN_ID = p_run_id;
  UPDATE PAYROLL_RUNS SET STATUS = 'CALCULATING', ... WHERE RUN_ID = p_run_id;
  COMMIT;
  ```
- **Issue:** Nothing checks that the run is `PENDING`. An `APPROVED`, `PAID` or `REVERSED` run can be recalculated, and two schedulers can calculate the same run at once. Existing `PAYROLL_DETAILS` are not cleared, so detail rows are appended.
- **Impact:** Duplicate earnings and tax lines, inflated totals, and paid runs changed after approval.
- **Recommendation:** `UPDATE PAYROLL_RUNS SET STATUS='CALCULATING' WHERE RUN_ID=:id AND STATUS IN ('PENDING','ERROR')` and require `SQL%ROWCOUNT = 1`. Delete prior details for `ERROR` re-runs inside the same transaction.

### RACE-05: `reverse_payroll` Has No State Check, Lock or Reason Persistence (MEDIUM)

- **Location:** `plsql/packages/PKG_PAYROLL.pkb:583-600`
- **Code:**
  ```sql
  PROCEDURE reverse_payroll(p_run_id IN NUMBER, p_reason IN VARCHAR2, ...) IS
  BEGIN
      UPDATE PAYROLL_RUNS SET STATUS = 'REVERSED', ... WHERE RUN_ID = p_run_id;
      UPDATE PAYROLL_DETAILS SET STATUS = 'REVERSED' WHERE RUN_ID = p_run_id;
  ```
- **Issue:** A `PENDING` or `CALCULATING` run can be reversed while it is being calculated, a missing `RUN_ID` succeeds silently, and `p_reason` is discarded.
- **Impact:** A reversal can race with a calculation, and SOX evidence for the reversal is lost.
- **Recommendation:** Lock the run, allow only `APPROVED` → `REVERSED` (or `PAID` → `REVERSED` with offsetting entries), and persist the reason and actor.

### RACE-06: Notification Queue Is Not Claimed Atomically (MEDIUM)

- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:78-113`
- **Code:**
  ```sql
  FOR notif_rec IN (SELECT ... FROM NOTIFICATION_QUEUE WHERE STATUS = 'PENDING' ...
                    FETCH FIRST p_batch_size ROWS ONLY) LOOP
  ```
- **Issue:** Rows are not locked (`FOR UPDATE SKIP LOCKED`) or marked `SENDING` before delivery. Overlapping scheduler executions, or a manual run during the 5-minute job, send the same email twice. The single `COMMIT` at the end (`:137`) also means a crash re-sends the whole batch.
- **Impact:** Duplicate termination and pay notifications.
- **Recommendation:** Claim rows with `FOR UPDATE SKIP LOCKED` and a `SENDING` status, and commit per message or use Oracle AQ.

---

## 3. Performance Issues

### PERF-01: Day-by-Day Loop with One SQL Query per Weekday (HIGH)

- **Location:** `plsql/packages/PKG_LEAVE.pkb:12-40`
- **Code:**
  ```sql
  WHILE v_date <= TRUNC(p_end_date) LOOP
      IF TO_CHAR(v_date, 'DY', ...) NOT IN ('SAT', 'SUN') THEN
          SELECT COUNT(*) INTO v_holiday_count FROM HOLIDAYS WHERE HOLIDAY_DATE = v_date ...;
  ```
- **Issue:** O(n) PL/SQL-to-SQL context switches per request, and `HOLIDAYS.HOLIDAY_DATE` has no index (PERF-07).
- **Impact:** Long-range requests (for example parental leave) and bulk validation are slow and hold CPU.
- **Recommendation:** Use one set-based query: generate the dates with `CONNECT BY LEVEL <= n` or use arithmetic for weekdays, then `NOT EXISTS` against `HOLIDAYS`. Or keep a `BUSINESS_CALENDAR` dimension table.

### PERF-02: Day-by-Day Loops in `PKG_COMMON` Business-Day Utilities (MEDIUM)

- **Location:** `plsql/packages/PKG_COMMON.pkb:132-146`, `:151-165`
- **Code:**
  ```sql
  WHILE v_date <= TRUNC(p_end_date) LOOP ... v_date := v_date + 1; END LOOP;
  WHILE v_added < p_days LOOP v_result := v_result + 1; ... END LOOP;
  ```
- **Issue:** Linear loops calling `TO_CHAR` per day. `add_business_days` returns the input date for negative `p_days`, and neither function is holiday-aware, which disagrees with `PKG_LEAVE`.
- **Impact:** CPU cost in reports, plus inconsistent business-day semantics between modules.
- **Recommendation:** Use closed-form weekday arithmetic plus a holiday table lookup, keep a single implementation, and support negative offsets.

### PERF-03: Row-by-Row Payroll Calculation (HIGH)

- **Location:** `plsql/packages/PKG_PAYROLL.pkb:294-327` (per-employee body `:350-552`)
- **Code:**
  ```sql
  -- BUG: Cursor loop - should use BULK COLLECT + FORALL
  FOR emp_rec IN (SELECT e.EMP_ID FROM EMPLOYEES e WHERE ...) LOOP
      calculate_employee_pay(p_run_id, emp_rec.EMP_ID, v_period_id, p_user);
  ```
- **Issue:** Each employee runs roughly 10 single-row SELECTs and 5–10 single-row INSERTs, plus a `get_ytd_earnings` aggregate over all of that employee's historic `PAYROLL_DETAILS` (`:802-820`).
- **Impact:** Pay-run time grows linearly with a large per-row constant, so a 10k-employee run takes hours. It also contributes to DATA-09.
- **Recommendation:** Stage inputs with `BULK COLLECT`, compute earnings and taxes set-based (`INSERT ... SELECT` joined to `TAX_BRACKETS`), keep YTD in a summary table, and use `FORALL` for detail inserts.

### PERF-04: `CONNECT BY` Hierarchies with No `NOCYCLE` and No Index (HIGH)

- **Location:** `schema/views/hrms_views.sql:47-57`; `plsql/packages/PKG_EMPLOYEE.pkb:822-840`
- **Code:**
  ```sql
  SELECT ..., SYS_CONNECT_BY_PATH(FIRST_NAME || ' ' || LAST_NAME, ' > ') AS ORG_PATH
  FROM EMPLOYEES WHERE EMPLOYMENT_STATUS = 'ACTIVE'
  START WITH MANAGER_EMP_ID IS NULL
  CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
  ```
- **Issue:**
  - `EMPLOYEES.MANAGER_EMP_ID` has no index, so each level scans the whole table.
  - A manager loop raises ORA-01436, because `NOCYCLE` is absent and `validate_manager` only guards package paths.
  - The `WHERE` filter is applied after the hierarchy is built, so reports of a terminated manager remain but show a broken `ORG_PATH`.
  - Headers note timeouts beyond 500 employees (`hrms_views.sql:45`, `PKG_EMPLOYEE.pks:10`).
- **Impact:** Org-chart forms and reports time out, and one bad `MANAGER_EMP_ID` update breaks the view for everyone.
- **Recommendation:** Index `MANAGER_EMP_ID`, add `NOCYCLE` and `CONNECT_BY_ISCYCLE`, move the status filter into `START WITH`/`CONNECT BY`, or materialize a closure table refreshed on change.

### PERF-05: New SMTP Connection per Notification (MEDIUM)

- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:87-107`
- **Code:**
  ```sql
  ) LOOP
      v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
      UTL_SMTP.HELO(v_connection, c_smtp_host);
      ...
      UTL_SMTP.QUIT(v_connection);
  ```
- **Issue:** Every message pays for a TCP connect, SMTP handshake and quit.
- **Impact:** Queue throughput is limited by network latency, and bulk operations (for example `generate_reviews_for_cycle`) back the queue up (`PKG_NOTIFICATION.pks:10`).
- **Recommendation:** Open one connection per batch and send multiple `MAIL`/`RCPT`/`DATA` transactions (with `RSET` on error), or hand off to a mail service.

### PERF-06: `NOCACHE` on Every Sequence (MEDIUM)

- **Location:** `schema/sequences/hrms_sequences.sql:9-49`
- **Code:**
  ```sql
  CREATE SEQUENCE HRMS.SEQ_PAYROLL_DETAIL START WITH 1 INCREMENT BY 1 NOCACHE;
  CREATE SEQUENCE HRMS.SEQ_NOTIFICATION   START WITH 1 INCREMENT BY 1 NOCACHE;
  ```
- **Issue:** Every `NEXTVAL` updates `SEQ$` in the data dictionary. That is a serialization point on high-volume sequences (`SEQ_PAYROLL_DETAIL`, `SEQ_AUDIT`, `SEQ_NOTIFICATION`), and on RAC it becomes cross-instance contention. The comment at `:19-20` misunderstands `NOCACHE`, which does not prevent gaps.
- **Impact:** Measurable slowdown during payroll and audit-heavy batches.
- **Recommendation:** `CACHE 100`–`1000` for surrogate keys. Gaps are acceptable; business numbers that must be gap-free need a different mechanism anyway.

### PERF-07: No Secondary or Function-Based Indexes in the Schema (MEDIUM)

- **Location:** `schema/` (only `tables/`, `views/`, `sequences/` exist); hot predicates at `PKG_SECURITY.pkb:44`, `plsql/triggers/trg_employees.sql:47`, `PKG_LEAVE.pkb:27`, `:53-59`, `PKG_PAYROLL.pkb:334-341`
- **Code:**
  ```sql
  WHERE UPPER(EMAIL) = UPPER(p_username)                 -- every login and every insert
  WHERE HOLIDAY_DATE = v_date                            -- every weekday of every leave request
  WHERE RUN_ID = p_run_id AND ELEMENT_TYPE = 'EARNING'  -- run totals
  ```
- **Issue:** Only PK and UK indexes exist. Foreign-key columns (`EMPLOYEES.DEPT_ID`, `MANAGER_EMP_ID`, `PAYROLL_DETAILS.RUN_ID`/`EMP_ID`, `LEAVE_REQUESTS.EMP_ID`) are unindexed. That forces full scans, and it causes table-level locks on the child table when a parent row is deleted or its key updated.
- **Impact:** Login, hire, leave and payroll paths get slower with data volume, and there is a deadlock risk on parent updates.
- **Recommendation:** Add `schema/indexes/`: FK indexes, `UPPER(EMAIL)` (unique, see DATA-12), `HOLIDAYS(HOLIDAY_DATE, LOCATION_CODE)`, `PAYROLL_DETAILS(RUN_ID, ELEMENT_TYPE)`, `LEAVE_REQUESTS(EMP_ID, STATUS, START_DATE)`, `NOTIFICATION_QUEUE(STATUS, PRIORITY, CREATED_DATE)`.

### PERF-08: Nested Per-Employee, Per-Leave-Type Accrual Loop (LOW)

- **Location:** `plsql/packages/PKG_LEAVE.pkb:459-552`
- **Code:**
  ```sql
  v_current_balance := get_leave_balance(emp_rec.EMP_ID, lt_rec.LEAVE_TYPE_ID, ...);
  UPDATE LEAVE_BALANCES SET ACCRUED = ACCRUED + v_accrued ...;
  IF SQL%ROWCOUNT = 0 THEN initialize_balances(...); UPDATE ... SET ACCRUED = v_accrued ...
  ...
  IF MOD(v_total_employees, 100) = 0 THEN COMMIT;
  ```
- **Issue:** Employees × leave types single-row operations, with commits partway through. There is no idempotency key on `LEAVE_ACCRUAL_LOG`, so a re-run double-accrues.
- **Impact:** Slow monthly job, and a partial failure leaves half the workforce accrued.
- **Recommendation:** Use a set-based `MERGE` into `LEAVE_BALANCES` from a computed accrual set, and add a unique `(EMP_ID, LEAVE_TYPE_ID, ACCRUAL_DATE)` on `LEAVE_ACCRUAL_LOG`.

### PERF-09: Nightly-Refreshed Denormalized Reporting Data (LOW)

- **Location:** `plsql/packages/PKG_REPORTING.pks:9`
- **Code:**
  ```sql
  --   - Denormalized reporting tables refreshed nightly; stale during business hours
  ```
- **Issue:** Reports read a snapshot that can be up to 24 hours stale.
- **Impact:** Headcount and compensation reports disagree with the Forms screens.
- **Recommendation:** Use fast-refresh materialized views or real-time MVs, or report directly from indexed OLTP tables.

---

## 4. Validation Drift (PLL / Forms vs. Server)

### VAL-01: Email Validation — Hand-Rolled PLL vs. Server Regex (MEDIUM)

- **Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41` vs `plsql/packages/PKG_COMMON.pkb:265-268` (via `PKG_VALIDATION.pkb:50-55`)
- **Code:**
  ```sql
  -- PLL
  v_dot_pos := INSTR(p_email, '.', v_at_pos);
  IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN RETURN FALSE;
  -- Server
  RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
  ```
- **Issue:** The PLL accepts inputs the server rejects: spaces, multiple `@`, `a@b.c`, trailing-dot domains such as `a@b.c.`. The PLL comment (`:17-19`, `:39`) says subdomains are rejected, but the code accepts them. `HRMS_EMPLOYEE.xml:375-377` calls the server version, so different forms behave differently.
- **Impact:** Users get inconsistent errors, invalid emails can be stored through paths that only use the PLL, and notification delivery fails.
- **Recommendation:** Delete the PLL implementation and call `PKG_VALIDATION.validate_email_format` everywhere. Add a `CHECK (REGEXP_LIKE(EMAIL, ...))` on `EMPLOYEES`.

### VAL-02: Hire-Date Future Limit Differs in Every Tier (MEDIUM)

- **Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:96-99` (0 days); `forms/xml-exports/HRMS_EMPLOYEE.xml:383-386` (90 days); `plsql/triggers/trg_employees.sql:35-38` (180 days); `plsql/packages/PKG_EMPLOYEE.pkb:183-205` (no check)
- **Code:**
  ```sql
  RETURN p_date IS NULL OR TRUNC(p_date) <= TRUNC(SYSDATE);         -- PLL
  IF :EMPLOYEE.HIRE_DATE > SYSDATE + 90 THEN                        -- Form
  IF :NEW.HIRE_DATE > SYSDATE + 180 THEN                            -- DB trigger
  ```
- **Issue:** There are four different rules for one business constraint, and the package API enforces none of them.
- **Impact:** Batch and integration hires can be dated 179 days out, while Forms users cannot pre-hire at all when the PLL is used.
- **Recommendation:** Store `MAX_FUTURE_HIRE_DAYS` in `SYSTEM_PARAMETERS`, enforce it once in `PKG_VALIDATION`, and call that from Forms and the package. Remove the trigger duplicate.

### VAL-03: Salary Range Is Not Enforced Server-Side (HIGH)

- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:220-240`; `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:102-135`; `plsql/packages/PKG_VALIDATION.pkb:17-48`
- **Code:**
  ```sql
  IF p_base_salary < v_min OR p_base_salary > v_max THEN
      -- NOTE: This is a soft warning, not an error
      IF g_debug_mode THEN DBMS_OUTPUT.PUT_LINE('WARNING: Salary ...'); END IF;
  ```
- **Issue:** `create_employee` does nothing when a salary is out of range (the output is only visible in debug mode), and no "manager approval" override is recorded. The PLL treats a NULL salary or grade as valid while `PKG_VALIDATION` treats it as an error. The PLL comment claims a stale cache, but the code queries the table directly.
- **Impact:** Out-of-band salaries enter payroll without approval evidence, which is a pay-equity and SOX control gap.
- **Recommendation:** Call `PKG_VALIDATION.validate_salary_for_grade` in `create_employee`, `promote_employee`, `rehire_employee` and `create_salary_record`. Require an explicit override flag plus approver, and persist it on `SALARY_RECORDS`.

### VAL-04: SSN Validation — PLL Rejects Zero Groups, Server Does Not (MEDIUM)

- **Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:69-90` vs `plsql/packages/PKG_COMMON.pkb:277-280`
- **Code:**
  ```sql
  IF SUBSTR(v_digits,1,3) = '000' OR SUBSTR(v_digits,4,2) = '00' OR SUBSTR(v_digits,6,4) = '0000' THEN RETURN FALSE;  -- PLL
  RETURN REGEXP_LIKE(REGEXP_REPLACE(p_ssn, '[^0-9]', ''), '^\d{9}$');                                              -- server
  ```
- **Issue:** The server accepts `000-00-0000`, `666-xx-xxxx` and `9xx-xx-xxxx` (ITIN range). The PLL's `TRANSLATE` keeps letters, so `12345678a` has length 9 and passes the length check.
- **Impact:** Invalid SSNs reach tax filings (W-2 / 941) through the API path.
- **Recommendation:** Keep one server rule that includes the SSA area, group and serial constraints, and have the PLL delegate to it.

### VAL-05: Phone Validation Character Sets Differ (LOW)

- **Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:47-63` vs `plsql/packages/PKG_COMMON.pkb:270-275`
- **Code:**
  ```sql
  v_digits := TRANSLATE(p_phone, '0123456789()-. +x', '0123456789');   -- PLL: strips only listed chars
  v_digits := REGEXP_REPLACE(p_phone, '[^0-9]', '');                   -- server: strips all non-digits
  ```
- **Issue:** `555/123/4567` fails in the PLL but passes on the server. `x` extensions are stripped and counted differently.
- **Impact:** Minor usability inconsistency.
- **Recommendation:** Delegate to the server function, or store E.164 numbers.

### VAL-06: Date-Range Validation Is Not Business-Day or Backdate Aware (LOW)

- **Location:** `plsql/packages/PKG_VALIDATION.pkb:6-15` vs `plsql/packages/PKG_LEAVE.pkb:115-138`
- **Code:**
  ```sql
  RETURN p_end_date >= p_start_date;                                 -- PKG_VALIDATION
  IF TRUNC(SYSDATE) - p_start_date > 5 THEN ... -20211              -- PKG_LEAVE only
  IF v_total_days <= 0 THEN ... -20212 'No business days'            -- PKG_LEAVE only
  ```
- **Issue:** Forms that validate with `PKG_VALIDATION` accept weekend-only ranges and old backdated ranges that `submit_leave_request` later rejects.
- **Impact:** Users see late errors after committing the form.
- **Recommendation:** Expose `PKG_LEAVE.validate_request(...)` and call it from `WHEN-VALIDATE-RECORD`.

### VAL-07: Password Minimum Length Hard-Coded, Ignoring Configuration (LOW)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:218` vs `data/seed/01_reference_data.sql:192`
- **Code:**
  ```sql
  IF LENGTH(p_new_password) < 8 THEN                                 -- code
  ... 'SECURITY', 'PASSWORD_MIN_LENGTH', '8', ...                    -- seed parameter (unused)
  ```
- **Issue:** Changing the parameter has no effect.
- **Impact:** A policy change cannot be deployed without a code release.
- **Recommendation:** Read `PASSWORD_MIN_LENGTH` (and complexity rules) through `PKG_COMMON.get_param`.

---

## 5. Circular / Layering Dependencies

**Observed package call graph (from package bodies):**

```
PKG_SECURITY     -> PKG_AUDIT, PKG_EMPLOYEE
PKG_EMPLOYEE     -> PKG_AUDIT, PKG_COMMON, PKG_NOTIFICATION, PKG_PAYROLL
PKG_PAYROLL      -> PKG_AUDIT, PKG_COMMON
PKG_LEAVE        -> PKG_AUDIT, PKG_NOTIFICATION
PKG_PERFORMANCE  -> PKG_AUDIT, PKG_NOTIFICATION
PKG_NOTIFICATION -> PKG_COMMON
PKG_INTEGRATION  -> PKG_COMMON
PKG_REPORTING    -> PKG_COMMON
PKG_VALIDATION   -> PKG_COMMON
trg_audit.sql    -> PKG_AUDIT   (trg_employees.sql mentions PKG_EMPLOYEE only in a comment)
Forms (*.xml)    -> PKG_SECURITY, PKG_EMPLOYEE, PKG_VALIDATION, PKG_LEAVE, PKG_PAYROLL
```

The body graph has no live cycle. The specs, however, declare dependencies that would create one, and the code comments describe one.

### DEP-01: Declared `PKG_EMPLOYEE` ↔ `PKG_PAYROLL` Cycle; Domain Layering Inverted (MEDIUM)

- **Location:** `plsql/packages/PKG_EMPLOYEE.pks:6-9`; `plsql/packages/PKG_PAYROLL.pks:6-9`; `plsql/packages/PKG_EMPLOYEE.pkb:271-281`, `:777-783`
- **Code:**
  ```sql
  -- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
  -- which in turn may call PKG_EMPLOYEE.is_active for validation
  PKG_PAYROLL.create_salary_record(p_emp_id => v_emp_id, ...);
  ```
- **Issue:** `PKG_PAYROLL.pks` claims it depends on `PKG_EMPLOYEE` (`is_active`), but the current body does not call it. The core HR package depends on payroll, so any recompilation of `PKG_PAYROLL` invalidates `PKG_EMPLOYEE` and, through it, `PKG_SECURITY` (login). If the documented `is_active` call is ever added back, it closes a real cycle (ORA-04068 cascades, and deployment ordering problems).
- **Impact:** Fragile deployments, and a payroll hot-fix invalidates the login path.
- **Recommendation:** Extract `SALARY_RECORDS` maintenance into `PKG_COMPENSATION` with no dependency on employee or payroll, and have both callers use it. Correct the headers.

### DEP-02: `PKG_SECURITY → PKG_EMPLOYEE`, with a Latent Reverse Edge (MEDIUM)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:75`; `plsql/packages/PKG_EMPLOYEE.pkb:738`, `:948-966`
- **Code:**
  ```sql
  PKG_EMPLOYEE.set_session_context(p_username, v_emp_id);      -- security -> domain
  -- TODO: Revoke system access via PKG_SECURITY                 -- planned domain -> security
  ```
- **Issue:** Security infrastructure depends on a domain package for session state. Doing the SEC-13 TODO directly creates `PKG_EMPLOYEE ↔ PKG_SECURITY`.
- **Impact:** A cycle risk, and login becomes coupled to the largest and most volatile package.
- **Recommendation:** Move session context to an application context (`DBMS_SESSION.SET_CONTEXT`) owned by `PKG_SECURITY`, and signal termination with an event, queue or trigger.

### DEP-03: Package Dependency Headers Are Stale (LOW)

- **Location:** `PKG_INTEGRATION.pks:6` (claims `PKG_PAYROLL`, `PKG_EMPLOYEE`), `PKG_LEAVE.pks:6` (claims `PKG_EMPLOYEE`, `PKG_COMMON`), `PKG_PERFORMANCE.pks:6`, `PKG_REPORTING.pks:6`, `PKG_SECURITY.pks:6` (omits `PKG_EMPLOYEE`), `PKG_PAYROLL.pks:6` (claims `PKG_EMPLOYEE`, `PKG_NOTIFICATION`)
- **Code:**
  ```sql
  -- Dependencies: PKG_COMMON, PKG_PAYROLL, PKG_EMPLOYEE      (PKG_INTEGRATION; body uses only PKG_COMMON)
  ```
- **Issue:** The documentation does not match `USER_DEPENDENCIES`.
- **Impact:** Engineers plan deployments and impact analysis from wrong information.
- **Recommendation:** Generate dependency docs from `USER_DEPENDENCIES` in CI and drop the hand-written headers.

---

## 6. Architectural Anti-Patterns

### ARCH-01: Autonomous Transactions for Audit, History and Notifications (HIGH)

- **Location:** `plsql/packages/PKG_AUDIT.pkb:14-26`; `plsql/packages/PKG_EMPLOYEE.pkb:155-170`; `plsql/packages/PKG_NOTIFICATION.pkb:27-56`; `plsql/packages/PKG_COMMON.pkb:16-28`, `:46-57`
- **Code:**
  ```sql
  PRAGMA AUTONOMOUS_TRANSACTION;
  BEGIN
      INSERT INTO EMPLOYEE_HISTORY (...) VALUES (...);
      COMMIT;
  ```
- **Issue:** History, audit and notifications commit on their own. When the business transaction later rolls back (for example `create_employee` failing on `DUP_VAL_ON_INDEX` at `:331`), the history row, audit row and "Welcome aboard" email are already committed. Autonomous transactions also cannot see the caller's uncommitted rows. For a new hire, `log_history` (`:285`) inserts a child row whose `EMPLOYEES` parent is still uncommitted in the calling transaction. By Oracle FK semantics this should fail (the autonomous transaction waits on the caller's lock, which is a self-deadlock, ORA-00060), and `:171-174` swallows the error. **HIRE history records are therefore expected to be silently lost** (inferred; not reproduced on a live instance).
- **Impact:** Phantom audit and history rows, missing hire history, and emails about hires or terminations that never happened.
- **Recommendation:** Write history and audit in the same transaction. Keep autonomous transactions only for error logging. Queue notifications transactionally (AQ with `VISIBILITY => ON_COMMIT`, or an outbox table processed after commit).

### ARCH-02: Audit Failures Silently Swallowed (HIGH)

- **Location:** `plsql/packages/PKG_AUDIT.pkb:27-31`; similar at `PKG_EMPLOYEE.pkb:171-178`, `PKG_NOTIFICATION.pkb:57-62`, `PKG_COMMON.pkb:29-35`
- **Code:**
  ```sql
  EXCEPTION
      WHEN OTHERS THEN
          -- Audit logging must never fail the calling transaction
          ROLLBACK;
  END log_action;
  ```
- **Issue:** Any constraint violation is discarded without trace: `CHK_AUDIT_ACTION` (DATA-06), `CHANGED_BY` length (DATA-14), or a sequence problem.
- **Impact:** Compliance gaps nobody notices. Auditors cannot tell "no change" from "change not logged".
- **Recommendation:** Log the failure to an alert log or `DBMS_SYSTEM.KSDWRT`, raise a metric or alert, and consider failing closed for sensitive tables (salary, bank).

### ARCH-03: One-Year Default Audit Purge (MEDIUM)

- **Location:** `plsql/packages/PKG_AUDIT.pkb:33-47`
- **Code:**
  ```sql
  PROCEDURE purge_old_records(p_days_to_keep IN NUMBER DEFAULT 365, ...) IS
  BEGIN
      DELETE FROM AUDIT_LOG WHERE CHANGED_DATE < SYSDATE - p_days_to_keep;
      COMMIT;
  ```
- **Issue:** Payroll and HR records usually have multi-year retention (FLSA 3 years, IRS 4 years, SOX 7 years). The purge does not archive first and does not record that it ran.
- **Impact:** Irrecoverable loss of legally required audit evidence.
- **Recommendation:** Drive retention from configuration per `TABLE_NAME`, archive before deleting (partition exchange), and audit the purge itself.

### ARCH-04: UTL_FILE Flat-File Integrations (MEDIUM)

- **Location:** `plsql/packages/PKG_INTEGRATION.pkb:7-9`, `:27-70`, `:99-119`, `:162-183`; `plsql/packages/PKG_PAYROLL.pkb:842-880`
- **Code:**
  ```sql
  v_file := UTL_FILE.FOPEN(c_gl_output_dir, v_filename, 'W', 32767);
  UTL_FILE.PUT_LINE(v_file, 'T|' || v_entries);
  ```
- **Issue:** GL, benefits (vendor-specific ADP format), time-and-attendance and the pay register all go through DB-server directories. There is no checksum, no atomic rename, no retry (`PKG_INTEGRATION.pks:11`), and no acknowledgement. The pay register CSV only quotes names and does not escape embedded quotes.
- **Impact:** Partially written files get picked up by downstream batch jobs, and integrations fail silently, affecting GL postings and benefit enrollment.
- **Recommendation:** Move to API or event-based integration (REST via ORDS, Oracle Integration Cloud, or AQ). In the interim, write to a temp name, rename on completion, add trailer and hash validation, and add retry and acknowledgement tables.

### ARCH-05: Stub Integrations Report Success (HIGH)

- **Location:** `plsql/packages/PKG_INTEGRATION.pkb:164-186`, `:196-203`
- **Code:**
  ```sql
  -- TODO: Implement actual parsing and database update
  v_imported := v_imported + 1;
  ...
  -- Placeholder for org structure sync with external directory (LDAP/AD)
  PKG_COMMON.log_info('PKG_INTEGRATION', 'sync_org_structure', 'Org structure sync completed', p_user);
  ```
- **Issue:** `import_time_attendance` counts lines as "imported" but persists nothing. `sync_org_structure` logs "completed" and does nothing.
- **Impact:** Overtime and hours never reach payroll, even though logs say they were imported. Directory de-provisioning never happens (compounding SEC-13).
- **Recommendation:** Implement or remove the procedures. Until then, have them raise `NOT_IMPLEMENTED` so schedulers show failures.

### ARCH-06: Stubbed Termination Side-Effects (MEDIUM)

- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:737-739`
- **Code:**
  ```sql
  -- TODO: Integrate with benefits system to trigger COBRA
  -- TODO: Revoke system access via PKG_SECURITY
  -- TODO: Calculate final pay via PKG_PAYROLL.calculate_final_pay
  ```
- **Issue:** Three legally significant off-boarding steps are not implemented, and `calculate_final_pay` does not exist.
- **Impact:** Missed COBRA notices (ERISA penalties), late final pay (state wage-payment laws), and orphaned access.
- **Recommendation:** Build an off-boarding workflow (an outbox table plus a handler per step) with status tracking and SLA alerts.

### ARCH-07: Hard-Coded 2024 Tax Constants and Brackets; Pre-Tax Deductions Ignored (HIGH)

- **Location:** `plsql/packages/PKG_PAYROLL.pkb:7-14`, `:605-677`, `:437`
- **Code:**
  ```sql
  c_ss_wage_base_2024   CONSTANT NUMBER := 168600;
  c_standard_deduction_single CONSTANT NUMBER := 14600;
  -- TODO: Read from TAX_BRACKETS table instead of hard-coding
  IF v_taxable <= 11600 THEN ...
  v_taxable_income := v_period_gross; -- Simplified; should subtract pretax deductions
  ```
- **Issue:** Tax-year constants are compiled in, and the `TAX_BRACKETS` table exists but is unused. `HEAD_OF_HOUSEHOLD` (allowed by `CHK_FILING_STATUS`, `02_payroll_tables.sql:172`) matches neither bracket branch (`:645`, `:661`; no `ELSE`), so `v_tax` stays `0` and it gets the single standard deduction. Pre-tax benefits (`PRETAX_FLAG`) are not deducted from taxable wages.
- **Impact:** Every 2025+ pay run withholds the wrong federal tax. Head-of-household employees get zero or incorrect withholding. Pre-tax elections are over-taxed.
- **Recommendation:** Drive brackets, wage bases and standard deductions from `TAX_BRACKETS` by `TAX_YEAR` and filing status. Subtract `PRETAX_FLAG='Y'` elements before computing tax. Add regression fixtures per tax year.

### ARCH-08: Hard-Coded October Fiscal-Year Start (MEDIUM)

- **Location:** `plsql/packages/PKG_COMMON.pkb:167-195`; `PKG_REPORTING.pks:10`; unused parameter at `data/seed/01_reference_data.sql:188`
- **Code:**
  ```sql
  IF EXTRACT(MONTH FROM p_date) >= 10 THEN RETURN EXTRACT(YEAR FROM p_date) + 1;
  WHEN v_month IN (10, 11, 12) THEN 1
  ```
- **Issue:** `FISCAL_YEAR_START` is seeded but ignored.
- **Impact:** Every fiscal report is wrong if the fiscal calendar changes, for example after an acquisition.
- **Recommendation:** Derive the fiscal year and quarter from `get_param('PAYROLL','FISCAL_YEAR_START')`, or from a fiscal calendar table.

### ARCH-09: Business Rules Duplicated Across Four Tiers (MEDIUM)

- **Location:** `plsql/triggers/trg_employees.sql:1-6`; `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:8-11`; `forms/xml-exports/HRMS_EMPLOYEE.xml:370-400`; `plsql/packages/PKG_VALIDATION.pks:1-8`
- **Code:**
  ```sql
  -- These triggers enforce business rules at the database level,
  -- duplicating logic that also exists in PKG_EMPLOYEE and Forms triggers.
  ```
- **Issue:** Email, hire-date, salary, SSN and uniqueness rules live in Forms item triggers, PLLs, packages and DB triggers, each slightly different (Section 4).
- **Impact:** Every rule change needs four edits, and the drift findings above are the result.
- **Recommendation:** Make `PKG_VALIDATION` the single source of truth. Forms and PLLs call it; triggers keep only declarative constraints.

### ARCH-10: Session State in Public Package Globals (MEDIUM)

- **Location:** `plsql/packages/PKG_EMPLOYEE.pks:14-17`; `plsql/packages/PKG_EMPLOYEE.pkb:948-966`
- **Code:**
  ```sql
  g_current_user       VARCHAR2(30);
  g_current_emp_id     NUMBER(10);
  g_current_dept_id    NUMBER(10);
  g_debug_mode         BOOLEAN := FALSE;
  ```
- **Issue:** Identity lives in writable public globals. Any caller can set `g_current_emp_id`, the value is lost on ORA-04068 package-state resets, and it does not survive connection pooling.
- **Impact:** Identity spoofing, and state loss after any recompilation.
- **Recommendation:** Use a secured application context (`CREATE CONTEXT ... USING PKG_SECURITY`) and read it with `SYS_CONTEXT`.

### ARCH-11: Magic Pay-Element IDs (LOW)

- **Location:** `plsql/packages/PKG_PAYROLL.pkb:409`, `:449`, `:467`, `:482`, `:496`, `:854-857`
- **Code:**
  ```sql
  SEQ_PAYROLL_DETAIL.NEXTVAL, p_run_id, p_emp_id, 1, 'EARNING', ...
  SUM(CASE WHEN pd.ELEMENT_ID = 100 THEN ABS(pd.AMOUNT) ELSE 0 END) AS FED,
  ```
- **Issue:** Element IDs 1 and 100–103 are coupled to seed data, not to `ELEMENT_CODE`.
- **Impact:** Payroll breaks in any environment seeded differently.
- **Recommendation:** Look up by `ELEMENT_CODE` (`BASE_PAY`, `FED_TAX`, ...) once per run.

### ARCH-12: `DBMS_OUTPUT` Used for Batch Status (LOW)

- **Location:** `plsql/packages/PKG_LEAVE.pkb:550-551`; `plsql/packages/PKG_PERFORMANCE.pkb:316`; `plsql/packages/PKG_AUDIT.pkb:45-46`; `plsql/packages/PKG_EMPLOYEE.pkb:235-236`
- **Code:**
  ```sql
  DBMS_OUTPUT.PUT_LINE('Accrual complete: ' || v_total_employees || ...);
  ```
- **Issue:** Output is discarded under `DBMS_SCHEDULER`.
- **Impact:** No operational visibility into batch jobs.
- **Recommendation:** Log to a job-run table or `PKG_COMMON.log_info`, and add `DBMS_APPLICATION_INFO` progress reporting.

---

## 7. Data Integrity Risks

### Trigger / DML vs. DDL cross-reference

Scripted comparison of every `INSERT INTO <table> (<cols>)` against `CREATE TABLE`:

| Source | Target table | Columns not in DDL |
|--------|--------------|--------------------|
| `plsql/triggers/trg_employees.sql:78-85`, `:90-97`, `:102-109` | `EMPLOYEE_HISTORY` | `HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON` |
| `data/seed/01_reference_data.sql:11-18` | `LOCATIONS` | `PHONE` (DDL: `PHONE_NUMBER`) |
| `data/seed/01_reference_data.sql:23-41` | `JOB_GRADES` | `GRADE_LEVEL` (and NOT NULL `GRADE_CODE` omitted) |
| `data/seed/01_reference_data.sql:182-201` | `SYSTEM_PARAMETERS` | `DESCRIPTION` (DDL: `PARAM_DESCRIPTION`) |

All package-body DML matched the DDL column names. Value-domain mismatches are listed separately in DATA-02, DATA-04 and DATA-06.

### DATA-01: `TRG_EMP_BEFORE_UPDATE` Column List Does Not Match `EMPLOYEE_HISTORY` (CRITICAL)

- **Location:** `plsql/triggers/trg_employees.sql:76-110` vs `schema/tables/01_core_tables.sql:152-177`
- **Code:**
  ```sql
  -- Trigger
  INSERT INTO EMPLOYEE_HISTORY (
      HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
      OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
  ) ...
  -- DDL
  HIST_ID, EMP_ID, CHANGE_TYPE, EFFECTIVE_DATE, OLD_DEPT_ID, NEW_DEPT_ID, OLD_JOB_ID, NEW_JOB_ID,
  OLD_MANAGER_ID, NEW_MANAGER_ID, OLD_SALARY, NEW_SALARY, OLD_LOCATION, NEW_LOCATION,
  REASON_CODE, COMMENTS, CREATED_BY (NOT NULL), CREATED_DATE
  ```
- **Issue:** Six of the eight referenced columns do not exist, so the trigger compiles with errors (PLS-00904 / ORA-00904). An invalid row trigger makes **every** `UPDATE` on `EMPLOYEES` fail with ORA-04098, not only status, department or job changes. Even with the names fixed, the insert omits the NOT NULL `CREATED_BY` and `EFFECTIVE_DATE`.
- **Impact:** `terminate_employee`, `transfer_employee`, `promote_employee`, `rehire_employee`, Forms edits and even `MODIFIED_DATE` touches all fail. Core HR operations are down.
- **Recommendation:** Remove history writes from the trigger, because `PKG_EMPLOYEE.log_history` already writes structured history (DATA-15). If they must stay, map the columns correctly (`HIST_ID`, `EFFECTIVE_DATE`, `OLD_/NEW_DEPT_ID`, `OLD_/NEW_JOB_ID`, `REASON_CODE`, `CREATED_BY`). Add a CI step that compiles every object against the DDL and fails on `USER_ERRORS`.

### DATA-02: Trigger Emits `CHANGE_TYPE` Values Rejected by `CHK_CHANGE_TYPE` (CRITICAL)

- **Location:** `plsql/triggers/trg_employees.sql:94`, `:106` vs `schema/tables/01_core_tables.sql:173-176`
- **Code:**
  ```sql
  SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'DEPARTMENT_CHANGE', SYSDATE, ...
  SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'JOB_CHANGE', SYSDATE, ...
  -- CHECK (CHANGE_TYPE IN ('HIRE','TRANSFER','PROMOTION','DEMOTION','SALARY_CHANGE',
  --                        'TERMINATION','REHIRE','LEAVE_START','LEAVE_END','STATUS_CHANGE'))
  ```
- **Issue:** Once DATA-01 is fixed, every department or job change raises ORA-02290 inside the trigger and rolls back the whole update.
- **Impact:** Transfers and promotions stay blocked after the column fix, so this is a second hidden release blocker.
- **Recommendation:** Use the domain values `TRANSFER` and `PROMOTION`/`DEMOTION`, or extend the constraint. Better, use one history writer (DATA-15).

### DATA-03: Reference Seed Script Does Not Match the DDL (CRITICAL)

- **Location:** `data/seed/01_reference_data.sql:11-18`, `:23-41`, `:182-201` vs `schema/tables/01_core_tables.sql:34-51`, `:56-71`; `schema/tables/04_performance_tables.sql:109-123`
- **Code:**
  ```sql
  INSERT INTO LOCATIONS (..., COUNTRY_CODE, PHONE, ACTIVE_FLAG, ...)                 -- DDL: PHONE_NUMBER
  INSERT INTO JOB_GRADES (GRADE_ID, GRADE_NAME, GRADE_LEVEL, MIN_SALARY, ...)        -- no GRADE_LEVEL; GRADE_CODE NOT NULL missing
  INSERT INTO SYSTEM_PARAMETERS (..., PARAM_VALUE, DESCRIPTION, EDITABLE_FLAG, ...)  -- DDL: PARAM_DESCRIPTION
  ```
- **Issue:** All 3 location, 10 grade and 10 system-parameter inserts fail with ORA-00904. `JOB_TITLES` (FK to `JOB_GRADES`), `DEPARTMENTS`/`EMPLOYEES` (FK to `LOCATIONS`) and `data/seed/02_employee_data.sql` then fail their foreign keys. `SET DEFINE OFF` without `WHENEVER SQLERROR EXIT` lets the script "complete" and `COMMIT` a partial seed.
- **Impact:** Fresh environments (dev, test, DR rebuilds) have no reference data. `get_param` returns NULL for every setting, and the application cannot run.
- **Recommendation:** Fix the column names and supply `GRADE_CODE`. Add `WHENEVER SQLERROR EXIT FAILURE ROLLBACK` to seed scripts, and run schema+seed installation in CI against a disposable Oracle 19c/23ai Free container.

### DATA-04: Payroll Error Handler Violates `FK_PD_ELEMENT`, Aborting the Run (CRITICAL)

- **Location:** `plsql/packages/PKG_PAYROLL.pkb:306-319` vs `schema/tables/02_payroll_tables.sql:136-153`
- **Code:**
  ```sql
  WHEN OTHERS THEN
      v_error_count := v_error_count + 1;
      INSERT INTO PAYROLL_DETAILS (DETAIL_ID, RUN_ID, EMP_ID, ELEMENT_ID, ELEMENT_TYPE, ...)
      VALUES (SEQ_PAYROLL_DETAIL.NEXTVAL, p_run_id, emp_rec.EMP_ID, 0, 'ERROR', 0, 'ERROR', ...);
  -- DDL: ELEMENT_ID NOT NULL, CONSTRAINT FK_PD_ELEMENT FOREIGN KEY (ELEMENT_ID) REFERENCES PAY_ELEMENTS(ELEMENT_ID)
  ```
- **Issue:** No `PAY_ELEMENTS` row has `ELEMENT_ID = 0` (the seed starts at 1). The handler raises ORA-02291, which propagates out of `calculate_payroll`. Batches of 50 are already committed (`:324-326`), and the run is left `CALCULATING` forever.
- **Impact:** A single employee with missing tax info or salary aborts payroll for everyone after them, and leaves a half-populated run that RACE-04 will then double on re-run.
- **Recommendation:** Write errors to a dedicated `PAYROLL_ERRORS` table (no FK to elements), or seed an `ERROR` pseudo-element. Mark the run `ERROR` in an outer handler.

### DATA-05: `rehire_employee` Is Always Rejected by `TRG_EMP_BEFORE_UPDATE` (HIGH)

- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:750-793` vs `plsql/triggers/trg_employees.sql:69-74`
- **Code:**
  ```sql
  -- Package
  UPDATE EMPLOYEES SET EMPLOYMENT_STATUS = 'ACTIVE', HIRE_DATE = p_rehire_date, ... WHERE EMP_ID = p_emp_id;
  -- Trigger
  -- Prevent reactivation of terminated employees via direct UPDATE
  -- (should go through PKG_EMPLOYEE.rehire_employee instead)
  IF :OLD.EMPLOYMENT_STATUS = 'TERMINATED' AND :NEW.EMPLOYMENT_STATUS = 'ACTIVE' THEN
      RAISE_APPLICATION_ERROR(-20503, ...);
  ```
- **Issue:** The trigger cannot tell the sanctioned rehire path from a direct update, so the only rehire API is blocked by design. `rehire_employee` also does not lock the row, does not check that the employee is actually `TERMINATED`, overwrites the original `HIRE_DATE` (losing tenure used for leave eligibility, `PKG_LEAVE.pkb:108`), and does not validate `p_job_id` or the salary range.
- **Impact:** Rehires are impossible, and the workarounds (direct DML with the trigger disabled) bypass every control.
- **Recommendation:** Let the package set a session flag or context that the trigger checks, or move the rule into the package and drop it from the trigger. Add `ORIGINAL_HIRE_DATE` / `REHIRE_DATE` columns, and lock and validate state.

### DATA-06: Leave Audit Trigger Violates `CHK_AUDIT_ACTION` and Column Length (HIGH)

- **Location:** `plsql/triggers/trg_audit.sql:47-59` vs `schema/tables/04_performance_tables.sql:96`, `:104`
- **Code:**
  ```sql
  PKG_AUDIT.log_action('LEAVE_REQUESTS', :NEW.REQUEST_ID, 'STATUS_CHANGE', ...);
  -- ACTION_TYPE VARCHAR2(10) NOT NULL
  -- CONSTRAINT CHK_AUDIT_ACTION CHECK (ACTION_TYPE IN ('INSERT', 'UPDATE', 'DELETE'))
  ```
- **Issue:** `'STATUS_CHANGE'` is 13 characters (ORA-12899) and not in the check list (ORA-02290). `PKG_AUDIT.log_action` swallows the error (ARCH-02).
- **Impact:** **No leave approval, rejection or cancellation has ever been audited**, and nothing signals the failure.
- **Recommendation:** Pass `'UPDATE'` and put the status transition in `OLD_VALUES`/`NEW_VALUES`, or widen the column and constraint. Fix ARCH-02 so the next mismatch is visible.

### DATA-07: `VW_LEAVE_SUMMARY.AVAILABLE` Contradicts the Table's Virtual Column (HIGH)

- **Location:** `schema/views/hrms_views.sql:96` vs `schema/tables/03_leave_tables.sql:47`; also `plsql/packages/PKG_LEAVE.pkb:567`, `:572`
- **Code:**
  ```sql
  -- Table (virtual column)
  AVAILABLE GENERATED ALWAYS AS (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL
  -- View
  lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE
  -- process_carryover
  lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS REMAINING
  ```
- **Issue:** The view re-derives `AVAILABLE` without `- PENDING` instead of selecting `lb.AVAILABLE`. Year-end carryover also ignores pending days, so pending requests are both carried over and later moved to `USED`.
- **Impact:** Employees and managers see inflated balances, and carryover over-credits days that are already committed to requests.
- **Recommendation:** Select `lb.AVAILABLE` in the view and use it in `process_carryover`. Never re-derive a generated column.

### DATA-08: `PAYROLL_RUNS` Totals Omit `BENEFIT` Deductions (HIGH)

- **Location:** `plsql/packages/PKG_PAYROLL.pkb:336-341` vs `:504-538`, `:858-860`; `schema/views/hrms_views.sql:115-116`
- **Code:**
  ```sql
  TOTAL_DEDUCTIONS = (... WHERE ... ELEMENT_TYPE IN ('DEDUCTION', 'TAX') ...),
  TOTAL_NET = (SELECT NVL(SUM(CASE WHEN ELEMENT_TYPE = 'EARNING' THEN AMOUNT
                                   WHEN ELEMENT_TYPE IN ('DEDUCTION', 'TAX') THEN -ABS(AMOUNT)
                                   ELSE 0 END), 0) ...
  -- but deductions are inserted with ded_rec.ELEMENT_TYPE IN ('DEDUCTION', 'BENEFIT')
  ```
- **Issue:** Medical, dental, vision and life (`BENEFIT`, element IDs 201–204) are written as negative detail rows but excluded from the run header totals. The view and pay register include them (`SUM(pd.AMOUNT)`).
- **Impact:** Run-level `TOTAL_NET` is overstated by the total benefit premiums. GL postings or bank funding based on the header disagree with the register and employee payslips.
- **Recommendation:** Define one net-pay formula (preferably `SUM(AMOUNT)` over non-error rows, with the sign convention enforced by a check constraint) and reuse it in the package, view and register.

### DATA-09: Partial Commits Leave Payroll Half-Calculated (HIGH)

- **Location:** `plsql/packages/PKG_PAYROLL.pkb:292`, `:322-326`, `:346`
- **Code:**
  ```sql
  COMMIT;                                   -- before processing
  ...
  -- ISSUE: Partial commits mean a failure leaves payroll half-calculated
  IF MOD(v_emp_count, 50) = 0 THEN COMMIT; END IF;
  ```
- **Issue:** The run is not atomic. `v_emp_count` only increments on success, so after an error `MOD(...,50)=0` can hold for several iterations in a row, or never. Commit points are unpredictable.
- **Impact:** A crash or error mid-run leaves some employees calculated and others not, with no restart marker.
- **Recommendation:** Use one transaction per run with set-based processing (PERF-03), or add explicit checkpoint and restart state (`PAYROLL_RUN_EMPLOYEES` with per-employee status).

### DATA-10: `VW_PAYROLL_LATEST` Is Not "Per Employee" (MEDIUM)

- **Location:** `schema/views/hrms_views.sql:105-129`
- **Code:**
  ```sql
  -- Latest payroll run details per employee
  WHERE pr.RUN_ID = (SELECT MAX(pr2.RUN_ID) FROM PAYROLL_RUNS pr2 WHERE pr2.STATUS = 'APPROVED')
  ```
- **Issue:** The view selects the globally latest approved run. If that is a `BONUS` or `SUPPLEMENTAL` run, only the employees in it appear, and everyone else vanishes. `MAX(RUN_ID)` also depends on sequence order rather than period dates, and `PAID` runs are excluded.
- **Impact:** Payslip and self-service screens built on the view show wrong or missing data.
- **Recommendation:** Use `ROW_NUMBER() OVER (PARTITION BY pd.EMP_ID ORDER BY pp.END_DATE DESC, pr.RUN_ID DESC)` across `APPROVED`/`PAID` regular runs.

### DATA-11: Soft-Delete Semantics Inconsistent (MEDIUM)

- **Location:** `plsql/triggers/trg_employees.sql:114-130`; `schema/views/hrms_views.sql:54`, `:80`, `:103`; `plsql/packages/PKG_PAYROLL.pkb:299-300`; `plsql/triggers/trg_employees.sql:45-48`
- **Code:**
  ```sql
  -- TRG_EMP_AFTER_DELETE
  -- Soft delete: instead of actual deletion, marks record as inactive
  CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
  BEFORE DELETE ON HRMS.EMPLOYEES
  ... RAISE_APPLICATION_ERROR(-20504, 'Direct deletion not allowed. ...');
  ```
- **Issue:** The header, trigger name and comment all disagree with the behaviour: it neither soft-deletes nor is an `INSTEAD OF` trigger. "Inactive" is represented two ways (`ACTIVE_FLAG` and `EMPLOYMENT_STATUS`) and they are filtered inconsistently. Views use only status, payroll uses both, email uniqueness uses only the flag, and the Forms workaround sets the flag without the status.
- **Impact:** An employee with `ACTIVE_FLAG='N'` and `EMPLOYMENT_STATUS='ACTIVE'` still appears in views and the org chart and can still log in (SEC-01 checks only status), but is excluded from payroll.
- **Recommendation:** Pick one lifecycle column, derive the other (virtual column or check `ACTIVE_FLAG = CASE WHEN STATUS='TERMINATED' THEN 'N' ELSE 'Y' END`), rename the trigger, and route "delete" through `terminate_employee`.

### DATA-12: Email Uniqueness Is Not Enforced by Any Constraint (MEDIUM)

- **Location:** `plsql/triggers/trg_employees.sql:40-54` vs `schema/tables/01_core_tables.sql:133-143`
- **Code:**
  ```sql
  -- Validate email uniqueness (also enforced by unique constraint, but
  -- this trigger provides a better error message)
  SELECT COUNT(*) INTO v_count FROM EMPLOYEES WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL) AND ACTIVE_FLAG = 'Y';
  ```
- **Issue:** There is no unique constraint or index on `EMAIL`; the only UK is `EMP_NUMBER`. The check is `BEFORE INSERT` only, so updates can create duplicates. It is not concurrency-safe. Multi-row `INSERT ... SELECT` raises ORA-04091 (mutating table).
- **Impact:** Duplicate login identifiers, which is the root cause of SEC-06.
- **Recommendation:** Clean up duplicates, then `CREATE UNIQUE INDEX UX_EMP_EMAIL ON EMPLOYEES (CASE WHEN ACTIVE_FLAG='Y' THEN UPPER(EMAIL) END)`, and drop the trigger query.

### DATA-13: Carryover Overwrites Opening Balance and Can Double-Expire (MEDIUM)

- **Location:** `plsql/packages/PKG_LEAVE.pkb:558-603`, `:610-623`; `PKG_LEAVE.pks:10`
- **Code:**
  ```sql
  UPDATE LEAVE_BALANCES SET CARRYOVER_FROM_PREV = v_carryover, OPENING_BALANCE = v_carryover, ...
  ...
  UPDATE LEAVE_BALANCES SET ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV, CARRYOVER_FROM_PREV = 0 ...
  ```
- **Issue:** `process_carryover` replaces the next year's `OPENING_BALANCE` instead of adding to it. Re-running `process_carryover` after `expire_carryover` restores `CARRYOVER_FROM_PREV`, and the next expiry subtracts it again (the "double-expire" in the spec header). There is no run marker.
- **Impact:** Leave balances are silently wrong after year-end re-runs.
- **Recommendation:** Add a `LEAVE_YEAR_END_RUNS` idempotency table, compute carryover as a separate `CARRYOVER` column feeding `AVAILABLE`, and never overwrite the opening balance.

### DATA-14: `USER_SESSIONS.USERNAME` and `AUDIT_LOG.CHANGED_BY` Are Shorter Than `EMPLOYEES.EMAIL` (MEDIUM)

- **Location:** `plsql/packages/PKG_SECURITY.pkb:66-72`, `:77` vs `schema/tables/04_performance_tables.sql:99`, `:156`; `schema/tables/01_core_tables.sql:109`
- **Code:**
  ```sql
  INSERT INTO USER_SESSIONS (SESSION_ID, EMP_ID, USERNAME, ...) VALUES (v_session_id, v_emp_id, p_username, ...);
  PKG_AUDIT.log_action('USER_SESSIONS', v_session_id, 'INSERT', p_username);
  -- USERNAME VARCHAR2(30), CHANGED_BY VARCHAR2(30), EMAIL VARCHAR2(100)
  ```
- **Issue:** The username is the email address. Any email longer than 30 characters makes login fail with ORA-12899, and the audit write fails silently. Every `CREATED_BY`/`MODIFIED_BY VARCHAR2(30)` populated from `p_user` has the same problem. Current seed emails reach 29 characters.
- **Impact:** Some employees cannot log in, with a latent failure for new hires with long names.
- **Recommendation:** Store `EMP_ID` (or a short login ID) in the session and audit rows, or widen the columns to 128 to match `USER` / `SYS_CONTEXT` limits.

### DATA-15: Duplicate Audit and History Writers (Package + Trigger) (MEDIUM)

- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:285-305`, `:713-722`; `plsql/triggers/trg_employees.sql:76-110`; `plsql/triggers/trg_audit.sql:10-40`, `:66-84`; `plsql/packages/PKG_PAYROLL.pkb:19` (`create_salary_record`)
- **Code:**
  ```sql
  log_history(p_emp_id => p_emp_id, p_change_type => 'TERMINATION', ...);   -- package
  PKG_AUDIT.log_action('EMPLOYEES', p_emp_id, 'UPDATE', p_user);           -- package
  -- plus TRG_EMP_BEFORE_UPDATE -> EMPLOYEE_HISTORY ('STATUS_CHANGE')
  -- plus TRG_SALARY_AUDIT      -> PKG_AUDIT.log_action('SALARY_RECORDS', ...)
  ```
- **Issue:** The same business event is recorded twice in different shapes, one structured and one free-text. The copies can disagree because one is autonomous and one is not.
- **Impact:** Double-counted history in tenure and turnover reports, and ambiguous audit evidence.
- **Recommendation:** Choose one writer per concern (triggers for row-level audit, the package for business-event history) and remove the other.

### DATA-16: Cross-Year Leave Requests Debit Only the Start Year (MEDIUM)

- **Location:** `plsql/packages/PKG_LEAVE.pkb:176-182`, `:241-248`
- **Code:**
  ```sql
  UPDATE LEAVE_BALANCES SET PENDING = PENDING + v_total_days
  WHERE EMP_ID = p_emp_id AND LEAVE_TYPE_ID = p_leave_type_id
  AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
  ```
- **Issue:** A Dec 28 – Jan 5 request debits the whole amount from the old year. `SQL%ROWCOUNT` is not checked, so when no balance row exists the request is accepted and no balance moves. `get_leave_balance` returns 0 on `NO_DATA_FOUND`, but non-accrual types skip that check.
- **Impact:** Year-end balances are wrong, and requests exist that were never debited.
- **Recommendation:** Split days per calendar year, require `SQL%ROWCOUNT = 1` (or initialize balances first), and lock the rows (RACE-03).

### DATA-17: Half-Day Overlap and Observed-Holiday Handling (LOW)

- **Location:** `plsql/packages/PKG_LEAVE.pkb:45-62`, `:9-11`, `:23-29`; `plsql/packages/PKG_VALIDATION.pkb:90-94`; `PKG_LEAVE.pks:9`, `:11`
- **Code:**
  ```sql
  AND START_DATE <= p_end_date AND END_DATE >= p_start_date;   -- ignores HALF_DAY_PERIOD
  WHERE HOLIDAY_DATE = v_date                                   -- exact match only
  ```
- **Issue:** An AM plus PM half-day on the same date is flagged as an overlap, while two AM requests are indistinguishable. Holidays that fall on weekends are not shifted to the observed weekday.
- **Impact:** Legitimate half-day requests are rejected, and employees are charged leave on observed holidays.
- **Recommendation:** Include `HALF_DAY_PERIOD` in the overlap predicate, and add an `OBSERVED_DATE` column to `HOLIDAYS` (populated when a holiday falls on a weekend).

---

## 8. Consolidated Findings Table

| ID | Severity | Category | Location | Title |
|----|----------|----------|----------|-------|
| SEC-01 | CRITICAL | Security | PKG_SECURITY.pkb:30-80 | Authentication never verifies password |
| SEC-02 | CRITICAL | Security | PKG_SECURITY.pkb:7 | Hard-coded AES-256 key |
| SEC-03 | CRITICAL | Security | PKG_EMPLOYEE.pkb:445-498 | SQL injection in search_employees |
| SEC-04 | HIGH | Security | PKG_SECURITY.pkb:14-24 | Unsalted MD5 password hashing |
| SEC-05 | HIGH | Security | PKG_SECURITY.pkb:28-50 | No account lockout |
| SEC-06 | HIGH | Security | PKG_SECURITY.pkb:51-56; HRMS_LOGIN.xml:86-90 | Ambiguous identity for duplicate emails |
| SEC-07 | HIGH | Security | PKG_SECURITY.pkb:211-234 | change_password stub reports success |
| SEC-08 | HIGH | Security | PKG_NOTIFICATION.pkb:7-10 | Hard-coded SMTP, port 25, no TLS |
| SEC-09 | MEDIUM | Security | PKG_SECURITY.pkb:179-206 | SSN encryption: zero IV, masked errors |
| SEC-10 | MEDIUM | Security | PKG_NOTIFICATION.pkb:96-101 | SMTP header injection |
| SEC-11 | MEDIUM | Security | PKG_INTEGRATION.pks:12 | Cleartext integration credentials |
| SEC-12 | MEDIUM | Security | PKG_SECURITY.pkb:64, 85-121 | Predictable session IDs |
| SEC-13 | MEDIUM | Security | PKG_EMPLOYEE.pkb:737-739 | Terminated users keep sessions |
| SEC-14 | LOW | Security | PKG_SECURITY.pkb:46-50 | Timing-based user enumeration |
| SEC-15 | LOW | Security | trg_audit.sql:20-57; PKG_COMMON.pkb:24-54 | Hand-built JSON audit payloads |
| RACE-01 | HIGH | Race | PKG_EMPLOYEE.pkb:39-55 | MAX()+1 employee number |
| RACE-02 | HIGH | Race | PKG_PAYROLL.pkb:232-263 | Period status unlocked; duplicate runs |
| RACE-03 | HIGH | Race | PKG_LEAVE.pkb:141-182 | Leave balance check-then-act |
| RACE-04 | HIGH | Race | PKG_PAYROLL.pkb:271-292 | calculate_payroll has no state guard |
| RACE-05 | MEDIUM | Race | PKG_PAYROLL.pkb:583-600 | reverse_payroll has no state guard |
| RACE-06 | MEDIUM | Race | PKG_NOTIFICATION.pkb:78-113 | Queue rows not claimed |
| PERF-01 | HIGH | Performance | PKG_LEAVE.pkb:12-40 | Per-day holiday query loop |
| PERF-02 | MEDIUM | Performance | PKG_COMMON.pkb:132-165 | Day-by-day utility loops |
| PERF-03 | HIGH | Performance | PKG_PAYROLL.pkb:294-327 | Row-by-row payroll |
| PERF-04 | HIGH | Performance | hrms_views.sql:47-57; PKG_EMPLOYEE.pkb:822-840 | CONNECT BY, no NOCYCLE or index |
| PERF-05 | MEDIUM | Performance | PKG_NOTIFICATION.pkb:87-107 | SMTP connection per message |
| PERF-06 | MEDIUM | Performance | hrms_sequences.sql:9-49 | NOCACHE sequences |
| PERF-07 | MEDIUM | Performance | schema/ | No secondary or FK indexes |
| PERF-08 | LOW | Performance | PKG_LEAVE.pkb:459-552 | Nested accrual loop |
| PERF-09 | LOW | Performance | PKG_REPORTING.pks:9 | Stale denormalized reporting |
| VAL-01 | MEDIUM | Validation | HRMS_VALIDATION_LIB.pll.sql:21-41 | Email validation drift |
| VAL-02 | MEDIUM | Validation | PLL:96-99; HRMS_EMPLOYEE.xml:383; trg_employees.sql:35 | Hire-date limit drift |
| VAL-03 | HIGH | Validation | PKG_EMPLOYEE.pkb:220-240 | Salary range not enforced server-side |
| VAL-04 | MEDIUM | Validation | PLL:69-90; PKG_COMMON.pkb:277-280 | SSN validation drift |
| VAL-05 | LOW | Validation | PLL:47-63; PKG_COMMON.pkb:270-275 | Phone validation drift |
| VAL-06 | LOW | Validation | PKG_VALIDATION.pkb:6-15 | Date-range validation drift |
| VAL-07 | LOW | Validation | PKG_SECURITY.pkb:218 | Password length ignores config |
| DEP-01 | MEDIUM | Dependency | PKG_EMPLOYEE.pks:6-9; PKG_PAYROLL.pks:6-9 | Declared EMPLOYEE↔PAYROLL cycle |
| DEP-02 | MEDIUM | Dependency | PKG_SECURITY.pkb:75 | SECURITY→EMPLOYEE, latent reverse edge |
| DEP-03 | LOW | Dependency | *.pks headers | Stale dependency headers |
| ARCH-01 | HIGH | Architecture | PKG_AUDIT/EMPLOYEE/NOTIFICATION/COMMON | Autonomous transaction overuse |
| ARCH-02 | HIGH | Architecture | PKG_AUDIT.pkb:27-31 | Audit failures swallowed |
| ARCH-03 | MEDIUM | Architecture | PKG_AUDIT.pkb:33-47 | 365-day audit purge |
| ARCH-04 | MEDIUM | Architecture | PKG_INTEGRATION.pkb; PKG_PAYROLL.pkb:842 | UTL_FILE integrations |
| ARCH-05 | HIGH | Architecture | PKG_INTEGRATION.pkb:164-203 | Stub integrations report success |
| ARCH-06 | MEDIUM | Architecture | PKG_EMPLOYEE.pkb:737-739 | Stubbed termination side-effects |
| ARCH-07 | HIGH | Architecture | PKG_PAYROLL.pkb:7-14, 605-677, 437 | Hard-coded 2024 tax logic |
| ARCH-08 | MEDIUM | Architecture | PKG_COMMON.pkb:167-195 | Hard-coded fiscal year |
| ARCH-09 | MEDIUM | Architecture | trg_employees.sql:1-6; PLL:8-11 | Rules duplicated across four tiers |
| ARCH-10 | MEDIUM | Architecture | PKG_EMPLOYEE.pks:14-17 | Session state in package globals |
| ARCH-11 | LOW | Architecture | PKG_PAYROLL.pkb:409, 449, 854-857 | Magic element IDs |
| ARCH-12 | LOW | Architecture | PKG_LEAVE.pkb:550 et al. | DBMS_OUTPUT batch status |
| DATA-01 | CRITICAL | Data integrity | trg_employees.sql:76-110 | Trigger columns not in EMPLOYEE_HISTORY |
| DATA-02 | CRITICAL | Data integrity | trg_employees.sql:94, 106 | CHANGE_TYPE values violate CHECK |
| DATA-03 | CRITICAL | Data integrity | 01_reference_data.sql:11-201 | Seed script vs DDL mismatch |
| DATA-04 | CRITICAL | Data integrity | PKG_PAYROLL.pkb:306-319 | ELEMENT_ID=0 violates FK |
| DATA-05 | HIGH | Data integrity | PKG_EMPLOYEE.pkb:750-793 | Rehire blocked by trigger |
| DATA-06 | HIGH | Data integrity | trg_audit.sql:47-59 | Leave audit violates CHK_AUDIT_ACTION |
| DATA-07 | HIGH | Data integrity | hrms_views.sql:96 | View AVAILABLE omits PENDING |
| DATA-08 | HIGH | Data integrity | PKG_PAYROLL.pkb:336-341 | Run totals omit BENEFIT |
| DATA-09 | HIGH | Data integrity | PKG_PAYROLL.pkb:292, 322-326 | Partial payroll commits |
| DATA-10 | MEDIUM | Data integrity | hrms_views.sql:105-129 | VW_PAYROLL_LATEST not per employee |
| DATA-11 | MEDIUM | Data integrity | trg_employees.sql:114-130 | Soft-delete inconsistencies |
| DATA-12 | MEDIUM | Data integrity | trg_employees.sql:40-54 | Email uniqueness not constrained |
| DATA-13 | MEDIUM | Data integrity | PKG_LEAVE.pkb:558-623 | Carryover overwrite / double-expire |
| DATA-14 | MEDIUM | Data integrity | PKG_SECURITY.pkb:66-77 | USERNAME/CHANGED_BY shorter than EMAIL |
| DATA-15 | MEDIUM | Data integrity | PKG_EMPLOYEE.pkb; trg_*.sql | Duplicate audit/history writers |
| DATA-16 | MEDIUM | Data integrity | PKG_LEAVE.pkb:176-182 | Cross-year leave debits start year |
| DATA-17 | LOW | Data integrity | PKG_LEAVE.pkb:45-62 | Half-day overlap / observed holidays |

---

## 9. Prioritized Migration Roadmap

### Phase 1 — Critical Security (release blocker)

| Order | Findings | Deliverable |
|------:|----------|-------------|
| 1 | SEC-01, SEC-04, SEC-05, SEC-07, SEC-14 | `USER_CREDENTIALS` with PBKDF2/SSO, constant-time verify, lockout, working `change_password` |
| 2 | SEC-02, SEC-09 | Rotate the SSN key into a Wallet/Vault or TDE, re-encrypt with random IVs, purge the key from Git history |
| 3 | SEC-03 | Bind-variable rewrite of `search_employees`, plus a CI scan rule |
| 4 | SEC-06, DATA-12, DATA-14 | Unique `UPPER(EMAIL)` index, session keyed by `EMP_ID`, form uses server identity |
| 5 | SEC-08, SEC-10, SEC-11, SEC-12, SEC-13, ARCH-10 | TLS/AUTH SMTP from config, header sanitization, secrets out of `SYSTEM_PARAMETERS`, random session tokens in an app context, session revocation on termination |

**Exit criteria:** penetration re-test passes, and no secrets in source or `SYSTEM_PARAMETERS`.

### Phase 2 — Data Integrity and Concurrency

| Order | Findings | Deliverable |
|------:|----------|-------------|
| 1 | DATA-01, DATA-02, DATA-05, DATA-15 | Remove history writes from `TRG_EMP_BEFORE_UPDATE`, one history writer, working rehire path |
| 2 | DATA-03 | Fix seed column names, add `WHENEVER SQLERROR EXIT`, CI install of schema+seed in Oracle Free |
| 3 | DATA-04, DATA-09, RACE-04, RACE-05, RACE-02 | `PAYROLL_ERRORS` table, atomic or checkpointed runs, guarded status transitions, locked period check, unique run per period/type |
| 4 | DATA-08, DATA-10, ARCH-07, ARCH-11 | Single net-pay formula, per-employee latest-pay view, `TAX_BRACKETS`-driven tax with pre-tax handling, element lookup by code |
| 5 | DATA-06, ARCH-01, ARCH-02, ARCH-03 | Audit in-transaction, failures surfaced, retention by configuration with archive |
| 6 | RACE-01, RACE-03, RACE-06, DATA-07, DATA-13, DATA-16, DATA-17 | `SEQ_EMP_NUMBER`, locked leave balance workflow, `SKIP LOCKED` queue, `AVAILABLE` from the virtual column, idempotent year-end, per-year split |
| 7 | DATA-11 | Single lifecycle column and delete semantics |

**Exit criteria:** every object compiles with zero `USER_ERRORS`, schema+seed installs cleanly in CI, and payroll and leave regression suites pass under concurrent load.

### Phase 3 — Performance

| Order | Findings | Deliverable |
|------:|----------|-------------|
| 1 | PERF-07 | `schema/indexes/` with FK, lookup and queue indexes |
| 2 | PERF-03, PERF-08 | Set-based payroll and accrual (`BULK COLLECT`/`FORALL`/`MERGE`), YTD summary table |
| 3 | PERF-01, PERF-02 | `BUSINESS_CALENDAR` table, single business-day implementation |
| 4 | PERF-04 | `NOCYCLE`, manager index, closure table or MV for the org chart |
| 5 | PERF-05, PERF-06, PERF-09 | Batched SMTP or mail service, `CACHE` on sequences, real-time MVs for reporting |

**Exit criteria:** a 10k-employee payroll completes within the batch window, and org-chart and login p95 are under 1 s.

### Phase 4 — Modernization

| Order | Findings | Deliverable |
|------:|----------|-------------|
| 1 | VAL-01…VAL-07, ARCH-09 | `PKG_VALIDATION` as the single rule engine, PLL/Forms delegate to it, declarative constraints in DDL |
| 2 | DEP-01, DEP-02, DEP-03 | `PKG_COMPENSATION` extraction, app-context session, generated dependency docs |
| 3 | ARCH-04, ARCH-05, ARCH-06 | Outbox and event-driven integrations (ORDS/REST/AQ) replacing UTL_FILE, implemented off-boarding workflow |
| 4 | ARCH-08, ARCH-12, SEC-15 | Configurable fiscal calendar, structured job logging, native JSON |
| 5 | — | Forms 12c to web UI (APEX or SPA over ORDS), strangler-fig by module: Login → Employee → Leave → Payroll |

**Exit criteria:** business logic has a single server-side home, and Forms modules are retired one by one behind stable APIs.

---

## Appendix A — Verification Notes

- **Trigger/DDL and seed/DDL:** a script parsed every `CREATE TABLE HRMS.<t> (...)` block and every `INSERT INTO <t> (<cols>)` / `UPDATE <t> SET <col> =` in `plsql/`, `forms/` and `data/seed/`. Only the four statements groups in Section 7 have unknown columns.
- **CHECK constraints:** literal values in `PKG_*`/trigger DML were compared with `CHK_*` constraints. The mismatches are DATA-02, DATA-04 (FK) and DATA-06.
- **Dependency graph:** built from `PKG_<name>.` references in `*.pkb` bodies, and compared with the `Dependencies:` headers in `*.pks`.
- **Lint:** `sqlfluff lint --dialect oracle .` (sqlfluff 3.2.5) exits 1 with 1,047 violations across 9 SQL files, all pre-existing. They are mostly `CP02` capitalisation, plus `PRS` parse errors on PL/SQL blocks and the `GENERATED ALWAYS AS ... VIRTUAL` column in `03_leave_tables.sql`. This change touches no SQL files.
- **XML:** `find forms/xml-exports -name '*.xml' -exec xmllint --noout {} +` passes.
- **Not verified at runtime:** no Oracle instance is available in this environment. ORA-error outcomes are inferred from Oracle semantics for invalid triggers (ORA-04098), missing columns (ORA-00904), check/FK violations (ORA-02290/ORA-02291) and value length (ORA-12899).
