# Technical Debt Report — HRMS (Oracle Forms 12c / PL/SQL)

Repository: `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
Scope: `plsql/` (packages, triggers), `schema/` (tables, views, sequences), `forms/` (XML exports, PLL libraries), `data/seed/`
Method: static analysis of the source in this repository. Every finding cites a file and current line numbers. Findings are classified as **Confirmed** (provable from code/DDL in this repo) or **Risk** (design weakness whose impact depends on runtime data/config). Comments in the source such as `-- VULNERABILITY` or `-- BUG` were treated as claims to verify, not as facts.

---

## 1. Executive Summary

The codebase is a legacy Oracle Forms/PL/SQL HRMS with 10 packages, 2 trigger files, 4 table DDL scripts, a view script, a sequence script, 5 form exports and 2 PLL libraries. Analysis produced **51 findings**.

Three classes of problem dominate:

1. **Authentication is not implemented.** `PKG_SECURITY.authenticate` accepts a password argument, never compares it to anything, and returns a valid session for any existing active e-mail address. Password hashing that does exist is unsalted MD5, and the AES key is a literal in the package body.
2. **Code and schema have diverged to the point of runtime failure.** The employee history trigger inserts six column names that do not exist in `EMPLOYEE_HISTORY`; the payroll error handler inserts `ELEMENT_ID = 0`, which violates `FK_PD_ELEMENT`; `rehire_employee` cannot fire history logging for the same reason. These are not stylistic issues — the affected statements cannot execute.
3. **Validation is implemented three times with three different rule sets** (PLL library, `PKG_VALIDATION`/`PKG_COMMON`, database triggers), so the answer to "is this record valid?" depends on which entry point is used.

### Severity counts

| Severity | Count |
|---|---|
| CRITICAL | 9 |
| HIGH | 15 |
| MEDIUM | 20 |
| LOW | 7 |
| **Total** | **51** |

### Category breakdown

| Category | Prefix | Findings | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|---|---|
| Security | SEC | 14 | 4 | 3 | 7 | 0 |
| Race conditions | RACE | 4 | 0 | 3 | 1 | 0 |
| Performance | PERF | 8 | 0 | 1 | 5 | 2 |
| Validation drift | DRIFT | 6 | 0 | 3 | 1 | 2 |
| Circular dependencies | CIRC | 2 | 0 | 1 | 0 | 1 |
| Architecture | ARCH | 9 | 2 | 3 | 3 | 1 |
| Data integrity | DATA | 8 | 3 | 1 | 3 | 1 |

### Top 5 by remediation urgency

| # | ID | Finding |
|---|---|---|
| 1 | SEC-01 | `authenticate` never verifies the password — any known e-mail logs in |
| 2 | ARCH-01 | `TRG_EMP_HISTORY` inserts non-existent columns — all status/dept/job updates fail |
| 3 | DATA-01 | Payroll error handler violates `FK_PD_ELEMENT` — one bad employee aborts the run |
| 4 | SEC-04 | Unbound dynamic SQL in `search_employees` — injectable from the employee search form |
| 5 | SEC-03 | Hard-coded AES-256 key in `PKG_SECURITY.pkb` |

---

## 2. Security (SEC)

### SEC-01 — `authenticate` never verifies the password *(CRITICAL, Confirmed)*

`plsql/packages/PKG_SECURITY.pkb:30-80`

```sql
    FUNCTION authenticate(
        p_username   IN VARCHAR2,
        p_password   IN VARCHAR2,
        p_ip_address IN VARCHAR2 DEFAULT NULL
    ) RETURN NUMBER IS
        v_emp_id     NUMBER;
        v_session_id NUMBER;
        v_stored_hash VARCHAR2(200);
        v_input_hash  VARCHAR2(200);
    BEGIN
        -- Look up user
        BEGIN
            SELECT EMP_ID INTO v_emp_id
            FROM EMPLOYEES
            WHERE UPPER(EMAIL) = UPPER(p_username)
...
        -- NOTE: In the real system, passwords are stored in a separate
        -- USER_CREDENTIALS table. For this legacy codebase, we simulate
        -- authentication against a simplified model.

        -- Create session
        SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
        INSERT INTO USER_SESSIONS (...) VALUES (v_session_id, v_emp_id, p_username, SYSDATE, ...);
```

**Issue.** `v_stored_hash` and `v_input_hash` are declared (lines 37-38) and never assigned or compared. `hash_password` is never called from `authenticate`. Control flows straight from the username lookup to session creation, so `p_password` is unused.
**Impact.** Complete authentication bypass. Any user who knows any active employee's e-mail address obtains a valid `SESSION_ID` and, through `PKG_EMPLOYEE.set_session_context` (line 75), that employee's application identity — including HR and payroll roles. This supersedes every other login-related weakness below.
**Recommendation.** Implement credential storage (`USER_CREDENTIALS` with per-user salt) and make `authenticate` fail closed: fetch the stored verifier, compute the candidate, compare in constant time, and only then create the session. Until it is fixed, treat this system as having no access control.

### SEC-02 — Unsalted MD5 password hashing *(CRITICAL, Confirmed)*

`plsql/packages/PKG_SECURITY.pkb:77-87`

```sql
    FUNCTION hash_password(
        p_password IN VARCHAR2
    ) RETURN VARCHAR2 IS
    BEGIN
        RETURN RAWTOHEX(
            DBMS_CRYPTO.HASH(
                UTL_RAW.CAST_TO_RAW(p_password),
                DBMS_CRYPTO.HASH_MD5
            )
        );
    END hash_password;
```

**Issue.** MD5 is a fast, collision-broken digest with no salt and no work factor. Identical passwords produce identical hashes, so the hash column leaks password reuse across employees.
**Impact.** Any leak of the hash store is equivalent to a leak of the passwords; commodity hardware exhausts common-password space in minutes and rainbow tables cover the rest.
**Recommendation.** Move verification out of the database into a service that uses bcrypt/scrypt/Argon2 with a per-user salt and tunable cost. If verification must stay in PL/SQL, use PBKDF2 (`DBMS_CRYPTO.HASH` in a keyed loop is not a substitute) and force a password reset for all users at cutover.

### SEC-03 — Hard-coded encryption key in package body *(CRITICAL, Confirmed)*

`plsql/packages/PKG_SECURITY.pkb:69-70`

```sql
    -- VULNERABILITY: Encryption key hard-coded in source
    c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```

**Issue.** The AES key used by `encrypt_ssn`/`decrypt_ssn` is a literal in source control, readable by anyone with `SELECT` on `ALL_SOURCE` or read access to this repository.
**Impact.** SSNs and any other data encrypted with this key are effectively cleartext to developers, DBAs, contractors, and anyone with a repo clone. The key cannot be rotated without a code deployment and a full re-encryption.
**Recommendation.** Move to Oracle TDE for column encryption, or hold the key in an external KMS/wallet and inject it at runtime. Rotate the key and re-encrypt as part of remediation — the current key must be considered permanently compromised.

### SEC-04 — SQL injection via unbound dynamic SQL in `search_employees` *(CRITICAL, Confirmed)*

`plsql/packages/PKG_EMPLOYEE.pkb:442-500`

```sql
        IF p_last_name IS NOT NULL THEN
            v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
        END IF;
...
        IF p_dept_id IS NOT NULL THEN
            v_sql := v_sql || 'AND e.DEPT_ID = ' || p_dept_id || ' ';
        END IF;
...
        IF p_hire_date_from IS NOT NULL THEN
            v_sql := v_sql || 'AND e.HIRE_DATE >= TO_DATE(''' ||
                     TO_CHAR(p_hire_date_from, 'YYYY-MM-DD') || ''', ''YYYY-MM-DD'') ';
        END IF;

        OPEN p_cursor FOR v_sql;
```

**Issue.** Five caller-supplied string parameters (`p_last_name`, `p_first_name`, `p_status`, `p_location_code`, plus `p_dept_id` numerically) are concatenated into the statement with no bind variables and no escaping. `OPEN p_cursor FOR v_sql` executes the result. The employee search form passes user keystrokes straight through (`forms/xml-exports/HRMS_EMPLOYEE.xml`, search block).
**Impact.** A payload such as `X'' OR ''1''=''1` in the surname field disables the filter; `UNION ALL SELECT` reaches any table the `HRMS` schema can read, including `USER_SESSIONS` and encrypted SSN columns. The procedure runs with the package owner's privileges, so this is a privilege-escalation path, not just a data-leak path.
**Recommendation.** Rewrite with bind variables: build the text with `:1`-style placeholders and pass values via `OPEN ... FOR v_sql USING ...`, or use a single static query with `(:p IS NULL OR col = :p)` predicates. Never interpolate identifiers or values from the client.

### SEC-05 — Password transmitted and handled in cleartext *(HIGH, Confirmed)*

`forms/xml-exports/HRMS_LOGIN.xml:10-13`, `:45-51`, `:74-79`

```xml
  Known Issues:
    - Password field transmitted in cleartext (Forms applet limitation)
...
    <Item Name="PASSWORD" ItemType="Text Field" DataType="Char"
          MaximumLength="100" Required="Yes"
          ConcealData="Yes"/>
...
        v_session_id := PKG_SECURITY.authenticate(
            :LOGIN.USERNAME,
            :LOGIN.PASSWORD,
            GET_APPLICATION_PROPERTY(CLIENT_HOST)
        );
```

**Issue.** `ConcealData="Yes"` only masks the characters on screen. The value crosses the Forms tier as a plain PL/SQL argument and, absent enforced TLS on the Forms listener, crosses the network unencrypted. It is also a candidate for capture in trace files and `V$SQL` bind capture.
**Impact.** Credential interception on the internal network; passwords appearing in diagnostic artifacts.
**Recommendation.** Enforce HTTPS/TLS end-to-end on the Forms and WebLogic tiers, and stop passing raw passwords into the database at all — authenticate at the application tier and pass only a token to PL/SQL.

### SEC-06 — No account lockout or failed-attempt tracking *(HIGH, Confirmed)*

`plsql/packages/PKG_SECURITY.pks:10-14`, `plsql/packages/PKG_SECURITY.pkb:30-80`, `forms/xml-exports/HRMS_LOGIN.xml:12`

```sql
--   - Password stored as MD5 hash (should be bcrypt/scrypt)
--   - Session timeout check uses DB server time, not app server time
--   - No account lockout after failed attempts
--   - DBMS_CRYPTO key hard-coded in package body
```

**Issue.** `authenticate` contains no counter, no `FAILED_ATTEMPTS` column update, no lockout branch, and no delay. Nothing rate-limits repeated calls.
**Impact.** Unlimited online guessing against every account, and unlimited enumeration of valid usernames (see SEC-07).
**Recommendation.** Add a credentials table with `FAILED_ATTEMPTS`, `LOCKED_UNTIL`, and `LAST_FAILED_DATE`; lock after N failures with exponential backoff; alert on bursts. Ideally delegate to an IdP that already implements this.

### SEC-07 — Username enumeration and timing oracle *(HIGH, Confirmed)*

`plsql/packages/PKG_SECURITY.pkb:41-57`

```sql
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
            WHEN TOO_MANY_ROWS THEN
                SELECT MIN(EMP_ID) INTO v_emp_id
                FROM EMPLOYEES
                WHERE UPPER(EMAIL) = UPPER(p_username)
                AND EMPLOYMENT_STATUS = 'ACTIVE';
        END;
```

**Issue.** The generic error message is correct, but the *work performed* differs sharply between a missing user (single indexed lookup, immediate raise) and an existing user (lookup plus sequence fetch, insert, context call, audit insert). The `TOO_MANY_ROWS` branch silently authenticates as the lowest `EMP_ID` sharing an e-mail address.
**Impact.** Response-time differences reveal which e-mail addresses are valid HRMS accounts; duplicate e-mail records resolve to an arbitrary employee's identity (see DATA-04).
**Recommendation.** Perform a constant-cost dummy verification on the unknown-user path, and make duplicate credentials an error rather than a `MIN()` pick.

### SEC-08 — Session timeout evaluated against database clock only *(MEDIUM, Confirmed)*

`plsql/packages/PKG_SECURITY.pkb:176-184`

```sql
        IF (SYSDATE - v_login_time) * 24 * 60 > c_session_timeout_min THEN
            UPDATE USER_SESSIONS SET
                SESSION_STATUS = 'EXPIRED',
                LOGOUT_TIME = SYSDATE
            WHERE SESSION_ID = p_session_id;
            RETURN FALSE;
        END IF;
```

**Issue.** Timeout is measured from `LOGIN_TIME` using `SYSDATE` (database server local time, no time zone). Sessions are only expired lazily, when `validate_session` happens to be called; there is no reaper job. Any clock skew or DST shift between app and database tiers moves the timeout by that amount.
**Impact.** Sessions can live past policy (or be cut short mid-transaction after a DST change); abandoned sessions stay `ACTIVE` indefinitely.
**Recommendation.** Store `LOGIN_TIME`/`LAST_ACTIVITY` as `TIMESTAMP WITH TIME ZONE`, compare against `SYSTIMESTAMP`, track idle rather than absolute age, and add a scheduled job that expires stale rows.

### SEC-09 — Password change is a stub that logs success *(MEDIUM, Confirmed)*

`plsql/packages/PKG_SECURITY.pkb:293-296`

```sql
        -- NOTE: Actual password update would go to USER_CREDENTIALS table
        -- This is a stub for the legacy system model

        PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
```

**Issue.** `change_password` writes an audit record asserting a credential change but updates nothing.
**Impact.** Users believe rotation happened; the audit trail asserts it happened; neither is true. Any incident response that relies on "password was rotated at T" is misled.
**Recommendation.** Implement the update or raise `ORA-20xxx 'not implemented'`. Never emit an audit record for an action that did not occur.

### SEC-10 — Hard-coded SMTP endpoint, unauthenticated port 25 *(MEDIUM, Confirmed)*

`plsql/packages/PKG_NOTIFICATION.pkb:6-10`

```sql
    c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
    c_smtp_port    CONSTANT NUMBER := 25;
    c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
    c_from_name    CONSTANT VARCHAR2(100) := 'HRMS System';
```

**Issue.** Relay host, port and sender identity are compile-time constants; the connection uses plain port 25 with no STARTTLS and no credentials (`UTL_SMTP.OPEN_CONNECTION` / `HELO` at lines 78-107).
**Impact.** Notification content — including payroll and leave details — traverses the network unencrypted. Environment promotion requires a code change, so a mis-promoted body can mail production employees from a test database.
**Recommendation.** Read host/port/sender from `SYSTEM_PARAMETERS` per environment, require TLS and authentication, and use an ACL-restricted network privilege for the schema.

### SEC-11 — FTP credentials stored in cleartext in a table *(MEDIUM, Risk)*

`plsql/packages/PKG_INTEGRATION.pks:7-11`

```sql
--   - GL posting uses flat file exchange (UTL_FILE) instead of API
--   - Benefits feed format is vendor-specific (ADP format)
--   - No retry logic for failed file transfers
--   - FTP credentials stored in SYSTEM_PARAMETERS table (cleartext)
```

**Issue.** The package documents plaintext transfer credentials in an application table. `SYSTEM_PARAMETERS` (see `schema/tables/01_core_tables.sql`) has no encryption and no column-level restriction, and any `SELECT` grant on it exposes the values. The credentials themselves are not present in this repository, so the exposure is documented rather than proven here.
**Impact.** Anyone with read access to reference data obtains credentials to the GL and benefits transfer endpoints, i.e. to outbound payroll data.
**Recommendation.** Move transfer secrets to a wallet/KMS, remove them from `SYSTEM_PARAMETERS`, rotate them, and switch to key-based SFTP.

### SEC-12 — Log payloads assembled by string concatenation *(MEDIUM, Confirmed)*

`plsql/packages/PKG_COMMON.pkb:24-25`, `:53-54`

```sql
            '{"package":"' || p_package || '","procedure":"' || p_procedure ||
            '","message":"' || REPLACE(SUBSTR(p_message, 1, 3000), '"', '\"') || '"}'
```

**Issue.** JSON is hand-built. Only `p_message` is partially escaped, and only for the double-quote character; `p_package` and `p_procedure` are unescaped, and backslashes, newlines and control characters are not handled anywhere.
**Impact.** Malformed JSON breaks downstream log parsing; attacker-controlled text can forge additional fields (log injection), corrupting the audit narrative.
**Recommendation.** Use `JSON_OBJECT(...)` (available in 19c) or bind columns individually instead of serialising by hand.

### SEC-13 — Login form swallows all exceptions *(MEDIUM, Confirmed)*

`forms/xml-exports/HRMS_LOGIN.xml:95-101`

```plsql
    EXCEPTION
        WHEN OTHERS THEN
            :LOGIN.ERROR_MSG := 'Invalid username or password.';
            :LOGIN.PASSWORD := NULL;
            GO_ITEM('LOGIN.PASSWORD');
            RAISE FORM_TRIGGER_FAILURE;
    END;
```

**Issue.** The handler covers the whole block, including `OPEN_FORM` and the `SELECT ... INTO :GLOBAL.current_emp_id`. A tablespace error, a missing privilege, or a failure opening `HRMS_MENU` is reported to the user as bad credentials, and nothing is logged.
**Impact.** Real outages present as mass authentication failure; no diagnostic trail exists for support. It also masks the `ROWNUM = 1` duplicate-e-mail path at line 90.
**Recommendation.** Catch only the authentication exception (`-20301`), log everything else via `HRMS_COMMON_LIB.handle_error`, and surface a distinct "system error" message.

### SEC-14 — Authorisation derived from job grade, not from roles *(MEDIUM, Risk)*

`plsql/packages/PKG_SECURITY.pks` (`has_permission`, `is_hr_admin`), `plsql/packages/PKG_SECURITY.pkb`

**Issue.** Permission checks are computed from organisational attributes (job grade / HR department membership) rather than from explicit role grants, and each caller decides whether to check at all. There is no central policy object and no negative grants.
**Impact.** A routine job-grade change silently confers or removes access to payroll data; a caller that forgets the check has none. This cannot be audited by inspecting a grant table.
**Recommendation.** Introduce explicit `ROLES`/`ROLE_PERMISSIONS`/`USER_ROLES` tables, evaluate access in one place, and make every entry point deny by default.

---

## 3. Race Conditions (RACE)

### RACE-01 — Employee number generated with `MAX()+1` *(HIGH, Confirmed)*

`plsql/packages/PKG_EMPLOYEE.pkb:39-55`

```sql
    FUNCTION generate_emp_number RETURN VARCHAR2 IS
        v_max_num NUMBER;
        v_new_number VARCHAR2(20);
    BEGIN
        SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
        INTO v_max_num
        FROM EMPLOYEES
        WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';

        v_new_number := c_emp_number_prefix || '-' || LPAD(v_max_num, 6, '0');

        RETURN v_new_number;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMPLOYEE.NEXTVAL, 6, '0');
    END generate_emp_number;
```

**Issue.** The read takes no lock, so two concurrent hires compute the same maximum and the same number. `schema/sequences/hrms_sequences.sql` already defines `SEQ_EMP_NUMBER` for exactly this purpose and it is unused on the normal path. The `WHEN OTHERS` fallback also draws from `SEQ_EMPLOYEE` (the surrogate-key sequence), so the two number spaces can collide. The full-table `MAX()` additionally makes hiring cost grow with headcount.
**Impact.** Duplicate `EMP_NUMBER` — blocked by `UK_EMP_NUMBER` in `schema/tables/01_core_tables.sql`, so the second concurrent hire fails with ORA-00001 and a meaningless message. If the constraint is ever dropped or deferred, duplicates reach payroll.
**Recommendation.** `RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0');` and delete the `WHEN OTHERS` fallback so genuine errors propagate.

### RACE-02 — Pay-period status checked without `FOR UPDATE` *(HIGH, Confirmed)*

`plsql/packages/PKG_PAYROLL.pkb:240-248`

```sql
        SELECT STATUS INTO v_status
        FROM PAY_PERIODS
        WHERE PERIOD_ID = p_period_id;

        IF v_status = 'CLOSED' THEN
            RAISE_APPLICATION_ERROR(-20102,
                'Cannot create run for closed period: ' || p_period_id);
        END IF;
```

**Issue.** Classic check-then-act: the status read is unlocked, and the subsequent `INSERT INTO PAYROLL_RUNS` is not protected against the period being closed in between. Nothing in the DDL prevents a run row from referencing a `CLOSED` period.
**Impact.** A payroll run created against a period closed microseconds earlier produces postings the period close has already reported to GL — a reconciliation break that is very hard to trace after the fact.
**Recommendation.** `SELECT STATUS INTO v_status FROM PAY_PERIODS WHERE PERIOD_ID = p_period_id FOR UPDATE;` inside the same transaction as the insert, and add a trigger or check that rejects new runs for non-`OPEN` periods.

### RACE-03 — Leave balance checked, then updated, with no lock *(HIGH, Confirmed)*

`plsql/packages/PKG_LEAVE.pkb:146-154` (check) and `:176-182` (update)

```sql
        -- Check balance (only for accrual-based leave types)
        IF v_leave_type.ACCRUAL_FLAG = 'Y' THEN
            v_balance := get_leave_balance(p_emp_id, p_leave_type_id);
            IF v_balance < v_total_days THEN
                RAISE_APPLICATION_ERROR(-20201,
                    'Insufficient leave balance. Available: ' || v_balance ||
                    ', Requested: ' || v_total_days);
            END IF;
        END IF;
```

**Issue.** `get_leave_balance` (`:369-387`) is a plain unlocked `SELECT`. Two requests submitted concurrently both observe the pre-request balance, both pass the check, and both then increment `PENDING`. The `LEAVE_BALANCES` DDL has no check constraint forbidding a negative available balance, so nothing catches it at the storage layer.
**Impact.** Employees can go negative on accrued leave; the overdraft only surfaces at year-end reconciliation or in a final settlement calculation.
**Recommendation.** Lock the balance row (`SELECT ... FOR UPDATE` on `LEAVE_BALANCES` keyed by emp/type/year) before the check and hold it through the `PENDING` update; add `CHECK (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING >= 0)` as a backstop.

### RACE-04 — Duplicate e-mail check in trigger is time-of-check/time-of-use *(MEDIUM, Confirmed)*

`plsql/triggers/trg_employees.sql:38-52`

**Issue.** The `BEFORE INSERT OR UPDATE` trigger counts rows with the same e-mail and raises if any exist. Two concurrent inserts each see zero and both proceed. As documented in ARCH-03, there is no unique constraint behind the check.
**Impact.** Duplicate e-mail addresses land in `EMPLOYEES`, which then feeds SEC-07's `TOO_MANY_ROWS` path and the login form's `ROWNUM = 1` — a user can be authenticated as a different employee.
**Recommendation.** Add `CONSTRAINT UK_EMP_EMAIL UNIQUE (EMAIL)` (after de-duplicating existing data) and let the constraint, not the trigger, enforce it.

---

## 4. Performance (PERF)

### PERF-01 — Per-day holiday query inside a day-by-day loop *(HIGH, Confirmed)*

`plsql/packages/PKG_LEAVE.pkb:10-34`

```sql
        WHILE v_date <= TRUNC(p_end_date) LOOP
            IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
                SELECT COUNT(*) INTO v_holiday_count
                FROM HOLIDAYS
                WHERE HOLIDAY_DATE = v_date
                AND ACTIVE_FLAG = 'Y'
                AND (LOCATION_CODE IS NULL OR LOCATION_CODE = p_location_code);
                ...
            END IF;
            v_date := v_date + 1;
        END LOOP;
```

**Issue.** One context switch and one query per weekday in the range. A one-year sabbatical request issues ~260 queries; the accrual batch calls this per employee per request.
**Impact.** Leave submission latency scales with request length, and year-end batches multiply it by headcount. This is the single largest avoidable cost in the leave module.
**Recommendation.** Fetch the applicable holidays once into a collection (or join against a generated date row source) and compute the count in a single SQL statement.

### PERF-02 — `business_days_between` iterates day by day *(MEDIUM, Confirmed)*

`plsql/packages/PKG_COMMON.pkb:132-146`

```sql
        WHILE v_date <= TRUNC(p_end_date) LOOP
            IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
                v_count := v_count + 1;
            END IF;
            v_date := v_date + 1;
        END LOOP;
```

**Issue.** Weekday counting is arithmetic and closed-form, but is implemented as a loop. Additionally the `NLS_DATE_LANGUAGE` override is applied per iteration.
**Impact.** O(range) CPU where O(1) suffices; noticeable when called inside tenure and accrual calculations across the whole employee base.
**Recommendation.** Replace with the closed form: whole weeks × 5 plus a small remainder adjustment derived from `TRUNC(date,'IW')`.

### PERF-03 — `add_business_days` iterates day by day *(MEDIUM, Confirmed)*

`plsql/packages/PKG_COMMON.pkb:151-165`

```sql
        WHILE v_added < p_days LOOP
            v_result := v_result + 1;
            IF TO_CHAR(v_result, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
                v_added := v_added + 1;
            END IF;
        END LOOP;
```

**Issue.** Same pattern in the inverse direction; also ignores holidays, unlike `PKG_LEAVE.calculate_business_days` (see DRIFT-04).
**Impact.** Unbounded loop cost for large `p_days`; SLA due dates computed here disagree with leave-module business days.
**Recommendation.** Compute the offset arithmetically and route holiday awareness through one shared function.

### PERF-04 — `CONNECT BY` org hierarchy view *(MEDIUM, Confirmed)*

`schema/views/hrms_views.sql:47-57`

```sql
CREATE OR REPLACE VIEW HRMS.VW_ORG_HIERARCHY AS
SELECT EMP_ID, EMP_NUMBER, FIRST_NAME || ' ' || LAST_NAME AS EMP_NAME,
       MANAGER_EMP_ID, DEPT_ID,
       LEVEL AS ORG_LEVEL,
       SYS_CONNECT_BY_PATH(FIRST_NAME || ' ' || LAST_NAME, ' > ') AS ORG_PATH,
       CONNECT_BY_ISLEAF AS IS_LEAF
FROM EMPLOYEES
WHERE EMPLOYMENT_STATUS = 'ACTIVE'
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
ORDER SIBLINGS BY LAST_NAME;
```

**Issue.** The view walks the entire active population and materialises `SYS_CONNECT_BY_PATH` and `ORDER SIBLINGS BY` for every row; predicates on a single employee usually cannot be pushed into the hierarchical walk. The filter is on `EMPLOYMENT_STATUS` only, while the rest of the codebase filters on `EMPLOYMENT_STATUS` *and* `ACTIVE_FLAG` (see DATA-07).
**Impact.** Full-hierarchy cost is paid even to answer "who is this person's manager", and `SYS_CONNECT_BY_PATH` risks ORA-01489 as names lengthen.
**Recommendation.** Replace with a recursive CTE that accepts a starting point, or maintain a materialised closure table refreshed on manager change.

### PERF-05 — SMTP connection opened per notification inside the loop *(MEDIUM, Confirmed)*

`plsql/packages/PKG_NOTIFICATION.pkb:78-107`

```sql
        FOR notif_rec IN (
            SELECT ... FROM NOTIFICATION_QUEUE WHERE STATUS = 'PENDING' ...
        ) LOOP
            BEGIN
                v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
                UTL_SMTP.HELO(v_connection, c_smtp_host);
                ...
                UTL_SMTP.QUIT(v_connection);
            END;
        END LOOP;
```

**Issue.** TCP connect, HELO handshake and QUIT are repeated for every queued message instead of once per batch.
**Impact.** Queue drain time is dominated by handshakes; a large batch (payroll notification fan-out) can look like a hung job and may trip connection-rate limits on the relay.
**Recommendation.** Open one connection before the loop, send all messages with `UTL_SMTP.RSET` between them, close it after, and reconnect only on error.

### PERF-06 — Payroll calculated employee-by-employee with periodic commits *(MEDIUM, Confirmed)*

`plsql/packages/PKG_PAYROLL.pkb:296-327`

```sql
        FOR emp_rec IN (SELECT e.EMP_ID FROM EMPLOYEES e WHERE ... ORDER BY e.EMP_ID) LOOP
            BEGIN
                calculate_employee_pay(p_run_id, emp_rec.EMP_ID, v_period_id, p_user);
                v_emp_count := v_emp_count + 1;
            EXCEPTION ...
            END;

            -- Commit every 50 employees to avoid long transactions
            -- ISSUE: Partial commits mean a failure leaves payroll half-calculated
            IF MOD(v_emp_count, 50) = 0 THEN
                COMMIT;
            END IF;
        END LOOP;
```

**Issue.** Row-at-a-time processing with per-row single-row DML inside `calculate_employee_pay`, plus a commit every 50 successes. The commit interval keys off `v_emp_count`, which is not incremented on error, so the interval drifts with failures.
**Impact.** Payroll runtime scales linearly with headcount at maximum context-switch cost, and there is no atomic unit: an abort leaves a partially calculated, already-committed run that must be reconciled by hand.
**Recommendation.** Restructure into set-based SQL / `FORALL` with `BULK COLLECT`, commit once per run, and record per-employee failures in a dedicated error table (see DATA-01) rather than in `PAYROLL_DETAILS`.

### PERF-07 — Almost all sequences are `NOCACHE` *(LOW, Confirmed)*

`schema/sequences/hrms_sequences.sql`

```sql
CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE HRMS.SEQ_EMP_HISTORY START WITH 1 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE HRMS.SEQ_EMP_NUMBER START WITH 1000 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE HRMS.SEQ_PAYROLL_DETAIL START WITH 1 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE HRMS.SEQ_NOTIFICATION START WITH 1 INCREMENT BY 1 NOCACHE;
...
CREATE SEQUENCE HRMS.SEQ_AUDIT START WITH 1 INCREMENT BY 1 CACHE 100;
```

**Issue.** `NOCACHE` forces a recursive update of `SYS.SEQ$` for every `NEXTVAL`. `SEQ_PAYROLL_DETAIL` and `SEQ_AUDIT` are the hottest sequences in the system; only `SEQ_AUDIT` is cached.
**Impact.** Serialisation on high-volume inserts (payroll detail rows, notification queue) and avoidable redo. `ORDER`ing/gap-free numbering is not a stated requirement anywhere in the schema comments.
**Recommendation.** `ALTER SEQUENCE ... CACHE 100` (or 1000 for payroll detail) for all non-user-facing surrogate keys; keep `NOCACHE` only where gapless numbering is a documented requirement.

### PERF-08 — Reporting reads denormalised tables refreshed nightly *(LOW, Confirmed)*

`plsql/packages/PKG_REPORTING.pks:8-10`

```sql
--   - Denormalized reporting tables refreshed nightly; stale during business hours
--   - Some reports use hard-coded fiscal year start (Oct 1)
```

**Issue.** Reporting is served from copies with a 24-hour staleness window and no refresh timestamp exposed to consumers.
**Impact.** Headcount and compensation reports contradict the transactional screens during the day, and users cannot tell how stale a number is.
**Recommendation.** Replace the copies with materialised views on a defined refresh schedule, and surface `LAST_REFRESH_DATE` on every report header.

---

## 5. Validation Drift (DRIFT)

### DRIFT-01 — Three different e-mail validation rules *(HIGH, Confirmed)*

Client: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:21-41`

```sql
    v_at_pos := INSTR(p_email, '@');
    IF v_at_pos = 0 OR v_at_pos = 1 OR v_at_pos = LENGTH(p_email) THEN
        RETURN FALSE;
    END IF;

    v_dot_pos := INSTR(p_email, '.', v_at_pos);
    IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
```

Server: `plsql/packages/PKG_COMMON.pkb:265-268`

```sql
    FUNCTION is_valid_email(p_email IN VARCHAR2) RETURN BOOLEAN IS
    BEGIN
        RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
    END is_valid_email;
```

**Issue.** The PLL performs positional `INSTR` checks and, notably, `RETURN TRUE` for NULL (line 25-27). The server uses a character-class regex. `PKG_VALIDATION.validate_email_format` (`plsql/packages/PKG_VALIDATION.pkb:50-55`) delegates to the server regex, and the employee form calls *that* (`forms/xml-exports/HRMS_EMPLOYEE.xml:376-380`) — so the PLL function is a third, divergent rule still attached to every form via `AttachedLibrary` (line 23).
**Impact.** `a b@x.y` passes the PLL and fails the server; `user@host.c` passes the PLL and fails the server. Forms that use the PLL path accept addresses the database later rejects, producing errors at commit rather than at entry, and notification delivery silently fails for addresses that were accepted somewhere upstream.
**Recommendation.** Delete `HRMS_VALIDATION_LIB.validate_email` and have it call `PKG_VALIDATION.validate_email_format`, so exactly one rule exists.

### DRIFT-02 — Future hire-date limit differs by layer: none / 90 days / 180 days *(HIGH, Confirmed)*

- PLL: `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:96-99` — no future date at all

```sql
    FUNCTION validate_date_not_future(p_date IN DATE) RETURN BOOLEAN IS
    BEGIN
        RETURN p_date IS NULL OR TRUNC(p_date) <= TRUNC(SYSDATE);
    END validate_date_not_future;
```

- Form: `forms/xml-exports/HRMS_EMPLOYEE.xml:382-386` — 90 days

```plsql
    ELSIF v_item = 'EMPLOYEE.HIRE_DATE' THEN
        IF :EMPLOYEE.HIRE_DATE > SYSDATE + 90 THEN
            MESSAGE('Hire date cannot be more than 90 days in the future');
            RAISE FORM_TRIGGER_FAILURE;
        END IF;
```

- Trigger: `plsql/triggers/trg_employees.sql:33-37` — 180 days

**Issue.** Three enforcement points, three limits, and no shared constant. Whichever layer a caller happens to traverse determines the rule.
**Impact.** A recruiter entering a 120-day-out start date is blocked in the form but the same value succeeds through a batch load or API path — an inconsistency users read as a bug and work around by loading data through the looser path. Conversely, PLL callers reject all legitimate future-dated hires.
**Recommendation.** Define one limit in `SYSTEM_PARAMETERS`, enforce it in `PKG_VALIDATION`, and have both the form and the trigger call that function.

### DRIFT-03 — Salary-range violation is a hard error in one path and a warning in another *(HIGH, Confirmed)*

Hard failure: `plsql/packages/PKG_VALIDATION.pkb:17-48`

```sql
        IF p_salary < v_min THEN
            RETURN 'Salary ' || TO_CHAR(p_salary, 'FM$999,999,990.00') ||
                   ' is below minimum for grade ' || v_grade_name || ...
```

Advisory only: `plsql/packages/PKG_EMPLOYEE.pkb` (`create_employee` salary check) logs a warning and proceeds.

**Issue.** `PKG_VALIDATION.validate_salary_for_grade` returns a blocking message, while the employee-creation path treats an out-of-band salary as a loggable warning. The PLL adds a third variant (DRIFT-05).
**Impact.** Out-of-band salaries enter through the creation path and are then rejected on any later edit, so records become uneditable without a data fix. Compensation-band compliance reporting cannot rely on the constraint holding.
**Recommendation.** Decide the policy once (blocking, or advisory with explicit override plus an approver recorded), implement it in `PKG_VALIDATION`, and call it from every write path.

### DRIFT-04 — Three business-day implementations with different holiday semantics *(MEDIUM, Confirmed)*

| Implementation | Weekends | Holidays | Location-aware |
|---|---|---|---|
| `PKG_COMMON.business_days_between` (`:132-146`) | yes | **no** | no |
| `PKG_LEAVE.calculate_business_days` (`:10-34`) | yes | yes | yes |
| `PKG_VALIDATION.is_business_day` (`:78-97`) | yes | yes | yes |

**Issue.** Three functions answer the same question. `PKG_COMMON` ignores the `HOLIDAYS` table entirely, so any caller using it counts public holidays as working days.
**Impact.** Tenure, SLA and accrual figures computed via `PKG_COMMON` disagree with leave deductions computed via `PKG_LEAVE` — the discrepancy grows by one day per holiday and appears as unexplained balance drift.
**Recommendation.** Keep one holiday-aware, location-aware implementation and make the other two thin wrappers around it.

### DRIFT-05 — PLL salary check documents a cache it does not use *(LOW, Confirmed)*

`forms/libraries/HRMS_VALIDATION_LIB.pll.sql:108-135`

```sql
-- Checks salary against grade range using cached local data
-- BUG: Uses a hard-coded cache that's populated at form startup
...
    -- Direct DB query (not cached - contradicts the comment above)
    SELECT MIN_SALARY, MAX_SALARY INTO v_min, v_max
    FROM JOB_GRADES WHERE GRADE_ID = p_grade_id;
```

**Issue.** The header comment and the in-line comment contradict each other and both contradict the code, which queries the database on every keystroke-level validation.
**Impact.** Misleading documentation drives wrong optimisation decisions, and the per-validation round trip is a real (if small) client-tier cost.
**Recommendation.** Delete the stale comments and delegate to `PKG_VALIDATION.validate_salary_for_grade`.

### DRIFT-06 — Date-range validation is shallower on the client than on the server *(LOW, Confirmed)*

`forms/libraries/HRMS_VALIDATION_LIB.pll.sql:96-99` vs `plsql/packages/PKG_VALIDATION.pkb:6-15`

```sql
    FUNCTION validate_date_range(
        p_start_date IN DATE,
        p_end_date   IN DATE
    ) RETURN BOOLEAN IS
    BEGIN
        IF p_start_date IS NULL OR p_end_date IS NULL THEN
            RETURN FALSE;
        END IF;
        RETURN p_end_date >= p_start_date;
    END validate_date_range;
```

**Issue.** The server rejects NULL endpoints and enforces ordering; the PLL offers only a not-in-future check and treats NULL as valid. NULL-handling is therefore inverted between the layers.
**Impact.** NULL-handling inconsistencies surface as errors at commit time rather than at entry, and leave requests with reversed dates are only caught server-side (`PKG_LEAVE.pkb:116-118`).
**Recommendation.** Expose `PKG_VALIDATION.validate_date_range` to the forms and remove the client-side variant.

---

## 6. Circular Dependencies (CIRC)

### CIRC-01 — `PKG_EMPLOYEE` ↔ `PKG_PAYROLL` *(HIGH, Confirmed)*

`plsql/packages/PKG_EMPLOYEE.pkb:273-285` and `:778-784`; `plsql/packages/PKG_PAYROLL.pks:6-9`

```sql
        -- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
        -- which in turn may call PKG_EMPLOYEE.is_active for validation
        PKG_PAYROLL.create_salary_record(
            p_emp_id         => v_emp_id,
            p_effective_date => p_hire_date,
            p_base_salary    => p_base_salary,
            p_change_reason  => 'NEW_HIRE',
            p_user           => p_user
        );
```

```sql
-- Dependencies: PKG_EMPLOYEE, PKG_COMMON, PKG_AUDIT, PKG_NOTIFICATION
-- Known issues:
--   - Circular dependency with PKG_EMPLOYEE (is_active check)
```

**Issue.** Each package body calls the other (`create_employee` and `rehire_employee` → `PKG_PAYROLL.create_salary_record` → `PKG_EMPLOYEE.is_active`). Both specs declare the other as a dependency.
**Impact.** Recompiling either body invalidates the other, so a change to one module can leave the other in an `INVALID` state until the next call reloads it — a common source of transient ORA-04068 "existing state of packages has been discarded" errors in production. It also makes the two packages impossible to test, deploy, or extract independently, which directly blocks any incremental migration.
**Recommendation.** Extract the shared predicate into a leaf package (e.g. `PKG_EMPLOYEE_STATUS` exposing `is_active`) that both depend on, or invert the flow so the orchestration lives in a caller above both packages.

### CIRC-02 — Latent `PKG_SECURITY` ↔ `PKG_EMPLOYEE` cycle *(LOW, Confirmed)*

`plsql/packages/PKG_SECURITY.pkb:75` and `plsql/packages/PKG_EMPLOYEE.pkb:737-739`

```sql
        PKG_EMPLOYEE.set_session_context(p_username, v_emp_id);
```

```sql
            -- TODO: Integrate with benefits system to trigger COBRA
            -- TODO: Revoke system access via PKG_SECURITY
            -- TODO: Calculate final pay via PKG_PAYROLL.calculate_final_pay
```

**Issue.** `PKG_SECURITY` already depends on `PKG_EMPLOYEE`. The termination TODO would add the reverse edge, creating a second cycle the moment access revocation is implemented.
**Impact.** Not currently active, but it makes the "obvious" fix for ARCH-07 introduce a new invalidation cycle.
**Recommendation.** Resolve CIRC-01 by introducing the leaf-package pattern first, then implement revocation against that layer.

---

## 7. Architecture (ARCH)

### ARCH-01 — Employee-history trigger inserts columns that do not exist *(CRITICAL, Confirmed)*

Trigger: `plsql/triggers/trg_employees.sql:78-85` (repeated at `:90-109` for department and job changes)

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

Table: `schema/tables/01_core_tables.sql` (`EMPLOYEE_HISTORY`)

```sql
CREATE TABLE HRMS.EMPLOYEE_HISTORY (
    HIST_ID              NUMBER(15)      NOT NULL,
    EMP_ID               NUMBER(10)      NOT NULL,
    CHANGE_TYPE          VARCHAR2(30)    NOT NULL,
    EFFECTIVE_DATE       DATE            NOT NULL,
    OLD_DEPT_ID          NUMBER(10),
    NEW_DEPT_ID          NUMBER(10),
    ...
    OLD_SALARY           NUMBER(12,2),
    NEW_SALARY           NUMBER(12,2),
    REASON_CODE          VARCHAR2(30),
    COMMENTS             VARCHAR2(4000),
    CREATED_BY           VARCHAR2(30)    NOT NULL,
    CREATED_DATE         DATE            DEFAULT SYSDATE NOT NULL,
    CONSTRAINT PK_EMP_HISTORY PRIMARY KEY (HIST_ID),
```

**Issue.** Six of the eight columns named by the trigger do not exist in the table:

| Trigger column | Actual DDL |
|---|---|
| `HISTORY_ID` | `HIST_ID` |
| `CHANGE_DATE` | `EFFECTIVE_DATE` |
| `OLD_VALUE` | *no such column* (typed `OLD_DEPT_ID`, `OLD_SALARY`, …) |
| `NEW_VALUE` | *no such column* |
| `CHANGED_BY` | `CREATED_BY` |
| `CHANGE_REASON` | `REASON_CODE` |

The generic string columns the trigger assumes were replaced by typed old/new pairs, and the trigger was never updated. Separately, the trigger passes `'DEPT_CHANGE'`/`'JOB_CHANGE'` as `CHANGE_TYPE`, which are absent from `CHK_CHANGE_TYPE` (`HIRE, TRANSFER, PROMOTION, DEMOTION, SALARY_CHANGE, TERMINATION, REHIRE, LEAVE_START, LEAVE_END, STATUS_CHANGE`).

**Impact.** The trigger cannot compile against this DDL; it fails with ORA-00904 (invalid identifier), and because the trigger is `AFTER UPDATE ... FOR EACH ROW` on `EMPLOYEES`, **every** status, department or job change fails. Terminations, promotions and transfers are all blocked, and no history rows exist for any change. This is the highest-impact defect in the repository after SEC-01.
**Recommendation.** Rewrite the trigger against the real DDL, mapping each change type to its typed columns (`OLD_DEPT_ID`/`NEW_DEPT_ID`, `OLD_JOB_ID`/`NEW_JOB_ID`, `OLD_SALARY`/`NEW_SALARY`) and using `HIST_ID`, `EFFECTIVE_DATE`, `REASON_CODE`, `CREATED_BY`. Add `DEPT_CHANGE`/`JOB_CHANGE` to `CHK_CHANGE_TYPE` or map them to `TRANSFER`/`PROMOTION`. Add a deployment check that compiles all triggers and fails the build on `INVALID` objects — this defect would not have survived one.

### ARCH-02 — Autonomous transactions used for routine logging *(MEDIUM, Confirmed)*

`plsql/packages/PKG_COMMON.pkb` (`log_error`, and `log_info` at `:46`), `plsql/packages/PKG_AUDIT.pkb:14`, `plsql/packages/PKG_NOTIFICATION.pkb:27`

```sql
    PROCEDURE log_action(
        ...
    ) IS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        INSERT INTO AUDIT_LOG (...);
        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            -- Audit logging must never fail the calling transaction
            ROLLBACK;
    END log_action;
```

**Issue.** Four separate procedures open an independent transaction per call. Each is invoked from within business transactions, and `PKG_NOTIFICATION` queues rows autonomously, so a queued notification commits even when the business change it announces is rolled back.
**Impact.** Every logged action consumes a transaction slot and a commit (a measurable cost inside the payroll loop), audit rows survive rolled-back work, and the `WHEN OTHERS THEN ROLLBACK` silently discards audit failures — so audit gaps are invisible. Autonomous transactions also cannot see the parent's uncommitted state, and a self-deadlock is possible if either ever touches a row the parent has locked.
**Recommendation.** Keep autonomous transactions only where independence is genuinely required (error logging on the failure path). Write audit rows in the parent transaction so they commit or roll back with the change they describe, and queue notifications in-transaction so cancelled work sends no mail.

### ARCH-03 — E-mail uniqueness enforced only by trigger, not by constraint *(HIGH, Confirmed)*

`plsql/triggers/trg_employees.sql:38-52` versus `schema/tables/01_core_tables.sql` (`EMPLOYEES`)

**Issue.** The trigger checks for duplicate e-mail addresses and its comment presents this as belt-and-braces alongside a constraint, but `EMPLOYEES` declares only `PK_EMPLOYEES` and `UK_EMP_NUMBER` — there is no unique key or unique index on `EMAIL`.
**Impact.** The check is bypassed by direct DML that disables triggers, by data loads, and by the concurrency window in RACE-04. Duplicate e-mails then feed SEC-07 and the login form's `ROWNUM = 1`, meaning a user can be authenticated as the wrong employee. The trigger also makes every insert/update do a table lookup that an index would answer in one probe.
**Recommendation.** Add `UK_EMP_EMAIL` (case-insensitive, e.g. a unique function-based index on `UPPER(EMAIL)`, matching how the login queries filter) and simplify the trigger to raise on ORA-00001.

### ARCH-04 — Flat-file GL/benefits integration with no acknowledgement or retry *(MEDIUM, Confirmed)*

`plsql/packages/PKG_INTEGRATION.pkb:6-9`, `:20-31`

```sql
    c_gl_output_dir       CONSTANT VARCHAR2(30) := 'GL_FEED_OUT';
    c_benefits_output_dir CONSTANT VARCHAR2(30) := 'BENEFITS_FEED_OUT';
    c_time_input_dir      CONSTANT VARCHAR2(30) := 'TIME_ATTENDANCE_IN';
...
        v_file := UTL_FILE.FOPEN(c_gl_output_dir, v_filename, 'W', 32767);
        UTL_FILE.PUT_LINE(v_file, ...);
```

**Issue.** Integration writes CSV through `UTL_FILE` to Oracle directory objects. There is no checksum, no acknowledgement, no idempotency key, and — as the spec states — no retry logic. A file written but never collected is indistinguishable from one collected successfully.
**Impact.** Silent data loss between HRMS and the GL/benefits vendor, detected only at month-end reconciliation. Directory objects also grant the schema filesystem write access on the database host, widening the blast radius of any SQL injection (SEC-04).
**Recommendation.** Move to an authenticated API or a message queue with delivery acknowledgement; until then, write a manifest with row counts and a hash, record every transfer in a table with status, and reconcile automatically.

### ARCH-05 — `import_time_attendance` counts rows it never imports *(CRITICAL, Confirmed)*

`plsql/packages/PKG_INTEGRATION.pkb:153-194`

```sql
                IF v_line IS NOT NULL AND SUBSTR(v_line, 1, 1) != '#' THEN
                    -- Parse CSV: emp_number,date,hours_regular,hours_overtime
                    -- TODO: Implement actual parsing and database update
                    v_imported := v_imported + 1;
                END IF;
```

**Issue.** The loop reads every line, increments `v_imported`, and writes nothing to the database. The procedure then reports that many records were imported.
**Impact.** Time-and-attendance data never reaches payroll, while the operator and the log both report a successful import of N records. Hourly employees are therefore paid from whatever stale or default hours exist — a silent, recurring payroll error that the monitoring explicitly conceals. Given it affects pay accuracy and actively reports false success, this is CRITICAL despite being "just" an unfinished feature.
**Recommendation.** Implement parsing and the `PAYROLL_DETAILS`/timecard update with per-row error capture, or make the procedure raise "not implemented" immediately. Do not report counts for work not performed.

### ARCH-06 — `sync_org_structure` logs completion of a no-op *(HIGH, Confirmed)*

`plsql/packages/PKG_INTEGRATION.pkb:196-203`

```sql
    PROCEDURE sync_org_structure(
        p_user IN VARCHAR2 DEFAULT USER
    ) IS
    BEGIN
        -- Placeholder for org structure sync with external directory (LDAP/AD)
        PKG_COMMON.log_info('PKG_INTEGRATION', 'sync_org_structure',
            'Org structure sync completed', p_user);
    END sync_org_structure;
```

**Issue.** The body's only statement asserts that a synchronisation completed.
**Impact.** Directory and HRMS org data drift indefinitely while the log shows healthy nightly syncs. Combined with ARCH-05 and SEC-09, this is a pattern: three separate stubs emit success telemetry, so monitoring cannot distinguish working features from unimplemented ones.
**Recommendation.** Implement the sync or raise "not implemented". Establish a rule that no procedure logs success it did not perform, and audit the codebase for other instances.

### ARCH-07 — Termination process leaves access, pay and benefits untouched *(MEDIUM, Confirmed)*

`plsql/packages/PKG_EMPLOYEE.pkb:737-739`

```sql
            -- TODO: Integrate with benefits system to trigger COBRA
            -- TODO: Revoke system access via PKG_SECURITY
            -- TODO: Calculate final pay via PKG_PAYROLL.calculate_final_pay
```

**Issue.** `terminate_employee` updates employment status but performs none of the three downstream steps. Nothing invalidates the terminated employee's rows in `USER_SESSIONS`.
**Impact.** A terminated employee keeps a valid application session until it ages out (and see SEC-08: expiry is lazy), final pay is not computed, and COBRA notification — a statutory obligation in the US — is not triggered. This is a compliance exposure, not only a functional gap.
**Recommendation.** Complete the termination orchestration: expire sessions immediately, invoke final-pay calculation, and emit the benefits event. Add a post-termination assertion that no `ACTIVE` session remains for the employee.

### ARCH-08 — Federal tax brackets hard-coded for 2024 *(HIGH, Confirmed)*

`plsql/packages/PKG_PAYROLL.pkb:643-660`

```sql
        -- 2024 Federal tax brackets (Single)
        -- TODO: Read from TAX_BRACKETS table instead of hard-coding
        IF p_filing_status = 'SINGLE' OR p_filing_status = 'MARRIED_SEPARATE' THEN
            IF v_taxable <= 11600 THEN
                v_tax := v_taxable * 0.10;
            ELSIF v_taxable <= 47150 THEN
                v_tax := 1160 + (v_taxable - 11600) * 0.12;
```

**Issue.** Bracket thresholds, rates and base amounts are literals in the package body, together with standard-deduction and allowance constants — while `schema/tables/02_payroll_tables.sql:159` already defines a `TAX_BRACKETS` table keyed by `TAX_YEAR` and `FILING_STATUS` that the code never reads. `MARRIED_SEPARATE` is also treated as identical to `SINGLE`, which is not correct at the upper thresholds.

**Impact.** Every tax year requires a code change and a production deployment, and until it happens withholding is silently computed on stale brackets — an under- or over-withholding error across the entire employee base, with statutory consequences. Because the table exists, the discrepancy is invisible to anyone auditing the schema rather than the code.

**Recommendation.** Read brackets from `TAX_BRACKETS` for the run's tax year, fail loudly if no rows exist for that year, and keep `MARRIED_SEPARATE` as its own filing status.

### ARCH-09 — Fiscal-year start hard-coded to October *(LOW, Confirmed)*

`plsql/packages/PKG_COMMON.pkb:168-179`

```sql
    -- get_fiscal_year (fiscal year starts Oct 1)
    ...
        IF EXTRACT(MONTH FROM p_date) >= 10 THEN
            RETURN EXTRACT(YEAR FROM p_date) + 1;
        ELSE
            RETURN EXTRACT(YEAR FROM p_date);
        END IF;
```

**Issue.** The fiscal-year boundary is the literal `10`, duplicated in reporting paths (`plsql/packages/PKG_REPORTING.pks:9` documents "hard-coded fiscal year start (Oct 1)").

**Impact.** An organisational change to the fiscal calendar — or use of this codebase by an entity with a different one — requires code changes in several places, with a high chance of missing one and producing reports that straddle two definitions.

**Recommendation.** Store the fiscal-year start month in `SYSTEM_PARAMETERS` and read it in one function that all callers use.

---

## 8. Data Integrity (DATA)

### DATA-01 — Payroll error handler violates `FK_PD_ELEMENT` *(CRITICAL, Confirmed)*

Handler: `plsql/packages/PKG_PAYROLL.pkb:306-319`

```sql
            EXCEPTION
                WHEN OTHERS THEN
                    v_error_count := v_error_count + 1;

                    -- Log error but continue processing other employees
                    INSERT INTO PAYROLL_DETAILS (
                        DETAIL_ID, RUN_ID, EMP_ID, ELEMENT_ID,
                        ELEMENT_TYPE, AMOUNT, STATUS, ERROR_MESSAGE,
                        CREATED_BY, CREATED_DATE
                    ) VALUES (
                        SEQ_PAYROLL_DETAIL.NEXTVAL, p_run_id, emp_rec.EMP_ID, 0,
                        'ERROR', 0, 'ERROR', SUBSTR(SQLERRM, 1, 4000),
                        p_user, SYSDATE
                    );
```

DDL: `schema/tables/02_payroll_tables.sql:136-154`

```sql
    CONSTRAINT FK_PD_ELEMENT FOREIGN KEY (ELEMENT_ID) REFERENCES HRMS.PAY_ELEMENTS(ELEMENT_ID)
```

**Issue.** The handler inserts the sentinel `ELEMENT_ID = 0`, but `PAY_ELEMENTS` has no row with `ELEMENT_ID = 0` — `data/seed/01_reference_data.sql` seeds elements starting at a non-zero id. The insert therefore raises ORA-02291 (integrity constraint violated — parent key not found) *inside the `WHEN OTHERS` handler*, so the new exception propagates out of the `FOR` loop.
**Impact.** The mechanism designed to let payroll survive one bad employee is precisely what kills the run: the first employee-level error aborts the whole batch. Worse, because PERF-06 commits every 50 employees, the abort leaves a committed, partially calculated payroll run whose totals were never updated. Recovery is manual.
**Recommendation.** Create a dedicated `PAYROLL_ERRORS` table with no FK to `PAY_ELEMENTS` (or seed a reserved `ELEMENT_ID = 0` 'SYSTEM ERROR' element), and never place fallible DML in a `WHEN OTHERS` handler without its own nested block.

### DATA-02 — `rehire_employee` cannot complete *(CRITICAL, Confirmed)*

`plsql/packages/PKG_EMPLOYEE.pkb:750-790`

```sql
        UPDATE EMPLOYEES SET
            EMPLOYMENT_STATUS  = 'ACTIVE',
            HIRE_DATE          = p_rehire_date,
            TERMINATION_DATE   = NULL,
            ...
        WHERE EMP_ID = p_emp_id;
...
        log_history(p_emp_id, 'REHIRE', p_rehire_date, ...);
```

**Issue.** The `UPDATE` changes `EMPLOYMENT_STATUS`, which fires the broken `TRG_EMP_HISTORY` (ARCH-01). Even if that were fixed, `log_history` then writes a second history row for the same event, so the trigger and the procedure duplicate each other's work.
**Impact.** Rehire fails outright today; after ARCH-01 is fixed it will produce duplicate history rows unless the overlap is resolved. Overwriting `HIRE_DATE` in place also destroys the original hire date, breaking any seniority or tenure calculation (`PKG_EMPLOYEE.pkb:871` computes tenure from `HIRE_DATE`).
**Recommendation.** Fix ARCH-01, then decide whether history is written by the trigger or by `log_history` — not both. Preserve the original hire date in a separate `ORIGINAL_HIRE_DATE` column and use it for tenure.

### DATA-03 — `VW_LEAVE_SUMMARY.AVAILABLE` disagrees with the table's own definition *(CRITICAL, Confirmed)*

View: `schema/views/hrms_views.sql:86-103`

```sql
       lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE
```

Table: `schema/tables/03_leave_tables.sql` (`LEAVE_BALANCES`)

```sql
    AVAILABLE            NUMBER(6,2)
        GENERATED ALWAYS AS
        (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL
```

**Issue.** The table's virtual column subtracts `PENDING`; the view does not. Both columns are named `AVAILABLE`. `PKG_LEAVE.get_leave_balance` (`:376-381`) uses the *table's* formula, so the view is the outlier.
**Impact.** Any screen or report reading the view shows a larger balance than the enforcement path allows. Employees see available days they cannot book, and the rejection message quotes a different number than the screen — a support-ticket generator that also invites double-booking of pending leave.
**Recommendation.** Change the view to select `lb.AVAILABLE` directly so exactly one definition exists, and add a regression check that any column named `AVAILABLE` matches the generated column.

### DATA-04 — Leave request spanning a year boundary decrements only one year *(HIGH, Confirmed)*

`plsql/packages/PKG_LEAVE.pkb:176-182`

```sql
            AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```

**Issue.** The `PENDING` update is keyed on the year of the start date only, and the balance check (`get_leave_balance`, `:369-387`) defaults `p_year` to `EXTRACT(YEAR FROM SYSDATE)` — the *current* year, not the request's year. For a request submitted in December for January leave, the check reads this year's balance while the update writes this year's row, and next year's balance is untouched.
**Impact.** Christmas-to-New-Year requests consume the wrong year's entitlement, and a January request submitted in December is validated against a balance that will be reset before the leave is taken. Year-end balances do not reconcile, and the error is systematically concentrated in the busiest leave period.
**Recommendation.** Split cross-year requests by calendar year and apply each portion to its own balance row; pass an explicit year to `get_leave_balance` derived from the leave dates, never from `SYSDATE`.

### DATA-05 — Half-day leave modelled inconsistently *(MEDIUM, Confirmed)*

`plsql/packages/PKG_LEAVE.pkb:128-133` and `check_leave_overlap` (`:37-60`)

```sql
        IF p_half_day_flag = 'Y' THEN
            v_total_days := 0.5;
        ELSE
            v_total_days := calculate_business_days(
                p_start_date, p_end_date, v_emp_rec.LOCATION_CODE);
        END IF;
```

**Issue.** When `p_half_day_flag = 'Y'` the total is hard-coded to 0.5 regardless of the date range, so a half-day flag on a two-week request deducts half a day. The overlap check compares date ranges only and ignores `HALF_DAY_FLAG`/`HALF_DAY_PERIOD`, both of which exist in the `LEAVE_REQUESTS` DDL.
**Impact.** Under-deduction of balances for mis-flagged multi-day requests, and two genuine half-days on the same date (morning and afternoon) are rejected as overlapping while a full day plus a half day on one date is accepted.
**Recommendation.** Validate that `HALF_DAY_FLAG = 'Y'` implies `START_DATE = END_DATE`, and include `HALF_DAY_PERIOD` in the overlap predicate.

### DATA-06 — Holidays matched on exact date, ignoring observed dates *(MEDIUM, Confirmed)*

`plsql/packages/PKG_LEAVE.pkb:21-27`, `plsql/packages/PKG_VALIDATION.pkb:90-94`

```sql
                SELECT COUNT(*) INTO v_holiday_count
                FROM HOLIDAYS
                WHERE HOLIDAY_DATE = v_date
                AND ACTIVE_FLAG = 'Y'
                AND (LOCATION_CODE IS NULL OR LOCATION_CODE = p_location_code);
```

**Issue.** Both call sites match `HOLIDAY_DATE` exactly, and the `HOLIDAYS` table has no `OBSERVED_DATE` column. A holiday falling on a Saturday or Sunday is simply skipped (the weekend branch runs first) and the weekday on which it is actually observed counts as a working day.
**Impact.** Leave deductions are one day too high in any year where a public holiday falls on a weekend — a recurring, employee-visible payroll/leave discrepancy.
**Recommendation.** Add `OBSERVED_DATE` to `HOLIDAYS`, populate it, and match on it in both call sites.

### DATA-07 — Two competing definitions of "active employee" *(MEDIUM, Confirmed)*

`schema/views/hrms_views.sql:47-57` (`EMPLOYMENT_STATUS = 'ACTIVE'` only) versus `plsql/packages/PKG_PAYROLL.pkb:296-302` and `forms/xml-exports/HRMS_EMPLOYEE.xml:53` (`EMPLOYMENT_STATUS = 'ACTIVE' AND ACTIVE_FLAG = 'Y'`)

```sql
            WHERE e.EMPLOYMENT_STATUS = 'ACTIVE'
            AND e.ACTIVE_FLAG = 'Y'
```

**Issue.** The schema carries both a status column and a soft-delete flag with no constraint tying them together, and different modules apply different combinations. `PKG_SECURITY.authenticate` (`:42-45`) checks only `EMPLOYMENT_STATUS`.
**Impact.** An employee with `EMPLOYMENT_STATUS = 'ACTIVE'` and `ACTIVE_FLAG = 'N'` appears in the org hierarchy and can log in, but is excluded from payroll — i.e. soft-deleted employees can authenticate yet are not paid. Headcount reported by different modules will not agree.
**Recommendation.** Define one predicate in a single function (or a `VW_ACTIVE_EMPLOYEES` view) and use it everywhere; add `CHECK (ACTIVE_FLAG = 'N' OR EMPLOYMENT_STATUS <> 'TERMINATED')`-style constraints to stop contradictory combinations.

### DATA-08 — Soft-delete enforced by a `BEFORE DELETE` trigger named `INSTEAD_OF` *(LOW, Confirmed)*

`plsql/triggers/trg_employees.sql:120-130`

```sql
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
BEFORE DELETE ON HRMS.EMPLOYEES
FOR EACH ROW
BEGIN
    RAISE_APPLICATION_ERROR(-20504,
        'Direct deletion not allowed. Use termination process or set ACTIVE_FLAG to N.');
END TRG_EMP_INSTEAD_OF_DELETE;
```

**Issue.** The name promises an `INSTEAD OF` trigger that converts deletes to soft deletes; the implementation is a `BEFORE DELETE` trigger that rejects them (`INSTEAD OF` is only valid on views, so the name can never be accurate here). The error message offers two different remedies — the termination process or a manual flag update — and the latter bypasses history and audit entirely.
**Impact.** Callers expecting a transparent soft delete get ORA-20504. The message actively encourages the unaudited `ACTIVE_FLAG = 'N'` path, which is how the contradictory states in DATA-07 arise.
**Recommendation.** Rename to `TRG_EMP_PREVENT_DELETE`, and point the message at the termination API only.

---

## 9. Migration Roadmap

Effort is expressed in engineering sessions of focused work, not calendar time.

### Phase 1 — Critical security and blocked functionality (do first)

Everything here is either an open door or a statement that cannot execute. Nothing else in the roadmap is worth doing until Phase 1 lands.

| Order | ID | Action | Effort |
|---|---|---|---|
| 1 | SEC-01 | Implement real credential verification; fail closed | 2-3 sessions |
| 2 | ARCH-01 | Rewrite `TRG_EMP_HISTORY` against actual DDL; add compile gate to deployment | 1 session |
| 3 | DATA-01 | Move payroll error rows to a table without the `PAY_ELEMENTS` FK | 0.5 session |
| 4 | SEC-04 | Convert `search_employees` to bind variables | 1 session |
| 5 | SEC-03 | Externalise the encryption key; rotate and re-encrypt | 1-2 sessions |
| 6 | SEC-02 | Replace MD5 with bcrypt/Argon2; force password reset | with SEC-01 |
| 7 | ARCH-05, ARCH-06, SEC-09 | Make the three success-logging stubs raise "not implemented" (immediate), then implement | 0.5 session, then 2-3 |
| 8 | DATA-02 | Fix `rehire_employee` once ARCH-01 is done | 0.5 session |
| 9 | SEC-05, SEC-06, SEC-07 | Enforce TLS; add lockout and constant-time failure paths | 1-2 sessions |

Exit criteria: no unauthenticated path returns a session; every trigger and package compiles `VALID`; a payroll run survives an employee-level error; no procedure logs success it did not perform.

### Phase 2 — Data integrity and correctness

| Order | ID | Action | Effort |
|---|---|---|---|
| 1 | DATA-03 | Point `VW_LEAVE_SUMMARY` at the generated `AVAILABLE` column | 0.25 session |
| 2 | ARCH-03, RACE-04 | Add `UK_EMP_EMAIL` after de-duplication | 0.5 session |
| 3 | RACE-01 | Use `SEQ_EMP_NUMBER`; delete the `WHEN OTHERS` fallback | 0.25 session |
| 4 | RACE-02, RACE-03 | Add `FOR UPDATE` locking to period and balance check-then-act paths | 1 session |
| 5 | DATA-04, DATA-05, DATA-06 | Correct cross-year, half-day and observed-holiday leave logic | 2 sessions |
| 6 | DATA-07, DATA-08 | Single "active employee" predicate; rename the delete trigger | 1 session |
| 7 | DRIFT-01…06 | Collapse validation into `PKG_VALIDATION`; make PLL and triggers call it | 2 sessions |
| 8 | ARCH-02 | Move audit writes into the parent transaction | 1 session |
| 9 | ARCH-07 | Complete termination orchestration (sessions, final pay, COBRA) | 2 sessions |

Exit criteria: one definition per business rule; no check-then-act without a lock; leave balances reconcile across a year boundary.

### Phase 3 — Performance

| Order | ID | Action | Effort |
|---|---|---|---|
| 1 | PERF-01 | Eliminate the per-day holiday query | 0.5 session |
| 2 | PERF-02, PERF-03 | Closed-form business-day arithmetic in the surviving implementation | 0.5 session |
| 3 | PERF-06 | Set-based / `FORALL` payroll calculation, one commit per run | 2-3 sessions |
| 4 | PERF-05 | One SMTP connection per batch | 0.5 session |
| 5 | PERF-07 | `CACHE` the hot sequences | 0.25 session |
| 6 | PERF-04 | Recursive CTE or closure table for the hierarchy | 1-2 sessions |
| 7 | PERF-08 | Materialised views with published refresh timestamps | 1 session |

Exit criteria: payroll runtime sub-linear in context switches; no query issued inside a date loop; batch notification time dominated by the relay, not by handshakes.

### Phase 4 — Modernisation

| Order | ID | Action | Effort |
|---|---|---|---|
| 1 | CIRC-01, CIRC-02 | Extract leaf packages to break the dependency cycles | 2 sessions |
| 2 | ARCH-04 | Replace `UTL_FILE` feeds with acknowledged API/queue integration | 3-4 sessions |
| 3 | SEC-10, SEC-11 | All endpoints and secrets from config/KMS, never from source | 1-2 sessions |
| 4 | ARCH-08 | Hard-coded 2024 tax brackets → `TAX_BRACKETS` table (already in the DDL) | 1 session |
| 5 | ARCH-09 | Fiscal-year start from `SYSTEM_PARAMETERS` instead of a literal `10` | 0.5 session |
| 6 | SEC-14 | Explicit role/permission model, deny by default | 3 sessions |
| 7 | SEC-12 | `JSON_OBJECT` for structured logging | 0.25 session |
| 8 | — | Retire the PLL/Forms client tier once validation is server-side only | out of scope here |

Exit criteria: no cycles between packages; no environment-specific literal in source; authorisation decisions readable from data rather than from code.

### Sequencing notes

- Two Phase-4 items are cheap and low-risk (ARCH-08 tax brackets, ARCH-09 fiscal-year literal) and can be pulled forward if a tax-year boundary is near — `TAX_BRACKETS` already exists in `schema/tables/02_payroll_tables.sql:159`, so the change is a lookup, not a schema change.
- CIRC-01 should be resolved before ARCH-07's access revocation, otherwise the fix introduces the second cycle described in CIRC-02.
- Every Phase-1 and Phase-2 item is blocked on the same missing capability: a deployment step that compiles all PL/SQL objects and fails on `INVALID`. Adding that check is the highest-leverage single action in this report — it would have caught ARCH-01, DATA-01 and DATA-02 before they shipped.

---

## Appendix — Validation performed

- `sqlfluff lint --dialect oracle .` — the known parse failure on `GENERATED ALWAYS AS ... VIRTUAL` in `schema/tables/03_leave_tables.sql` is a SQLFluff dialect limitation, not a defect in the DDL.
- `find forms/xml-exports -name '*.xml' -exec xmllint --noout {} +` — all form exports are well-formed XML.
- No build system or automated test suite exists in this repository, so no findings in this report were verified by execution. All conclusions are derived from source and DDL inspection; findings marked **Risk** depend on runtime data or configuration not present here.
