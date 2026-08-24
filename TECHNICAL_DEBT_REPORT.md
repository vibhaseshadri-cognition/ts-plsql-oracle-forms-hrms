# Technical Debt Report — Oracle Forms / PL/SQL HRMS

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Stack:** Oracle Forms 12c, Oracle Reports, Oracle Database 19c, PL/SQL, WebLogic
**Scope analyzed:** 12 PL/SQL packages (specs + bodies), 2 trigger scripts, 4 table DDL scripts, 1 view script, 1 sequence script, 2 PLL form libraries, 6 Forms XML exports, 3 seed data scripts
**Method:** full-source review; every finding below is grounded in current file content and line numbers. Claims in existing source comments were re-verified against the code, and several are corrected here (see [Corrections to In-Code Annotations](#corrections-to-in-code-annotations)).

---

## Executive Summary

The codebase is a functionally broad but structurally fragile legacy HRMS. Three classes of defect dominate:

1. **Authentication is non-functional as security control.** `PKG_SECURITY.authenticate` never compares any password to any stored credential — it resolves the username to an `EMP_ID` and issues a session. Password hashing exists (`MD5`) but is dead code, and `change_password` validates complexity then discards the new password. Any caller who knows an active employee's email obtains a valid session.
2. **Code references columns that do not exist.** The employee audit trigger and the reference-data seed script both name columns absent from the DDL. These fail at compile/run time (`ORA-00904`) — the history trigger silently disables *all* employee change auditing, and the seed script prevents a clean schema install.
3. **Balance and payroll arithmetic disagrees between layers.** `VW_LEAVE_SUMMARY.AVAILABLE` omits `- PENDING` while the base table's virtual column includes it; leave balance updates are silently no-ops when a balance row for the target year is missing; payroll commits every 50 employees with no restart marker.

### Severity Counts

| Severity | Count |
|---|---|
| CRITICAL | 6 |
| HIGH | 11 |
| MEDIUM | 29 |
| LOW | 11 |
| **Total** | **57** |

### Category Breakdown

| Category | ID prefix | Findings | Critical | High | Medium | Low |
|---|---|---|---|---|---|---|
| Security vulnerabilities | `SEC` | 15 | 4 | 4 | 5 | 2 |
| Race conditions | `RACE` | 4 | 0 | 1 | 3 | 0 |
| Performance | `PERF` | 8 | 0 | 0 | 6 | 2 |
| Validation drift | `DRIFT` | 4 | 0 | 1 | 2 | 1 |
| Circular dependencies | `CIRC` | 2 | 0 | 1 | 1 | 0 |
| Architectural anti-patterns | `ARCH` | 11 | 2 | 1 | 4 | 4 |
| Data integrity | `DATA` | 13 | 0 | 3 | 8 | 2 |

### Top 6 items to fix first

| ID | Severity | One-line summary |
|---|---|---|
| SEC-01 | CRITICAL | `authenticate()` never verifies the password — authentication bypass |
| ARCH-01 | CRITICAL | Employee history trigger inserts into 6 non-existent columns — auditing is dead |
| SEC-04 | CRITICAL | `search_employees` concatenates caller input into dynamic SQL |
| SEC-03 | CRITICAL | Hard-coded 30-byte AES-256 key — SSN encryption raises at runtime and the error is swallowed |
| ARCH-02 | CRITICAL | Seed script columns do not match DDL — schema install fails |
| DATA-01 | HIGH | `VW_LEAVE_SUMMARY.AVAILABLE` overstates balance by omitting `PENDING` |

---

## 1. Security Vulnerabilities

### SEC-01 — CRITICAL — `authenticate()` issues sessions without verifying the password

**Location:** `plsql/packages/PKG_SECURITY.pkb:30-80`

```sql
FUNCTION authenticate(
    p_username IN VARCHAR2, p_password IN VARCHAR2, p_ip_address IN VARCHAR2 DEFAULT NULL
) RETURN NUMBER IS
    v_stored_hash VARCHAR2(200);   -- declared, never assigned
    v_input_hash  VARCHAR2(200);   -- declared, never assigned
BEGIN
    SELECT EMP_ID INTO v_emp_id FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
    ...
    -- NOTE: In the real system, passwords are stored in a separate
    -- USER_CREDENTIALS table. For this legacy codebase, we simulate
    -- authentication against a simplified model.

    SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
    INSERT INTO USER_SESSIONS (...) VALUES (v_session_id, v_emp_id, p_username, SYSDATE, ...);
    RETURN v_session_id;
```

**Issue:** `p_password` is never read after the parameter declaration. `hash_password` is never called from `authenticate`. There is no `USER_CREDENTIALS` table anywhere in `schema/tables/`, and `EMPLOYEES` has no password column, so there is nothing to compare against. `v_stored_hash` / `v_input_hash` are dead locals.

**Impact:** Complete authentication bypass. Knowledge of any active employee's email address (available in every notification and export) yields a valid `SESSION_ID`, which `is_session_valid` then accepts and `PKG_EMPLOYEE.set_session_context` promotes to an application identity. Combined with SEC-08, a login as any Director-graded employee grants full-module access.

**Recommendation:** Do not remediate incrementally. Move authentication out of the database into the identity provider (SSO/OIDC) as part of Phase 1; if a DB-resident credential store must persist in the interim, add `USER_CREDENTIALS (EMP_ID, PASSWORD_HASH, SALT, ALGORITHM, FAILED_ATTEMPTS, LOCKED_UNTIL, PASSWORD_CHANGED_DATE)` and make `authenticate` fail closed when no credential row exists.

### SEC-02 — CRITICAL — Password hashing uses unsalted MD5

**Location:** `plsql/packages/PKG_SECURITY.pkb:14-24`

```sql
RETURN RAWTOHEX(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(p_password), DBMS_CRYPTO.HASH_MD5));
```

**Issue:** MD5 is collision-broken and, more importantly here, unsuitable for password storage: no salt and no work factor, so an offline attacker recovers passwords at commodity GPU rates. `PKG_SECURITY.pks:12` already acknowledges this ("Password stored as MD5 hash (should be bcrypt/scrypt)"). The function is currently unreferenced (SEC-01), so it is a trap waiting for whoever "fixes" authentication by calling it.

**Impact:** If SEC-01 is remediated by wiring in `hash_password`, the system ships credential storage that fails PCI-DSS 8.3.1, NIST SP 800-63B, and any SOC 2 password-storage control.

**Recommendation:** Delete `hash_password`. Oracle's `DBMS_CRYPTO` offers no adaptive KDF; perform password hashing (bcrypt/scrypt/Argon2id) in the identity provider or an application-tier service, never in PL/SQL.

### SEC-03 — CRITICAL — Hard-coded encryption key, wrong key length, and swallowed failure

**Location:** `plsql/packages/PKG_SECURITY.pkb:7`, `179-206`

```sql
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
...
v_raw := DBMS_CRYPTO.ENCRYPT(
    src => UTL_RAW.CAST_TO_RAW(p_ssn),
    typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
    key => c_encryption_key);
```

**Issue:** Three defects in one construct:
1. The key is a literal in source, committed to version control and readable by anyone with `SELECT` on `ALL_SOURCE` — it is not protected by the wallet or by Oracle Key Vault.
2. The literal is **30 bytes**, not 32. AES-256 requires a 256-bit key, so `DBMS_CRYPTO.ENCRYPT` raises an invalid-key-size error (`ORA-28234` class) on every call. SSN encryption has never worked.
3. `decrypt_ssn` traps `WHEN OTHERS` and returns `'***DECRYPT_ERROR***'`, so the failure surfaces as a benign-looking string rather than an exception — masking (2) indefinitely.

Additionally, CBC mode is used with no explicit IV, so `DBMS_CRYPTO` uses a zero IV: identical SSNs would produce identical ciphertext, permitting equality inference across rows.

**Impact:** PII that the system claims to encrypt is either not stored at all (writes fail) or stored deterministically. Key rotation is impossible without a code deployment. `EMPLOYEES.SSN_ENCRYPTED` content cannot be trusted for compliance attestations.

**Recommendation:** Replace with Transparent Data Encryption (TDE) on the SSN column, or a `DBMS_CRYPTO` wrapper whose key is fetched from Oracle Key Vault, with a random per-row IV stored alongside the ciphertext. Remove the `WHEN OTHERS` handler so cryptographic failures are loud.

### SEC-04 — CRITICAL — SQL injection in `search_employees`

**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:445-498`

```sql
IF p_last_name IS NOT NULL THEN
    v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
END IF;
IF p_dept_id IS NOT NULL THEN
    v_sql := v_sql || 'AND e.DEPT_ID = ' || p_dept_id || ' ';
END IF;
IF p_status IS NOT NULL THEN
    v_sql := v_sql || 'AND e.EMPLOYMENT_STATUS = ''' || p_status || ''' ';
END IF;
...
OPEN p_cursor FOR v_sql;
```

**Issue:** Seven filter parameters are concatenated into the statement text; five are `VARCHAR2` and are injectable via quote-breaking (`' OR 1=1 --`), and `p_dept_id` is injectable without quotes if a caller passes a non-numeric string through an implicit conversion path. `PKG_EMPLOYEE.pkb:442` acknowledges the issue for `p_last_name` only; the exposure is broader. The procedure is invoked from the Forms search block, so the inputs are end-user-controlled.

**Impact:** Arbitrary read of any object visible to the `HRMS` schema — salaries, `SSN_ENCRYPTED`, `EMPLOYEE_BANK_ACCOUNTS`, `USER_SESSIONS` — through a single UI text field. Union-based extraction is straightforward because the caller receives an open `REF CURSOR`.

**Recommendation:** Rewrite with static SQL using the `(:p IS NULL OR col = :p)` pattern, or keep dynamic SQL but bind every value via `OPEN p_cursor FOR v_sql USING ...`. Never concatenate. Add a code-review gate rejecting `||` inside strings assigned to variables passed to `OPEN ... FOR` or `EXECUTE IMMEDIATE`.

### SEC-05 — HIGH — `change_password` does not verify the old password and never persists the new one

**Location:** `plsql/packages/PKG_SECURITY.pkb:211-240`

```sql
IF LENGTH(p_new_password) < 8 THEN RAISE_APPLICATION_ERROR(-20310, ...); END IF;
IF NOT REGEXP_LIKE(p_new_password, '[A-Z]') THEN RAISE_APPLICATION_ERROR(-20311, ...); END IF;
IF NOT REGEXP_LIKE(p_new_password, '[0-9]') THEN RAISE_APPLICATION_ERROR(-20312, ...); END IF;

-- NOTE: Actual password update would go to USER_CREDENTIALS table
-- This is a stub for the legacy system model
PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
```

**Issue:** `p_old_password` is never referenced — no re-authentication before a credential change. The new password is validated for complexity, then dropped. An audit record is written claiming an `UPDATE` that did not occur.

**Impact:** Users believe rotation succeeded; the audit trail asserts it did. Incident response reading `AUDIT_LOG` would wrongly conclude compromised credentials were rotated.

**Recommendation:** Until a credential store exists, make the procedure raise `ORA-20313 'Password management not implemented'` rather than logging a false success. When implemented, require `p_old_password` verification and write the audit record only after a successful commit.

### SEC-06 — HIGH — No account lockout or brute-force throttling

**Location:** `plsql/packages/PKG_SECURITY.pkb:30-80`; `schema/tables/01_core_tables.sql` (`USER_SESSIONS`, 9 columns)

**Issue:** There is no failed-attempt counter, no lockout state, and no rate limit. `USER_SESSIONS` records only successful sessions (`SESSION_ID, EMP_ID, USERNAME, LOGIN_TIME, LOGOUT_TIME, IP_ADDRESS, SESSION_STATUS, CREATED_DATE`) — there is no failed-login table, so brute-force attempts leave no trace at all. `PKG_SECURITY.pks:14` lists this as a known issue.

**Impact:** Unlimited credential-guessing with no detection surface. Once SEC-01 is fixed, this becomes the primary path to account takeover.

**Recommendation:** Add `LOGIN_ATTEMPTS (USERNAME, ATTEMPT_TIME, SOURCE_IP, RESULT)` plus lockout counters on the credential row; lock for an increasing interval after 5 failures; alert on ≥10 failures per username or IP per 10 minutes.

### SEC-07 — HIGH — User enumeration via timing/error path, and duplicate-email account confusion

**Location:** `plsql/packages/PKG_SECURITY.pkb:41-57`

```sql
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        -- VULNERABILITY: Timing attack - different response time for
        -- invalid user vs invalid password
        RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
    WHEN TOO_MANY_ROWS THEN
        -- Multiple employees with same email - use first active one
        SELECT MIN(EMP_ID) INTO v_emp_id FROM EMPLOYEES
        WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
```

**Issue:** Unknown usernames short-circuit immediately while known usernames proceed through session creation, giving an observable timing and side-effect difference (a `USER_SESSIONS` row is created only for valid users). Separately, when two active employees share an email the code silently authenticates as `MIN(EMP_ID)`. `EMPLOYEES` has no unique constraint on `EMAIL` — uniqueness is only enforced by the `ACTIVE_FLAG='Y'` count check in `plsql/triggers/trg_employees.sql:44-52`, which is itself race-prone.

**Impact:** Attackers enumerate the valid-employee directory. Duplicate-email records let one person's login resolve to another person's identity and permissions.

**Recommendation:** Constant-time failure path (always perform a dummy hash comparison), identical error for every failure mode, and a `UNIQUE` index on `UPPER(EMAIL)` — enforced by the database rather than by trigger arithmetic.

### SEC-08 — HIGH — Authorization compares a surrogate key against a privilege threshold

**Location:** `plsql/packages/PKG_SECURITY.pkb:134-178`

```sql
SELECT e.DEPT_ID, j.GRADE_ID INTO v_dept_id, v_grade_id
FROM EMPLOYEES e JOIN JOB_TITLES j ON e.JOB_ID = j.JOB_ID WHERE e.EMP_ID = p_emp_id;

IF v_grade_id >= 8 THEN RETURN TRUE;  -- Senior management - full access
IF p_action = 'VIEW' AND v_grade_id >= 5 THEN RETURN TRUE;
```

**Issue:** `GRADE_ID` is a surrogate primary key on `JOB_GRADES`, not a seniority level. `schema/sequences/hrms_sequences.sql` defines `SEQ_JOB_GRADE` for allocating it, so any grade created after the seed data receives an ID far above 8. `JOB_GRADES` in `schema/tables/01_core_tables.sql` has **no** `GRADE_LEVEL` column (see ARCH-02) — there is no ordinal seniority attribute to compare against, so the code substitutes the key. The seed data coincidentally makes `GRADE_ID` equal to intended level for grades 1-10 only.

**Impact:** Silent privilege escalation. The first new job grade added through the application — an intern band, a contractor band — gets an ID ≥ 11 and therefore unconditional full access to every module including payroll and SSN views. `has_permission` also ignores `p_module` entirely above the threshold, and `v_dept_id` is selected but never used, so the "edit own department" rule described in the comments is not implemented.

**Recommendation:** Introduce explicit roles (`ROLES`, `ROLE_PRIVILEGES`, `EMPLOYEE_ROLES`) and resolve permissions by module+action lookup. Never derive authority from a surrogate key. If a level attribute is wanted, add `JOB_GRADES.GRADE_LEVEL` to the DDL (which the seed data already assumes exists) and compare on that.

### SEC-09 — MEDIUM — Password travels from the Forms client to the database as a bind value in cleartext

**Location:** `forms/xml-exports/HRMS_LOGIN.xml` (LOGIN block, `WHEN-BUTTON-PRESSED`)

```sql
v_session_id := PKG_SECURITY.authenticate(
    :LOGIN.USERNAME, :LOGIN.PASSWORD, GET_APPLICATION_PROPERTY(CLIENT_HOST));
```

**Issue:** The item sets `Conceal Data = Yes`, which only masks on-screen rendering. The secret is then sent to the server as a plain bind variable; whether it is protected in transit depends entirely on Oracle Net encryption (`SQLNET.ENCRYPTION_SERVER`), which is not configured anywhere in this repository. Nothing in the codebase asserts a TLS requirement.

**Impact:** On an unencrypted Oracle Net channel, credentials are recoverable by anyone able to observe traffic between the Forms server and the database.

**Recommendation:** Mandate native network encryption (`SQLNET.ENCRYPTION_SERVER = required`) or TCPS, and document it in the deployment blueprint. Longer term, authenticate at the middle tier so the password never reaches the database (see SEC-01).

### SEC-10 — MEDIUM — Hard-coded SMTP endpoint on port 25 with no TLS or authentication

**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:7-11`

```sql
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
```

**Issue:** Relay host, port, and sender identity are compile-time constants; `UTL_SMTP.OPEN_CONNECTION` at line 90 is followed by `HELO` with no `STARTTLS` and no `AUTH`. Notification bodies carry names, leave details, and salary-change confirmations.

**Impact:** HR-sensitive content crosses the network unencrypted; the open relay path can be abused for internal phishing with a trusted `From`. Environment promotion (dev → prod) requires a code change, encouraging drift.

**Recommendation:** Move SMTP configuration into `SYSTEM_PARAMETERS` (already read by `PKG_COMMON.get_param`), use port 587 with `STARTTLS` and credentials from the wallet, and route through a mail gateway rather than direct SMTP from the database.

### SEC-11 — MEDIUM — FTP credentials stored in cleartext in `SYSTEM_PARAMETERS`

**Location:** `plsql/packages/PKG_INTEGRATION.pks:9-13` (documented), `plsql/packages/PKG_INTEGRATION.pkb` (parameter reads)

```sql
-- Known issues:
--   - FTP credentials stored in SYSTEM_PARAMETERS table (cleartext)
```

**Issue:** Outbound GL and benefits file transfers rely on credentials held as plain `PARAM_VALUE` rows. `SYSTEM_PARAMETERS` has no column-level protection and is readable by every account with schema `SELECT`, including reporting users.

**Impact:** Any read access to the HRMS schema — including read-only BI accounts — yields credentials to the finance and benefits vendor endpoints, which receive full payroll extracts.

**Recommendation:** Store transfer credentials in an Oracle Wallet or external secrets manager referenced by alias; if they must live in the database, isolate them in a table owned by a separate schema with no public grants, and switch to SFTP with key-based authentication so no password exists to leak.

### SEC-12 — MEDIUM — Audit payloads are hand-concatenated JSON with inconsistent escaping

**Location:** `plsql/packages/PKG_COMMON.pkb:16-60`; `plsql/triggers/trg_audit.sql:20-57`

```sql
-- log_error (escapes double quotes)
'{"package":"' || p_package || '","procedure":"' || p_procedure ||
'","message":"' || REPLACE(SUBSTR(p_message, 1, 3000), '"', '\"') || '"}'

-- log_info (no escaping at all)
'{"package":"' || p_package || '","procedure":"' || p_procedure ||
'","message":"' || SUBSTR(p_message, 1, 3000) || '"}'
```

**Issue:** JSON is built by string concatenation in `log_error`, `log_info`, and all of `trg_audit.sql`. `log_error` escapes `"` but not `\`, newlines, or control characters; `log_info` escapes nothing. Values flowing in include user-entered names and reasons.

**Impact:** Audit records become unparseable, and an attacker can inject synthetic JSON fields into `AUDIT_LOG.NEW_VALUES` to forge or obscure audit content — defeating the trail that SOX/SOC 2 review depends on.

**Recommendation:** Use `JSON_OBJECT(...)` (available in 19c) everywhere, and store the column as `CLOB` with an `IS JSON` check constraint so malformed payloads are rejected at write time.

### SEC-13 — MEDIUM — Session validity is absolute-only; no idle timeout and clock-skew dependent

**Location:** `plsql/packages/PKG_SECURITY.pkb:98-130`

```sql
IF (SYSDATE - v_login_time) * 24 * 60 > c_session_timeout_min THEN
```

**Issue:** The comparison uses `LOGIN_TIME`, so a session dies 30 minutes after login regardless of activity — there is no last-activity column in `USER_SESSIONS` to support idle timeout. `SYSDATE` is database server time while the session was created from the Forms tier; `PKG_SECURITY.pks:13` notes the mismatch. There is no session invalidation on password change, termination, or privilege change.

**Impact:** Simultaneously too strict (active users are logged out mid-transaction, encouraging workarounds like shared long-lived sessions) and too loose (a stolen `SESSION_ID` remains valid for its full window even after the employee is terminated by `PKG_EMPLOYEE.terminate_employee`).

**Recommendation:** Add `LAST_ACTIVITY_TIME`, refresh it on each validated call, expire on idle *and* absolute limits, use `SYSTIMESTAMP` at a single tier, and have `terminate_employee` and `change_password` close open sessions.

### SEC-14 — LOW — No MFA, SSO, or federation path

**Location:** `plsql/packages/PKG_SECURITY.pks:16-30` (public API surface)

**Issue:** The published interface (`authenticate`, `logout`, `is_session_valid`, `has_permission`, `change_password`) has no hook for a second factor or an external assertion; identity is a username string.

**Impact:** Blocks compliance with common insurer/customer requirements for privileged HR data access, and makes the eventual identity-provider migration an interface-breaking change.

**Recommendation:** Define the target boundary now — the Forms tier accepts an IdP-issued token and calls `PKG_SECURITY.establish_session(p_subject, p_assertion)` — so Phase 1 and Phase 4 work converge instead of conflicting.

### SEC-15 — LOW — Login form swallows all exceptions

**Location:** `forms/xml-exports/HRMS_LOGIN.xml` (`WHEN-BUTTON-PRESSED`, `EXCEPTION WHEN OTHERS`)

**Issue:** The handler converts every server-side failure into a generic message. Genuine faults (network, package invalid state, the SEC-03 crypto error) are indistinguishable from bad credentials, and nothing is logged client-side.

**Impact:** Outages and attacks look identical to users and to support; diagnosis requires database-side tracing.

**Recommendation:** Distinguish `-20301` (credential failure, generic message to the user) from all other errors (log via `PKG_COMMON.log_error`, show a support reference ID).

---

## 2. Race Conditions

### RACE-01 — HIGH — `MAX()+1` employee-number generation, with a fallback to the wrong sequence

**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:35-55`

```sql
-- BUG: race condition under concurrent inserts - no SELECT FOR UPDATE
SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
INTO v_max_num FROM EMPLOYEES
WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';

v_new_number := c_emp_number_prefix || '-' || LPAD(v_max_num, 6, '0');
RETURN v_new_number;
EXCEPTION
    WHEN OTHERS THEN
        -- Fallback: use sequence-based number
        RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMPLOYEE.NEXTVAL, 6, '0');
```

**Issue:** Two sessions reading `MAX()` before either commits compute the same number; the second `INSERT` violates `UK_EMP_NUMBER` (`schema/tables/01_core_tables.sql`). `schema/sequences/hrms_sequences.sql` defines `SEQ_EMP_NUMBER` precisely for this purpose and it is **never referenced anywhere in the codebase**. The `WHEN OTHERS` fallback then draws from `SEQ_EMPLOYEE` — the surrogate-key sequence for `EMP_ID`, starting at 10000 — so a fallback both consumes primary-key values and produces employee numbers from a different, non-contiguous namespace. `TO_NUMBER(SUBSTR(EMP_NUMBER, 5))` also raises `ORA-01722` for any historical number not matching the expected shape, silently routing every subsequent call into the fallback.

**Impact:** Hiring fails intermittently under concurrent onboarding (the common case at quarter start), and the retry path corrupts the employee-number series in a way that is hard to unwind after the fact.

**Recommendation:** `RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMP_NUMBER.NEXTVAL, 6, '0');` — delete the `MAX()` query and the fallback entirely. Reseed `SEQ_EMP_NUMBER` above the current maximum during the migration.

### RACE-02 — MEDIUM — Payroll run created against an unlocked period status

**Location:** `plsql/packages/PKG_PAYROLL.pkb:241-265` (compare with `:193-196` and `:561-564`)

```sql
SELECT STATUS INTO v_status FROM PAY_PERIODS WHERE PERIOD_ID = p_period_id;   -- no FOR UPDATE

IF v_status = 'CLOSED' THEN
    RAISE_APPLICATION_ERROR(-20102, 'Cannot create run for closed period: ' || p_period_id);
END IF;

SELECT SEQ_PAYROLL_RUN.NEXTVAL INTO v_run_id FROM DUAL;
INSERT INTO PAYROLL_RUNS (...) VALUES (...);
```

**Issue:** The check-then-insert is not atomic. `close_pay_period` (line 561) *does* use `FOR UPDATE`, which makes the omission here an inconsistency rather than a house style: a close committing between the read and the insert produces a run attached to a closed period.

**Impact:** Payroll runs materialize inside closed accounting periods, breaking GL reconciliation and requiring manual reversal of `PAYROLL_RUNS` and `PAYROLL_DETAILS`.

**Recommendation:** Add `FOR UPDATE` to the line 241 select (matching line 193), and add a database-level guard — a check that no `PAYROLL_RUNS` row may be inserted for a period whose status is `CLOSED`, enforced by trigger or by moving run creation behind a single serialized procedure.

### RACE-03 — MEDIUM — Carryover expiry is not idempotent and loses its audit basis

**Location:** `plsql/packages/PKG_LEAVE.pkb:610-623`

```sql
UPDATE LEAVE_BALANCES SET
    ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
    CARRYOVER_FROM_PREV = 0,
    MODIFIED_BY = p_user, MODIFIED_DATE = SYSDATE
WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE) AND CARRYOVER_FROM_PREV > 0;
```

**Issue:** The `CARRYOVER_FROM_PREV > 0` predicate means a second sequential run does not double-subtract — but two *concurrent* runs (scheduler overlap, or an operator re-running after a perceived hang) can both read the pre-update value under read committed and each apply the subtraction to different rows in interleaved order; more importantly, the update destroys `CARRYOVER_FROM_PREV` in place, leaving no record of what was expired. No row is written to `LEAVE_ACCRUAL_LOG`, so an incorrect expiry cannot be identified or reversed.

**Impact:** Silent, unauditable balance reductions. Disputes over expired carryover cannot be adjudicated from system data.

**Recommendation:** Write a `LEAVE_ACCRUAL_LOG` row per affected balance inside the same transaction, add a `CARRYOVER_EXPIRED_DATE` marker instead of relying on the zeroed amount, and serialize the job with `DBMS_LOCK.REQUEST` so overlapping executions are impossible.

### RACE-04 — MEDIUM — Forms client allocates keys and bypasses server-side creation logic

**Location:** `forms/xml-exports/HRMS_EMPLOYEE.xml` (EMPLOYEE block, `PRE-INSERT`)

```sql
BEGIN
    :EMPLOYEE.EMP_ID := SEQ_EMPLOYEE.NEXTVAL;
    :EMPLOYEE.EMP_NUMBER := PKG_EMPLOYEE.generate_emp_number;
    :EMPLOYEE.ACTIVE_FLAG := 'Y';
    :EMPLOYEE.EMPLOYMENT_STATUS := 'ACTIVE';
    ...
END;
```

**Issue:** The form inserts employees directly rather than calling `PKG_EMPLOYEE.create_employee`. Consequently it skips every server-side rule that procedure applies — department validation, manager validation, grade/salary range checking, location defaulting, `EMPLOYEE_HISTORY` logging, and initial salary record creation. It also calls the RACE-01 generator from a second, concurrent code path, widening the collision window.

**Impact:** Two divergent creation paths with different invariants. Employees created through the form have no history row and no salary record, so downstream payroll and reporting silently omit them.

**Recommendation:** Replace the `PRE-INSERT` trigger and the block's DML with `ON-INSERT` calling `PKG_EMPLOYEE.create_employee`, making the package the only writer to `EMPLOYEES`.

---

## 3. Performance Issues

### PERF-01 — MEDIUM — Per-day holiday query inside the leave day-count loop (N+1)

**Location:** `plsql/packages/PKG_LEAVE.pkb:15-40`

```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count FROM HOLIDAYS
        WHERE HOLIDAY_DATE = v_date AND ACTIVE_FLAG = 'Y'
        AND (LOCATION_CODE IS NULL OR LOCATION_CODE = p_location_code);
        ...
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Issue:** One context switch and one query per weekday in the range. A 20-day request issues ~14 queries; the annual accrual job (`process_accruals`) calls this per employee per leave type.

**Impact:** Accrual and balance batch time scales as employees × leave types × days rather than as a single set operation — the dominant cost in the nightly window.

**Recommendation:** Single set-based statement — count non-weekend days from a generated date range with an anti-join to `HOLIDAYS`:

```sql
SELECT COUNT(*) INTO v_count
FROM (SELECT TRUNC(p_start_date) + LEVEL - 1 d FROM DUAL
      CONNECT BY LEVEL <= TRUNC(p_end_date) - TRUNC(p_start_date) + 1) c
WHERE TO_CHAR(c.d, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT','SUN')
AND NOT EXISTS (SELECT 1 FROM HOLIDAYS h WHERE h.HOLIDAY_DATE = c.d
                AND h.ACTIVE_FLAG = 'Y'
                AND (h.LOCATION_CODE IS NULL OR h.LOCATION_CODE = p_location_code));
```

### PERF-02 — MEDIUM — Day-by-day loop in `business_days_between`

**Location:** `plsql/packages/PKG_COMMON.pkb:132-146`

```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        v_count := v_count + 1;
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Issue:** Pure iteration where closed-form arithmetic suffices, and it is invoked from report queries — inside a `SELECT` this incurs a context switch per row per day. It also ignores holidays, unlike PERF-01's version, so two different "business day" definitions coexist (see DRIFT-04).

**Impact:** Tenure and turnover reports over multi-year ranges loop thousands of times per row.

**Recommendation:** Compute from week arithmetic (`TRUNC(diff/7)*5 + remainder adjustment`), or delegate to the single set-based helper from PERF-01. Mark the function `DETERMINISTIC` so it can be used in a function-based index if reports need it.

### PERF-03 — MEDIUM — Day-by-day loop in `add_business_days`

**Location:** `plsql/packages/PKG_COMMON.pkb:151-165`

```sql
WHILE v_added < p_days LOOP
    v_result := v_result + 1;
    IF TO_CHAR(v_result, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        v_added := v_added + 1;
    END IF;
END LOOP;
```

**Issue:** Same pattern as PERF-02. Additionally there is no guard on `p_days`: a negative value makes the `WHILE` condition false immediately and returns the input date (silently wrong rather than erroring), while a large value loops proportionally.

**Impact:** SLA/deadline calculations in performance-review and onboarding workflows are slower than necessary and wrong for negative offsets.

**Recommendation:** Closed-form calculation with an explicit `p_days < 0` branch (or a raised exception if backward offsets are not supported).

### PERF-04 — MEDIUM — `CONNECT BY` hierarchy traversal with a documented ceiling

**Location:** `schema/views/hrms_views.sql:47-60`; `plsql/packages/PKG_EMPLOYEE.pkb:825-840`

```sql
-- WARNING: Performance degrades significantly with >500 employees
CREATE OR REPLACE VIEW HRMS.VW_ORG_HIERARCHY AS
SELECT ... FROM EMPLOYEES
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
ORDER SIBLINGS BY LAST_NAME;
```

**Issue:** The view walks the whole tree with no depth limit and no cycle protection (`NOCYCLE` absent) — a data-entry loop in `MANAGER_EMP_ID` yields `ORA-01436`. `PKG_EMPLOYEE.get_org_chart` uses the same construct with `LEVEL <= p_max_depth` placed in the `CONNECT BY` clause and filters `EMPLOYMENT_STATUS = 'ACTIVE'`, which prunes entire subtrees below any inactive manager rather than re-parenting them. `PKG_EMPLOYEE.pks` records that this "times out for deep hierarchies".

**Impact:** Org-chart screens and headcount rollups degrade non-linearly; terminated middle managers make whole departments vanish from the chart.

**Recommendation:** Add `NOCYCLE`, drop the status filter from the traversal (filter at the outer query, or re-parent to the nearest active manager), and materialize the hierarchy — a nightly closure table or `MATERIALIZED VIEW` with a `MANAGER_EMP_ID` index — for reporting consumers.

### PERF-05 — MEDIUM — One SMTP connection opened per notification

**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:78-115`

```sql
FOR notif_rec IN (SELECT ... FROM NOTIFICATION_QUEUE WHERE STATUS = 'PENDING' ...) LOOP
    v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
    UTL_SMTP.HELO(v_connection, c_smtp_host);
    ...
    UTL_SMTP.QUIT(v_connection);
END LOOP;
```

**Issue:** TCP connect, `HELO`, and teardown per message. There is also no per-message exception isolation around the connection open, so one unreachable relay aborts the remaining queue, and no retry/backoff state is recorded.

**Impact:** Queue drain time is dominated by connection setup (typically 10-50ms each); a transient relay outage stalls all notifications, including leave approvals that gate business workflow.

**Recommendation:** Open one connection, send all messages, then `QUIT` — reopening only on error, with per-message `RETRY_COUNT` / `NEXT_RETRY_TIME` on `NOTIFICATION_QUEUE`. Better: hand off to a mail gateway and keep the database out of the SMTP path entirely.

### PERF-06 — MEDIUM — Row-by-row payroll calculation with intermediate commits

**Location:** `plsql/packages/PKG_PAYROLL.pkb:268-330`

```sql
-- BUG: Cursor loop - should use BULK COLLECT + FORALL
FOR emp_rec IN (SELECT e.EMP_ID FROM EMPLOYEES e
                WHERE e.EMPLOYMENT_STATUS = 'ACTIVE' AND e.ACTIVE_FLAG = 'Y'
                ORDER BY e.EMP_ID) LOOP
    calculate_employee_pay(p_run_id, emp_rec.EMP_ID, v_period_id, p_user);
    ...
    -- ISSUE: Partial commits mean a failure leaves payroll half-calculated
    IF MOD(v_emp_count, 50) = 0 THEN COMMIT; END IF;
END LOOP;
```

**Issue:** Each employee triggers independent queries and inserts through `calculate_employee_pay`. The commit every 50 rows is worse than a performance problem: it breaks atomicity with no restart marker, so a mid-run failure leaves `PAYROLL_RUNS` in a state where the completed subset is indistinguishable from the pending subset.

**Impact:** Long payroll windows, and after a failure there is no safe action — re-running double-pays the committed subset, doing nothing under-pays the remainder. Recovery is manual `PAYROLL_DETAILS` inspection.

**Recommendation:** Restructure as set-based `INSERT ... SELECT` per pay element (or `BULK COLLECT` + `FORALL` in bounded batches), commit once per run, and record `LAST_PROCESSED_EMP_ID` on `PAYROLL_RUNS` so a restart is deterministic. Make `calculate_employee_pay` idempotent for a given `(RUN_ID, EMP_ID)`.

### PERF-07 — LOW — Every sequence is `NOCACHE`

**Location:** `schema/sequences/hrms_sequences.sql` (29 of 29 `CREATE SEQUENCE` statements)

```sql
CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
CREATE SEQUENCE HRMS.SEQ_PAYROLL_DETAIL START WITH 1 INCREMENT BY 1 NOCACHE;
```

**Issue:** `NOCACHE` forces a recursive `SYS.SEQ$` update and redo write per `NEXTVAL`. `SEQ_PAYROLL_DETAIL` and `SEQ_AUDIT` are the hottest — one call per payroll detail line and per audited change.

**Impact:** Row-level insert throughput is capped by sequence maintenance, and `SQ` enqueue contention appears under concurrent payroll or audit load. The gap-avoidance this buys is not required by any documented rule.

**Recommendation:** `CACHE 100` (or `1000` for `SEQ_AUDIT` and `SEQ_PAYROLL_DETAIL`); keep `NOCACHE ORDER` only where strict gapless numbering is a stated legal requirement.

### PERF-08 — LOW — Reporting tables refreshed nightly and stale all day

**Location:** `plsql/packages/PKG_REPORTING.pks:8-10`; `PKG_REPORTING.refresh_reporting_tables`

```sql
-- Known issues:
--   - Denormalized reporting tables refreshed nightly; stale during business hours
```

**Issue:** Denormalized tables are rebuilt on a schedule with no freshness marker exposed to consumers, and no incremental path.

**Impact:** Headcount and turnover figures presented during the day silently exclude same-day hires and terminations; users reconcile against operational screens and lose trust in reports.

**Recommendation:** Convert to materialized views with `REFRESH FAST ON COMMIT` where the query permits, otherwise surface `LAST_REFRESH_DATE` in every report header so consumers can see the as-of time.

---

## 4. Validation Drift (Forms PLL vs Server-Side Packages)

### DRIFT-01 — HIGH — Client and server email validation accept different sets of addresses

**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql` (`validate_email`) vs `plsql/packages/PKG_COMMON.pkb:265-268`

```sql
-- Client (PLL): positional INSTR checks
v_at_pos := INSTR(p_email, '@');
IF v_at_pos = 0 OR v_at_pos = 1 OR v_at_pos = LENGTH(p_email) THEN RETURN FALSE; END IF;
v_dot_pos := INSTR(p_email, '.', v_at_pos);
IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN RETURN FALSE; END IF;
-- BUG: Only checks for one dot after @, rejects valid subdomains
RETURN TRUE;

-- Server (PKG_COMMON.is_valid_email)
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

**Issue:** The two implementations disagree, and the in-code comment mis-states the direction of the drift. Traced against the actual logic, the client check is **more permissive**, not less: `user@mail.company.com` passes both (the first dot after `@` satisfies the positional test), while addresses like `a@b.c` (single-character TLD) and anything containing spaces or characters outside the server's character class pass the client and are then rejected by the server regex. The client also treats `NULL` as valid because `INSTR(NULL,'@')` yields `NULL` and neither `IF` fires.

**Impact:** Users are told their address is acceptable, complete a multi-tab employee entry, and only then hit a server-side rejection — or, where the server-side check is not invoked on that path, an invalid address is persisted and every subsequent notification to that employee fails silently in `NOTIFICATION_QUEUE`.

**Recommendation:** Single source of truth. Delete the PLL implementation and have `validate_email` call `PKG_COMMON.is_valid_email` (one round trip, already required elsewhere in the same trigger), or generate both from one regex constant. Add a `CHECK` constraint or a validating trigger on `EMPLOYEES.EMAIL` so no path can persist an invalid address. Correct the misleading comment.

### DRIFT-02 — MEDIUM — Salary validation: comment describes a cache that does not exist; NULL handling differs

**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql` (`validate_salary_range`) vs `plsql/packages/PKG_VALIDATION.pkb` (`validate_salary`)

```sql
-- BUG: Uses a hard-coded cache that's populated at form startup
-- and never refreshed. If grade ranges change mid-session, this
-- validation uses stale data.
...
-- Direct DB query (not cached - contradicts the comment above)
SELECT MIN_SALARY, MAX_SALARY INTO v_min, v_max FROM JOB_GRADES WHERE GRADE_ID = p_grade_id;
```

**Issue:** The documented stale-cache defect is not present in the code — the function queries `JOB_GRADES` directly on every call. The real drift is behavioural: the client returns "valid" for a `NULL` salary or grade, while `PKG_VALIDATION.validate_salary` returns an error message requiring both. Neither is authoritative, because `PKG_EMPLOYEE` only warns on out-of-range salaries (DATA-08).

**Impact:** Maintainers "fix" a cache that isn't there and miss the real gap; NULL salaries pass the form and reach a server layer that rejects them, or bypass validation entirely on the direct-insert path (RACE-04).

**Recommendation:** Delete the incorrect comment. Align NULL semantics explicitly (decide whether salary is mandatory at creation and encode it in both layers plus a `NOT NULL`/`CHECK` constraint), and make the server-side range check authoritative and blocking.

### DRIFT-03 — LOW — SSN validation is stricter on the client than on the server

**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql` (`validate_ssn`) vs `plsql/packages/PKG_COMMON.pkb` (`is_valid_ssn`)

**Issue:** The PLL rejects structurally invalid SSN groups (all-zero area/group/serial and the reserved `666`/`9xx` ranges); the server-side helper only verifies that nine digits are present after stripping formatting.

**Impact:** Any non-Forms path — batch import (`PKG_INTEGRATION.import_time_attendance`), data migration, direct package calls — accepts SSNs the UI would reject, so the same data quality rule holds for interactive entry only.

**Recommendation:** Move the group rules into `PKG_COMMON.is_valid_ssn` and have the PLL delegate to it, so all ingress paths share one definition.

### DRIFT-04 — MEDIUM — Three incompatible definitions of a valid date, spread across three layers

**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql` (`validate_date_not_future`), `plsql/packages/PKG_VALIDATION.pkb` (`validate_date_range`, `validate_business_day`), `plsql/triggers/trg_employees.sql:35-37`

```sql
-- Trigger: allows hire dates up to 180 days ahead
IF :NEW.HIRE_DATE > SYSDATE + 180 THEN
    RAISE_APPLICATION_ERROR(-20501, 'Hire date cannot be more than 180 days in the future');

-- PKG_VALIDATION.validate_date_range: ordering only
RETURN p_end_date >= p_start_date;
```

**Issue:** The PLL forbids future dates outright, the trigger permits up to 180 days ahead, and `PKG_VALIDATION.validate_date_range` checks only ordering with no bounds at all. Business-day/holiday logic lives in a fourth place (`validate_business_day`), and "business day" itself has two definitions (PERF-01 excludes holidays, PERF-02 does not).

**Impact:** Future-dated hires — a normal onboarding practice the trigger was written to support — are blocked in the UI while being legal in the database, so users work around the form. Rules cannot be changed in one place, and no layer can be trusted by the others.

**Recommendation:** Consolidate all date rules into `PKG_VALIDATION` with named, parameterized limits (`c_max_future_hire_days`), have both the PLL and the triggers call it, and keep a single `business_days_between` implementation that takes an explicit "include holidays" flag.

---

## 5. Circular Dependencies

### CIRC-01 — HIGH — `PKG_EMPLOYEE` ⇄ `PKG_PAYROLL`

**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:271-280`; `PKG_EMPLOYEE.pks:6-9`; `PKG_PAYROLL.pkb` (calls back into `PKG_EMPLOYEE`)

```sql
-- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
-- which in turn may call PKG_EMPLOYEE.is_active for validation
PKG_PAYROLL.create_salary_record(
    p_emp_id => v_emp_id, p_effective_date => p_hire_date, ...);
```

**Issue:** `PKG_EMPLOYEE.create_employee` calls `PKG_PAYROLL.create_salary_record`, which validates by calling back into `PKG_EMPLOYEE`. The cycle is documented in both specs as a known issue. In Oracle this compiles (package bodies resolve at run time) but it couples the two largest modules bidirectionally.

**Impact:** Recompiling either package invalidates the other, so a payroll patch requires revalidating employee code and vice versa — every deployment touches both, and dependency-driven invalidation cascades to `PKG_REPORTING`, `PKG_LEAVE`, and the Forms modules. The cycle also means no correct migration order exists: neither package can be extracted to a service first.

**Recommendation:** Break the cycle by extracting the shared validation primitives (`is_active`, grade/salary range lookup) into a leaf package with no upward dependencies, and invert the creation flow — have an orchestration layer call `PKG_EMPLOYEE` then `PKG_PAYROLL` rather than nesting them. This is a prerequisite for any incremental modernization (Phase 4).

### CIRC-02 — MEDIUM — Latent `PKG_SECURITY` ⇄ `PKG_EMPLOYEE` cycle

**Location:** `plsql/packages/PKG_SECURITY.pkb:75` and `plsql/packages/PKG_EMPLOYEE.pkb:737-739`

```sql
-- PKG_SECURITY.authenticate already calls into PKG_EMPLOYEE
PKG_EMPLOYEE.set_session_context(p_username, v_emp_id);

-- PKG_EMPLOYEE.terminate_employee plans the reverse edge
-- TODO: Revoke system access via PKG_SECURITY
```

**Issue:** One direction exists today (`PKG_SECURITY` → `PKG_EMPLOYEE`); the outstanding TODO in `terminate_employee` would add the reverse edge and close a second cycle. `PKG_EMPLOYEE.pks` does not list `PKG_SECURITY` as a dependency, so the coupling would be undocumented.

**Impact:** The obvious implementation of a required security control (session revocation on termination, see SEC-13) creates new structural debt. Deferring it leaves terminated employees with live sessions.

**Recommendation:** Put session-context management in a leaf utility package that both `PKG_SECURITY` and `PKG_EMPLOYEE` depend on, then implement revocation against that package instead of calling `PKG_SECURITY` from `PKG_EMPLOYEE`.

---

## 6. Architectural Anti-Patterns

### ARCH-01 — CRITICAL — Employee history trigger references six columns that do not exist

**Location:** `plsql/triggers/trg_employees.sql:78-114` (three separate `INSERT` statements at lines 78, 90, 102) vs `schema/tables/01_core_tables.sql` (`EMPLOYEE_HISTORY`)

```sql
-- Trigger writes:
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (...);
```

```sql
-- DDL defines (18 columns, structured old/new pairs):
CREATE TABLE HRMS.EMPLOYEE_HISTORY (
    HIST_ID NUMBER(15) NOT NULL, EMP_ID NUMBER(10) NOT NULL,
    CHANGE_TYPE VARCHAR2(30) NOT NULL, EFFECTIVE_DATE DATE NOT NULL,
    OLD_DEPT_ID NUMBER(10), NEW_DEPT_ID NUMBER(10),
    OLD_JOB_ID NUMBER(10), NEW_JOB_ID NUMBER(10),
    OLD_MANAGER_ID NUMBER(10), NEW_MANAGER_ID NUMBER(10),
    OLD_SALARY NUMBER(12,2), NEW_SALARY NUMBER(12,2),
    OLD_LOCATION VARCHAR2(10), NEW_LOCATION VARCHAR2(10),
    REASON_CODE VARCHAR2(30), COMMENTS VARCHAR2(4000),
    CREATED_BY VARCHAR2(30) NOT NULL,
    CREATED_DATE DATE DEFAULT SYSDATE NOT NULL, ...);
```

Verified mapping of every mismatch:

| Trigger column | Exists in DDL? | Actual DDL column |
|---|---|---|
| `HISTORY_ID` | no | `HIST_ID` (PK, `NOT NULL`) |
| `CHANGE_DATE` | no | `EFFECTIVE_DATE` (`NOT NULL`) |
| `OLD_VALUE` | no | `OLD_DEPT_ID` / `OLD_JOB_ID` / `OLD_SALARY` / `OLD_MANAGER_ID` / `OLD_LOCATION` |
| `NEW_VALUE` | no | corresponding `NEW_*` columns |
| `CHANGED_BY` | no | `CREATED_BY` (`NOT NULL`) |
| `CHANGE_REASON` | no | `REASON_CODE` + `COMMENTS` |

Three mandatory columns (`HIST_ID`, `EFFECTIVE_DATE`, `CREATED_BY`) are absent from the insert lists entirely.

**Issue:** `TRG_EMP_BEFORE_UPDATE` cannot compile — every one of its three history inserts fails with `ORA-00904: invalid identifier`. The trigger is therefore in an `INVALID`/`ERROR` state, and because it is a `BEFORE UPDATE` trigger on `EMPLOYEES`, its invalidity makes **every** update to `EMPLOYEES` fail at run time until the trigger is dropped or disabled — which is almost certainly what has happened in the live environment, silently disabling all employee change history. The correct column list is not unknown: `PKG_EMPLOYEE.log_history` (`plsql/packages/PKG_EMPLOYEE.pkb:137-180`) inserts the right 18 columns, so two writers to the same table disagree.

**Impact:** No auditable record of salary, department, job, or manager changes from any path other than `PKG_EMPLOYEE`. This is a direct SOX/SOC 2 audit-trail failure, and it is unrecoverable retroactively — the history for the affected period does not exist anywhere.

**Recommendation:** Rewrite all three inserts to the real column list, sourcing `HIST_ID` from `SEQ_EMP_HISTORY`, mapping old/new values into the typed columns, and setting `EFFECTIVE_DATE`/`CREATED_BY`. Better: delete the trigger's history logic and route all history through `PKG_EMPLOYEE.log_history`, which already works, so there is one writer. Add a deployment gate that fails the build on any `INVALID` object in `USER_OBJECTS` — this defect is trivially detectable and was shipped.

### ARCH-02 — CRITICAL — Seed data references columns that do not exist and omits mandatory ones

**Location:** `data/seed/01_reference_data.sql` (lines 11-17, 23-42, 182-200) vs `schema/tables/01_core_tables.sql`

| Seed target | Line(s) | Column in seed | Status vs DDL |
|---|---|---|---|
| `LOCATIONS` | 11, 14, 17 | `PHONE` | does not exist (DDL: `PHONE_NUMBER`) |
| `JOB_GRADES` | 23-42 (10 rows) | `GRADE_LEVEL` | does not exist |
| `JOB_GRADES` | 23-42 (10 rows) | `GRADE_CODE` | **missing** from insert, `NOT NULL` in DDL |
| `SYSTEM_PARAMETERS` | 182-200 (10 rows) | `DESCRIPTION` | does not exist (DDL: `PARAM_DESCRIPTION`) |

```sql
INSERT INTO JOB_GRADES (GRADE_ID, GRADE_NAME, GRADE_LEVEL, MIN_SALARY, MAX_SALARY, ...)
VALUES (1, 'Entry Level', 1, 35000, 55000, ...);
```

**Issue:** 23 insert statements fail — `ORA-00904` for the three non-existent columns and `ORA-01400` for the omitted `NOT NULL` `GRADE_CODE`. The reference data script cannot run against the schema the repository defines, so a clean install produces a database with no locations, no job grades, and no system parameters.

**Impact:** The documented install path is broken: without `JOB_GRADES` rows nothing can be hired (grade lookup fails in `create_employee`), and without `SYSTEM_PARAMETERS` every `PKG_COMMON.get_param` call returns nothing, disabling integrations. Any environment currently running must have been provisioned by hand, so no environment matches source control — the schema in production is unknown.

**Recommendation:** Reconcile in the direction the code expects: rename the seed columns to `PHONE_NUMBER` and `PARAM_DESCRIPTION`, supply `GRADE_CODE`, and **add `JOB_GRADES.GRADE_LEVEL` to the DDL** — SEC-08 shows the authorization logic needs an ordinal level and is abusing `GRADE_ID` in its absence. Then add CI that runs the full DDL + seed sequence against a disposable database on every commit; both ARCH-01 and ARCH-02 would have been caught by a single such run.

### ARCH-03 — HIGH — Auto-approval path always raises

**Location:** `plsql/packages/PKG_LEAVE.pkb:199-201` with `:226`

```sql
-- Auto-approve if no approval required
IF v_leave_type.REQUIRES_APPROVAL = 'N' THEN
    approve_leave_request(v_request_id, NULL, 'Auto-approved', p_user);
END IF;
```

`approve_leave_request` validates the request status before approving, and raises `ORA-20204` when the status is not `PENDING` (line 226). But `submit_leave_request` has already inserted the row with `CASE WHEN v_leave_type.REQUIRES_APPROVAL = 'Y' THEN 'PENDING' ELSE 'APPROVED' END` (line 170) — so for `REQUIRES_APPROVAL = 'N'` the row is already `APPROVED` when the auto-approval call runs.

**Issue:** Every submission of a no-approval leave type (typically bereavement, jury duty, unpaid) raises `ORA-20204` after the insert. Depending on the caller's exception handling, the user sees an error for a request that was in fact created, or the whole transaction rolls back.

**Impact:** An entire class of leave type is unusable through the normal path, and the failure mode is confusing — the leave sometimes exists despite the error, so users resubmit and create duplicates (which the overlap check may or may not catch, see DATA-05).

**Recommendation:** Delete the auto-approval call — line 170 already sets the correct terminal status — and move the side effects that approval performs (balance movement from `PENDING` to `USED`, notification) into a shared private procedure invoked by both paths.

### ARCH-04 — MEDIUM — `PRAGMA AUTONOMOUS_TRANSACTION` used for all logging, with exceptions swallowed

**Location:** `plsql/packages/PKG_AUDIT.pkb:14`; `PKG_COMMON.pkb:16`, `:46`; `PKG_NOTIFICATION.pkb:27`; `PKG_EMPLOYEE.pkb:155`

```sql
PROCEDURE log_history(...) IS
    PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
    INSERT INTO EMPLOYEE_HISTORY (...) VALUES (...);
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN ROLLBACK; ...
END;
```

**Issue:** Five procedures across four packages run in autonomous transactions and commit independently of the caller. This is defensible for audit logging (the record should survive a rolled-back business transaction) but it is applied uniformly, including to `PKG_NOTIFICATION.send_notification` — so a notification is queued and committed even when the triggering business change is subsequently rolled back. Each one also traps `WHEN OTHERS` and continues, so failures are invisible.

**Impact:** Notifications sent for events that never happened ("Your leave was approved" for a rolled-back approval). Autonomous transactions also cannot see the parent's uncommitted data, so audit rows may reference rows that do not yet exist, and they consume a separate transaction slot per call, increasing undo pressure during the payroll loop (PERF-06).

**Recommendation:** Keep autonomous transactions for `PKG_AUDIT` and `PKG_COMMON.log_error` only. Make `send_notification` enlist in the caller's transaction so the queue row commits with the business change. Replace `WHEN OTHERS` with logging that at minimum increments a failure counter visible to monitoring.

### ARCH-05 — MEDIUM — Soft delete implemented as a raising trigger with a misleading name

**Location:** `plsql/triggers/trg_employees.sql:120-130`

```sql
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
BEFORE DELETE ON HRMS.EMPLOYEES
...
    RAISE_APPLICATION_ERROR(-20504, ...);
```

**Issue:** The trigger is named `INSTEAD_OF` but is a `BEFORE DELETE` trigger that unconditionally raises — it blocks deletes rather than converting them to soft deletes. `INSTEAD OF` triggers are only valid on views, so the name describes an intent the implementation cannot fulfil. Callers wanting a soft delete must know to call `terminate_employee` instead; nothing enforces or documents that at the point of failure beyond the error text.

**Impact:** Legitimate data-correction deletes (duplicate records created by RACE-01/RACE-04) require DBA intervention to disable the trigger, and the misnomer misleads maintainers into thinking a soft-delete redirect exists.

**Recommendation:** Rename to `TRG_EMP_PREVENT_DELETE`, and make the error message name the supported alternative (`PKG_EMPLOYEE.terminate_employee`). If true soft-delete-on-delete semantics are wanted, expose an updatable view with a genuine `INSTEAD OF DELETE` trigger.

### ARCH-06 — MEDIUM — Flat-file integration via `UTL_FILE` with no retry, acknowledgment, or checksum

**Location:** `plsql/packages/PKG_INTEGRATION.pkb` (GL journal export, benefits export, time-attendance import); `PKG_PAYROLL.pkb:823-895` (pay register); `PKG_INTEGRATION.pks:9-13`

```sql
-- Known issues:
--   - GL posting uses flat file exchange (UTL_FILE) instead of API
--   - Benefits feed format is vendor-specific (ADP format)
--   - No retry logic for failed file transfers
```

**Issue:** Four separate integrations write or read files from database-server directories. There is no transactional coupling between the database state and the file, no checksum or record-count trailer, no acknowledgment from the receiving system, and no retry. `UTL_FILE` failures are handled by closing the handle and returning.

**Impact:** Payroll and GL data can be silently half-transmitted — the database believes the export succeeded while finance receives a truncated file. Reconciliation is manual and after the fact. The pattern also requires database-server filesystem access, blocking any move to a managed/cloud database.

**Recommendation:** Add a record count and hash trailer to every file plus an `INTEGRATION_RUNS` table tracking `SENT`/`ACKNOWLEDGED`/`FAILED` with retry counts, as an interim control. Target state: replace file exchange with authenticated REST calls from a middle tier, keeping the database out of the integration path.

### ARCH-07 — MEDIUM — 2024 federal tax brackets hard-coded while a `TAX_BRACKETS` table exists

**Location:** `plsql/packages/PKG_PAYROLL.pkb:605-700`

```sql
-- NOTE: Hard-coded 2024 brackets - should read from TAX_BRACKETS table
...
-- TODO: Read from TAX_BRACKETS table instead of hard-coding
```

**Issue:** Bracket thresholds and rates are literals in the package body, filing-status handling is partial, and `TAX_BRACKETS` (11 columns, defined in `schema/tables/02_payroll_tables.sql`) is unused. There is no effective-dating, so a bracket change requires a code deployment mid-year.

**Impact:** Withholding is wrong for every tax year after 2024 — under-withholding creates employee tax liabilities and employer penalty exposure. Because the values are in compiled code, there is no audit record of which rates were applied to a historical run.

**Recommendation:** Populate `TAX_BRACKETS` with effective-dated rows keyed by `(TAX_YEAR, FILING_STATUS, BRACKET_FLOOR)`, read them in `calculate_tax`, and store the applied `TAX_YEAR` on `PAYROLL_DETAILS` so historical runs remain explainable. Add a payroll-run precondition that fails if no brackets exist for the run's year.

### ARCH-08 — LOW — Time-attendance import is a stub that reports success

**Location:** `plsql/packages/PKG_INTEGRATION.pkb:165-180`

```sql
-- TODO: Implement actual parsing and database update
v_imported := v_imported + 1;
```

**Issue:** The procedure reads the file, increments a counter, and returns the count as if records were imported. Nothing is parsed or persisted.

**Impact:** Operators see "N records imported" while no timekeeping data reaches the database, so payroll runs on missing hours data — and monitoring built on the return value reports healthy.

**Recommendation:** Raise `ORA-20xxx 'Not implemented'` until the parser exists, so the gap is visible. Then implement with per-record error capture into a staging table rather than an aggregate count.

### ARCH-09 — LOW — Termination leaves three required downstream actions as TODOs

**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:737-739`

```sql
-- TODO: Integrate with benefits system to trigger COBRA
-- TODO: Revoke system access via PKG_SECURITY
-- TODO: Calculate final pay via PKG_PAYROLL.calculate_final_pay
```

**Issue:** `terminate_employee` updates status and history but performs none of the offboarding steps. Each is a compliance or security obligation: COBRA notification is statutory, access revocation is a security control (see SEC-13), final pay is often deadline-bound by state law.

**Impact:** Every termination requires three manual follow-ups with no tracking; missed COBRA notices and un-revoked access are the failure modes that surface in audits.

**Recommendation:** Implement access revocation first (smallest, highest risk — closes SEC-13's revocation gap, via the leaf package from CIRC-02). Record the remaining obligations in an `OFFBOARDING_TASKS` table with due dates so manual steps are at least tracked while unimplemented.

### ARCH-10 — LOW — Fiscal year start hard-coded to October 1

**Location:** `plsql/packages/PKG_COMMON.pkb:170-179`; also `PKG_REPORTING.pks:9`

```sql
IF EXTRACT(MONTH FROM p_date) >= 10 THEN
    RETURN EXTRACT(YEAR FROM p_date) + 1;
ELSE
    RETURN EXTRACT(YEAR FROM p_date);
END IF;
```

**Issue:** The October boundary is embedded in a shared utility and duplicated in reporting logic. Any entity with a different fiscal calendar — an acquisition, an international subsidiary — cannot be supported without a code change, and the duplication guarantees the two will drift.

**Impact:** Blocks multi-entity consolidation; a fiscal calendar change becomes a code release touching reporting, leave accrual, and payroll period logic.

**Recommendation:** Read the fiscal start month from `SYSTEM_PARAMETERS` and make `get_fiscal_year` the only implementation, called by reporting.

### ARCH-11 — LOW — Notification templates and delivery policy embedded in package constants

**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:7-20`; `PKG_NOTIFICATION.pks:9-11`

**Issue:** Message bodies and HTML fragments are string constants in the body alongside the SMTP configuration (SEC-10), with no rate limiting or de-duplication on `NOTIFICATION_QUEUE`.

**Impact:** Any wording change — including legally reviewed language — requires a package deployment; a batch job bug can emit thousands of duplicate emails with nothing to stop it.

**Recommendation:** Move templates into a `NOTIFICATION_TEMPLATES` table keyed by type and locale, and add a per-recipient-per-type rate limit checked before enqueue.

---

## 7. Data Integrity Risks

### DATA-01 — HIGH — `VW_LEAVE_SUMMARY.AVAILABLE` omits `PENDING`, contradicting the base table

**Location:** `schema/views/hrms_views.sql:86-100` (expression at line 96) vs `schema/tables/03_leave_tables.sql` (`LEAVE_BALANCES.AVAILABLE`)

```sql
-- View
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,
```

```sql
-- Table (virtual column, authoritative)
AVAILABLE NUMBER(6,2) GENERATED ALWAYS AS
    (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL,
```

**Issue:** Two columns with the same name and different formulas. The view omits `- PENDING`, so it reports leave that is already committed to submitted requests as available. Both are queried by different consumers: `PKG_LEAVE.get_leave_balance` reads the table column, while reports and Forms LOVs read the view.

**Impact:** Employees and managers see an inflated balance and submit requests the server-side check then rejects — or, where the view feeds an approval decision, leave is approved beyond entitlement, producing negative balances that must be clawed back. The discrepancy equals the employee's total pending days, so it is largest exactly when it matters (peak request season).

**Recommendation:** Change the view to `lb.AVAILABLE` — select the virtual column directly rather than recomputing it, eliminating the possibility of drift. Audit all consumers for reliance on the inflated value, and add a regression test asserting `view.AVAILABLE = table.AVAILABLE` for all rows.

### DATA-02 — HIGH — Leave balances are keyed by the request's start-date year

**Location:** `plsql/packages/PKG_LEAVE.pkb:182`, `:248`, `:302`, `:352`, `:360`

```sql
UPDATE LEAVE_BALANCES SET PENDING = PENDING + v_total_days, ...
WHERE EMP_ID = p_emp_id AND LEAVE_TYPE_ID = p_leave_type_id
AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```

**Issue:** Every balance movement — pending on submit, pending→used on approve, reversal on cancel — targets the single `CALENDAR_YEAR` derived from `START_DATE`. `UK_LEAVE_BAL` makes `(EMP_ID, LEAVE_TYPE_ID, CALENDAR_YEAR)` unique, so a request spanning December 28 to January 4 charges all its days to the earlier year.

**Impact:** Year-end leave is deducted from the wrong entitlement: the prior year is over-consumed (possibly beyond its balance) while the new year's allocation is untouched. Because the same wrong year is used consistently across submit/approve/cancel, the error is self-consistent and therefore invisible to reconciliation — it surfaces only as unexplained year-end balance discrepancies.

**Recommendation:** Split multi-year requests at the year boundary and apply days to each year's balance proportionally, or (simpler and auditable) reject cross-year requests at submission with a message directing the user to submit one request per year. Add a check that the sum of `LEAVE_REQUESTS` days per year reconciles to `LEAVE_BALANCES.USED`.

### DATA-03 — HIGH — Balance updates are silent no-ops when no balance row exists

**Location:** `plsql/packages/PKG_LEAVE.pkb:176-182` (and the same pattern at `:248`, `:302`, `:352`)

```sql
UPDATE LEAVE_BALANCES
SET PENDING = PENDING + v_total_days, MODIFIED_BY = p_user, MODIFIED_DATE = SYSDATE
WHERE EMP_ID = p_emp_id AND LEAVE_TYPE_ID = p_leave_type_id
AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
-- no SQL%ROWCOUNT check
```

**Issue:** `SQL%ROWCOUNT` is never inspected. If no `LEAVE_BALANCES` row exists for that employee/type/year — a new hire before accrual initialization, a newly added leave type, or a cross-year request per DATA-02 — the update affects zero rows and the procedure continues to a successful commit. The `LEAVE_REQUESTS` row is created with no corresponding balance movement.

**Impact:** Leave is granted and taken with no balance impact whatsoever: the employee's entitlement is never decremented, so the request is effectively free and unlimited. `LEAVE_REQUESTS` and `LEAVE_BALANCES` diverge permanently, and the divergence is undetectable from either table alone.

**Recommendation:** After every balance update, `IF SQL%ROWCOUNT = 0 THEN RAISE_APPLICATION_ERROR(...)` — or auto-create the balance row from `LEAVE_TYPES` defaults inside the same transaction. Add a nightly reconciliation query comparing approved request days to `USED` per employee/type/year and alerting on mismatch.

### DATA-04 — MEDIUM — Half-day flag overrides the entire date range

**Location:** `plsql/packages/PKG_LEAVE.pkb:128-134`

```sql
IF p_half_day_flag = 'Y' THEN
    v_total_days := 0.5;
ELSE
    v_total_days := calculate_business_days(p_start_date, p_end_date, v_emp_rec.LOCATION_CODE);
END IF;
```

**Issue:** When `p_half_day_flag = 'Y'` the computed total is `0.5` regardless of `p_start_date` and `p_end_date`. Nothing validates that a half-day request is a single day, so a two-week request with the flag set is charged half a day.

**Impact:** Trivially exploitable under-charging of leave (set the half-day checkbox on a long request), and even without intent, a user who leaves the flag set from a previous entry gets weeks of unrecorded absence.

**Recommendation:** Reject `p_half_day_flag = 'Y'` when `TRUNC(p_end_date) != TRUNC(p_start_date)`, and compute `days - 0.5` for ranges where only the first or last day is a half day (which is what the `p_half_day_period` parameter implies was intended).

### DATA-05 — MEDIUM — Overlap detection ignores half-day periods

**Location:** `plsql/packages/PKG_LEAVE.pkb` (`check_overlap`) vs `PKG_LEAVE.pks` (`p_half_day_flag`, `p_half_day_period` parameters)

```sql
SELECT COUNT(*) INTO v_count FROM LEAVE_REQUESTS
WHERE EMP_ID = p_emp_id AND STATUS IN ('PENDING', 'APPROVED')
AND (p_exclude_request_id IS NULL OR REQUEST_ID != p_exclude_request_id)
AND START_DATE <= p_end_date AND END_DATE >= p_start_date;
```

**Issue:** The overlap function compares dates only; its signature accepts no half-day information even though `submit_leave_request` does. Two genuinely compatible morning/afternoon half-days on the same date are reported as overlapping and rejected, while the reverse case (two half-days claimed for the same period) cannot be distinguished either.

**Impact:** Valid split-day leave is blocked, pushing users to record full days instead — over-charging entitlement and corrupting absence data used for payroll and capacity planning.

**Recommendation:** Add `HALF_DAY_FLAG`/`HALF_DAY_PERIOD` to the overlap predicate so same-date requests conflict only when their periods intersect, and add a unique constraint or check preventing two `AM` (or two `PM`) requests on one date.

### DATA-06 — MEDIUM — Observed holidays are not recognized

**Location:** `plsql/packages/PKG_LEAVE.pkb:15-40` (documented in-code)

```sql
-- BUG: Does not handle "observed" holidays (e.g., if July 4 falls on
-- Saturday, the observed Friday is not excluded)
```

**Issue:** `HOLIDAYS` (8 columns) stores only actual dates, with no observed-date column. Weekend-falling holidays are skipped twice over: the actual date is already excluded as a weekend, and the observed weekday is counted as a working day.

**Impact:** Employees are charged leave for company holidays roughly two days per year, and business-day calculations disagree with the payroll calendar.

**Recommendation:** Add `OBSERVED_DATE` to `HOLIDAYS` (defaulting to `HOLIDAY_DATE`), populate it for weekend-falling holidays, and match on `OBSERVED_DATE` in all business-day logic — including the consolidated implementation from PERF-01.

### DATA-07 — MEDIUM — History logging failures are swallowed

**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:155-180`

```sql
PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
    INSERT INTO EMPLOYEE_HISTORY (...) VALUES (...);
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK;
        IF g_debug_mode THEN
            DBMS_OUTPUT.PUT_LINE('WARNING: Failed to log history for EMP_ID=' || ...);
        END IF;
END log_history;
```

**Issue:** Any failure to record history is discarded; the warning goes to `DBMS_OUTPUT` and only when `g_debug_mode` is on, so in production it goes nowhere. The business change commits regardless. This is the *working* history writer — combined with ARCH-01 (the broken trigger), a silent failure here means no history exists from any source.

**Impact:** Undetectable gaps in the change history for salary and organizational changes, which is precisely the data an audit samples.

**Recommendation:** Log the failure via `PKG_COMMON.log_error` (autonomous, so it survives), and treat history-write failure as fatal to the business transaction for salary changes specifically — a compensation change with no audit record should not be allowed to commit.

### DATA-08 — MEDIUM — Out-of-range salaries are accepted with a debug-only warning

**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:225-245`

```sql
IF p_base_salary < v_min OR p_base_salary > v_max THEN
    -- NOTE: This is a soft warning, not an error
    -- Forms trigger WHEN-VALIDATE-ITEM shows warning dialog
    -- but allows override with manager approval
    IF g_debug_mode THEN
        DBMS_OUTPUT.PUT_LINE('WARNING: Salary ' || p_base_salary ||
            ' outside grade range [' || v_min || '-' || v_max || ']');
    END IF;
END IF;
```

**Issue:** The only enforcement of grade salary bands is a `DBMS_OUTPUT` line emitted when debug mode is on. The comment describes a Forms override-with-approval workflow, but no approval is requested, recorded, or verified anywhere — and the direct-insert path (RACE-04) bypasses even the dialog.

**Impact:** Salaries outside approved bands are persisted with no record of an exception being granted. Pay-equity and budget controls are unenforced, and there is no data to identify which salaries were overrides.

**Recommendation:** If overrides are legitimate, model them: require an `OVERRIDE_APPROVED_BY` argument, reject the change without it, and store it on `SALARY_RECORDS` so exceptions are queryable. Otherwise raise an error.

### DATA-09 — MEDIUM — Compensation views can multiply employee rows

**Location:** `schema/views/hrms_views.sql:10-40` (`VW_ACTIVE_EMPLOYEES`), `:63-84` (`VW_EMPLOYEE_COMPENSATION`)

**Issue:** Both views join `EMPLOYEES` to `SALARY_RECORDS` filtered on `ACTIVE_FLAG = 'Y'`. Nothing in `schema/tables/02_payroll_tables.sql` constrains an employee to a single active salary record — no unique index on `(EMP_ID, ACTIVE_FLAG)` and no exclusion of overlapping effective dates. `PKG_PAYROLL.create_salary_record` is the only writer that deactivates prior rows, and RACE-04's direct-insert path does not create salary records at all.

**Impact:** An employee with two active salary rows appears twice in headcount views, double-counting them in headcount and doubling their contribution to compensation totals. Because the duplication depends on data state, reports are intermittently wrong with no error.

**Recommendation:** Enforce one active record per employee with a unique function-based index (`CASE WHEN ACTIVE_FLAG='Y' THEN EMP_ID END`), and defensively pick the latest by `EFFECTIVE_DATE` in the views. Add a data-quality check for employees with zero or multiple active salary records.

### DATA-10 — MEDIUM — Two soft-delete markers, inconsistently applied

**Location:** `EMPLOYEES.ACTIVE_FLAG` and `EMPLOYEES.EMPLOYMENT_STATUS` (`schema/tables/01_core_tables.sql`); consumers in `schema/views/hrms_views.sql:47-60`, `plsql/triggers/trg_employees.sql:44-52`, `plsql/packages/PKG_PAYROLL.pkb:295-300`

```sql
-- VW_ORG_HIERARCHY: status only
WHERE ... START WITH MANAGER_EMP_ID IS NULL ... -- EMPLOYMENT_STATUS = 'ACTIVE'

-- Email uniqueness trigger: flag only
WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL) AND ACTIVE_FLAG = 'Y';

-- Payroll cursor: both
WHERE e.EMPLOYMENT_STATUS = 'ACTIVE' AND e.ACTIVE_FLAG = 'Y'
```

**Issue:** Two independent columns encode overlapping meaning, with no constraint tying them together (nothing prevents `ACTIVE_FLAG='Y'` with `EMPLOYMENT_STATUS='TERMINATED'`). Different consumers filter on one, the other, or both, so "active employee" has three definitions. `EMPLOYMENT_STATUS` additionally carries `ON_LEAVE` and `SUSPENDED`, which the flag cannot express.

**Impact:** Headcount differs between screens; a partially-terminated record (one marker updated) can be paid by payroll while absent from the org chart, or block email reuse indefinitely. Reconciling reports against each other is impossible.

**Recommendation:** Make `EMPLOYMENT_STATUS` authoritative, derive `ACTIVE_FLAG` from it via a virtual column (or drop it after migrating consumers), and add a check constraint asserting consistency during the transition. Define "active" once, in a view every consumer uses.

### DATA-11 — LOW — YTD accumulations assume full-year employment

**Location:** `plsql/packages/PKG_PAYROLL.pkb` (`calculate_employee_pay` YTD accumulation)

**Issue:** Year-to-date figures are accumulated from `PAYROLL_DETAILS` within the database's calendar year with no handling for mid-year hires, rehires, or prior-employer amounts, and no `YTD_START_DATE` on the employee record.

**Impact:** Withholding calculations that depend on YTD totals (annualized-wage methods, wage-base-limited taxes) are wrong for employees hired mid-year — an under- or over-withholding that surfaces at year-end filing.

**Recommendation:** Store an explicit YTD basis per employee per tax year and initialize it at hire/rehire; reconcile against `PAYROLL_DETAILS` rather than deriving from it.

### DATA-12 — LOW — Overtime and holiday pay rules are implicit

**Location:** `plsql/packages/PKG_PAYROLL.pkb` (pay element processing); `PAY_ELEMENTS` (17 columns)

**Issue:** Multipliers and eligibility for overtime and holiday premiums are applied in procedural code rather than driven by `PAY_ELEMENTS` configuration, with no jurisdiction dimension (state overtime rules differ) and no effective dating.

**Impact:** Multi-state compliance risk, and rule changes require code deployment with no historical record of the rule applied to a past run.

**Recommendation:** Drive premium calculation from effective-dated `PAY_ELEMENTS` rows including jurisdiction, and stamp the applied element version on `PAYROLL_DETAILS`.

### DATA-13 — MEDIUM — `VW_PAYROLL_LATEST` defines "latest" by maximum `RUN_ID`

**Location:** `schema/views/hrms_views.sql:109-130`

```sql
WHERE pr.RUN_ID = (
    SELECT MAX(pr2.RUN_ID) FROM PAYROLL_RUNS pr2 WHERE pr2.STATUS = 'APPROVED')
```

**Issue:** The subquery selects the highest surrogate key across all approved runs globally, ignoring `PAY_PERIODS` dates and run type. An off-cycle run (bonus, correction, termination final pay) approved after a regular run has a higher `RUN_ID` and therefore becomes "latest", as does a late-approved run for an earlier period.

**Impact:** Screens and reports labelled "latest payroll" show a bonus-only or single-employee correction run as the current payroll, understating totals and omitting most employees. There is also no period scoping, so the view cannot answer "latest run for period X" at all.

**Recommendation:** Determine latest by the pay period's `END_DATE` (tie-broken by `RUN_ID`) and restrict to regular run types, or parameterize the view by period — e.g. `ROW_NUMBER() OVER (PARTITION BY pr.PERIOD_ID ORDER BY pp.END_DATE DESC, pr.RUN_ID DESC)` — so consumers select explicitly.

---

## Corrections to In-Code Annotations

The source contains many `-- BUG:` / `-- NOTE:` comments. Several do not match the code as written; a maintainer trusting them would fix the wrong thing. Verified corrections:

| Location | Comment claims | Verified reality |
|---|---|---|
| `HRMS_VALIDATION_LIB.pll.sql` (`validate_email`) | "rejects valid subdomains" | `user@mail.company.com` **passes**. The real drift is the opposite: the client is more permissive than the server regex, and treats `NULL` as valid (DRIFT-01). |
| `HRMS_VALIDATION_LIB.pll.sql` (`validate_salary_range`) | Uses a stale startup cache | No cache exists; the function queries `JOB_GRADES` on every call. The real defect is NULL-handling drift (DRIFT-02). |
| `PKG_SECURITY.pks:12` | "Password stored as MD5 hash" | No password is stored or compared anywhere; `hash_password` is unreferenced. The defect is far more severe than weak hashing (SEC-01). |
| `PKG_LEAVE.pkb:610-623` (`expire_carryover`) | Implied repeatable double-expiry | The `CARRYOVER_FROM_PREV > 0` predicate prevents a second sequential subtraction. The real risks are concurrent execution and destroyed audit basis (RACE-03). |
| `PKG_EMPLOYEE.pkb:442` | SQL injection "possible via `p_last_name`" | Five string parameters plus `p_dept_id` are injectable, not one (SEC-04). |
| `PKG_PAYROLL.pkb:241` area | — (no annotation) | Unflagged race: `close_pay_period` locks its row, `create_payroll_run` does not (RACE-02). |
| `trg_employees.sql:120` | Name asserts `INSTEAD OF DELETE` | It is a `BEFORE DELETE` trigger that raises; `INSTEAD OF` is not valid on tables (ARCH-05). |

Two defects carry **no** annotation at all and are the highest-impact findings in the report: ARCH-01 (trigger/DDL column mismatch) and ARCH-02 (seed/DDL column mismatch). Both are mechanically detectable — see the CI recommendation in Phase 2.

---

## Prioritized Migration Roadmap

Effort is expressed in engineering sessions (one session ≈ a focused day of implementation plus verification), not calendar time. Sequencing matters more than the estimates: Phase 2's CI gate is what prevents Phase 1's fixes from regressing.

### Phase 1 — Critical Security (blocking; nothing else ships first)

| Order | Findings | Work | Sessions |
|---|---|---|---|
| 1 | SEC-01, SEC-02, SEC-05, SEC-06, SEC-07 | Stand up a real credential/identity path: IdP integration at the Forms tier, or `USER_CREDENTIALS` with adaptive hashing, lockout, and constant-time failure. Delete `hash_password`. Make `change_password` fail loudly until backed. | 3-4 |
| 2 | SEC-04 | Rewrite `search_employees` with bind variables; grep the codebase for other `OPEN ... FOR`/`EXECUTE IMMEDIATE` concatenation. | 1 |
| 3 | SEC-03 | Replace the hard-coded key with wallet-sourced material or TDE; fix the key length; remove the swallowing handler; assess whether any `SSN_ENCRYPTED` data was ever written. | 1-2 |
| 4 | SEC-08 | Replace grade-threshold checks with an explicit role model. | 2 |
| 5 | SEC-09, SEC-10, SEC-11 | Require Oracle Net encryption; move SMTP and transfer credentials out of source and out of `SYSTEM_PARAMETERS` into the wallet. | 1 |
| 6 | SEC-13, SEC-12 | Add `LAST_ACTIVITY_TIME` and revocation on terminate/password-change; convert audit payloads to `JSON_OBJECT`. | 1 |

**Exit criteria:** no authentication path succeeds without credential verification; no credential or key literal remains in source; injection scan clean.

### Phase 2 — Data Integrity (immediately after Phase 1; several items are one-line fixes with large blast radius)

| Order | Findings | Work | Sessions |
|---|---|---|---|
| 1 | ARCH-02 | Reconcile seed script and DDL (including adding `JOB_GRADES.GRADE_LEVEL`, which SEC-08 needs); verify a clean install from scratch. | 0.5 |
| 2 | **CI gate** | Run full DDL + seed + package compile against a disposable database on every commit; fail the build on any `INVALID` object or seed error. This alone would have caught ARCH-01 and ARCH-02. | 1 |
| 3 | ARCH-01, DATA-07 | Route all employee history through `PKG_EMPLOYEE.log_history`; delete the trigger's broken inserts; make history-write failure fatal for salary changes. Assess and document the historical audit gap. | 1-2 |
| 4 | DATA-01 | Change `VW_LEAVE_SUMMARY` to select `lb.AVAILABLE`; add the view-vs-table regression assertion. | 0.5 |
| 5 | DATA-03, DATA-02 | Add `SQL%ROWCOUNT` guards to every balance update; handle or reject cross-year requests; run a full reconciliation of `LEAVE_REQUESTS` against `LEAVE_BALANCES` and correct historical drift. | 2 |
| 6 | ARCH-03, DATA-04, DATA-05, DATA-06 | Fix the auto-approval path; constrain the half-day flag; make overlap detection half-day aware; add `HOLIDAYS.OBSERVED_DATE`. | 2 |
| 7 | RACE-01, RACE-04 | Switch to `SEQ_EMP_NUMBER`; make `PKG_EMPLOYEE.create_employee` the only writer to `EMPLOYEES` and repoint the Forms block at it. | 1-2 |
| 8 | RACE-02, RACE-03, DATA-08, DATA-09, DATA-10, DATA-13 | Add the missing `FOR UPDATE`; serialize and audit carryover expiry; enforce salary bands and one-active-salary-record; unify the soft-delete marker; correct `VW_PAYROLL_LATEST`. | 3 |

**Exit criteria:** clean install from source succeeds; zero `INVALID` objects; leave and payroll reconciliation queries return no discrepancies.

### Phase 3 — Performance (safe to parallelize with late Phase 2)

| Order | Findings | Work | Sessions |
|---|---|---|---|
| 1 | PERF-06, ARCH-07 | Make payroll set-based and single-commit with a restart marker; move tax brackets into `TAX_BRACKETS` with effective dating. | 3 |
| 2 | PERF-01, PERF-02, PERF-03, DRIFT-04 | One consolidated, set-based business-day implementation used by every caller and both validation layers. | 1-2 |
| 3 | PERF-05, ARCH-04 | Single SMTP session per queue drain with per-message retry state; make `send_notification` transactional. | 1 |
| 4 | PERF-04 | `NOCYCLE`, fix the active-manager pruning, materialize the hierarchy. | 1-2 |
| 5 | PERF-07, PERF-08 | Cache the hot sequences; expose report freshness or convert to fast-refresh MVs. | 1 |

**Exit criteria:** payroll run is atomic and restartable; nightly accrual and payroll windows measured and within budget.

### Phase 4 — Modernization (after the estate is safe and correct)

| Order | Findings | Work | Sessions |
|---|---|---|---|
| 1 | CIRC-01, CIRC-02 | Extract shared validation and session-context primitives into leaf packages; invert the creation flow to break both cycles. Prerequisite for everything below. | 2-3 |
| 2 | DRIFT-01, DRIFT-02, DRIFT-03 | Single source of truth for every validation rule; PLL libraries delegate to packages; add the missing database constraints. | 2 |
| 3 | ARCH-06, ARCH-08, SEC-11 | Replace `UTL_FILE` exchange with authenticated API calls from a middle tier; implement the time-attendance parser or make it fail loudly; add `INTEGRATION_RUNS` tracking. | 3-4 |
| 4 | ARCH-09, ARCH-10, ARCH-11, DATA-11, DATA-12 | Implement offboarding automation; externalize fiscal calendar, templates, and pay rules into configuration. | 3 |
| 5 | SEC-14, SEC-15 | Complete the identity-provider boundary defined in Phase 1; proper error handling in the Forms tier. | 2 |
| 6 | — | Forms retirement: with cycles broken and packages behaving as services, migrate module by module (Leave → Performance → Employee → Payroll), keeping PL/SQL as the data layer behind an API. | separate program |

**Exit criteria:** no validation rule implemented twice; no package cycle; no file-based integration; Forms modules replaceable independently.

---

## Verification Performed

- Trigger and package `INSERT` column lists were extracted programmatically and diffed against parsed `CREATE TABLE` DDL across all 30 tables; every mismatch reported (ARCH-01, ARCH-02) is a confirmed structural difference, and `UPDATE ... SET` column lists were checked by the same method and are clean.
- Seed inserts were additionally checked for omitted `NOT NULL` columns without defaults (`JOB_GRADES.GRADE_CODE`).
- `sqlfluff lint --dialect oracle .` and `find forms/xml-exports -name '*.xml' -exec xmllint --noout {} +` were run per the repository blueprint; the only parse limitation is the known `GENERATED ALWAYS AS ... VIRTUAL` construct in `schema/tables/03_leave_tables.sql`.
- No Oracle database is available in this environment, so findings are static-analysis based. Runtime claims are derived from Oracle semantics (invalid identifier on missing columns, invalid key size for a 30-byte AES-256 key) rather than observed execution, and are marked as such where relevant.

**Not covered by this report:** `PKG_PERFORMANCE` and `PKG_REPORTING` bodies were reviewed only for the patterns in scope (fiscal year, staleness, hierarchy) and may hold additional debt; the Oracle Reports `.rdf` definitions and WebLogic deployment descriptors are not present in the repository; no dynamic profiling or penetration testing was performed.
