# Technical Debt Report — Oracle Forms HRMS

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Analysis date:** 2026-09-07
**Estate analyzed:** 11 PL/SQL packages (spec + body), 2 trigger scripts, 30 tables, 6 views, 29 sequences, 6 Oracle Forms XML exports, 2 PLL libraries, seed data scripts
**Method:** static source review of the repository at `main`; every finding below cites the current file and line numbers. Column-level claims were verified by mechanically diffing DML column lists against `CREATE TABLE` DDL.

---

## 1. Executive Summary

The codebase is a representative Oracle Forms 12c / Oracle DB 19c HRMS estate. Analysis found **50 findings**, including **7 CRITICAL** defects that make core flows either insecure or outright non-functional against the shipped schema.

The most consequential results are not the well-known legacy smells (MD5, `UTL_FILE` feeds, `CONNECT BY`) but four hard defects that the in-code comments do *not* mention:

1. `PKG_SECURITY.authenticate` **never verifies the password** — it looks the user up by email and issues a session. Every credential is accepted.
2. The hard-coded AES key is **30 bytes**, so `encrypt_ssn`/`decrypt_ssn` cannot execute at all under `ENCRYPT_AES256` (32-byte key required).
3. `TRG_EMP_BEFORE_UPDATE` inserts into `EMPLOYEE_HISTORY` using **six column names that do not exist**, and the seed data script references **three more** non-existent columns — both fail at runtime.
4. `PKG_EMPLOYEE.rehire_employee` is blocked by `TRG_EMP_BEFORE_UPDATE`, the very trigger that names it as the sanctioned rehire path — rehire can never succeed.

### Severity counts

| Severity | Count |
|---|---|
| CRITICAL | 7 |
| HIGH | 17 |
| MEDIUM | 21 |
| LOW | 5 |
| **Total** | **50** |

### Category breakdown

| Category | CRITICAL | HIGH | MEDIUM | LOW | Total |
|---|---|---|---|---|---|
| Security (SEC) | 3 | 5 | 4 | 1 | 13 |
| Data integrity & correctness (DATA) | 4 | 4 | 4 | 0 | 12 |
| Race conditions (RACE) | 0 | 3 | 1 | 0 | 4 |
| Performance (PERF) | 0 | 3 | 4 | 0 | 7 |
| Validation drift (VAL) | 0 | 1 | 3 | 1 | 5 |
| Architecture (ARCH) | 0 | 1 | 5 | 3 | 9 |
| **Total** | **7** | **17** | **21** | **5** | **50** |

### Findings that contradict the code's own comments

The repository is heavily annotated with `-- BUG:`, `-- VULNERABILITY:` and `-- TODO:` markers (22 occurrences). Those markers are **not** a reliable inventory of the debt:

| Comment claim | Reality |
|---|---|
| `PKG_SECURITY.pkb:12` "Uses MD5 — should use stronger algorithm" | `hash_password` is never called by anything; authentication does no password check at all (SEC-01) |
| `PKG_EMPLOYEE.pks:9`, `PKG_PAYROLL.pks:9`, `README.md:127` "Circular dependency between `PKG_EMPLOYEE` and `PKG_PAYROLL`" | The cycle does not exist in the bodies; `PKG_PAYROLL` never references `PKG_EMPLOYEE`. A real cycle risk exists elsewhere: `PKG_SECURITY` → `PKG_EMPLOYEE` → `PKG_PAYROLL` (ARCH-01) |
| `HRMS_VALIDATION_LIB.pll.sql:104` "Uses a hard-coded cache … populated at form startup" | The function issues a direct `SELECT` (the file's own next comment admits this) (VAL-04) |
| `trg_employees.sql:117` "converts DELETE into an UPDATE" | It raises `ORA-20504`; nothing is converted (DATA-11) |
| `hrms_sequences.sql:19` "`SEQ_EMP_NUMBER` … gaps" | `SEQ_EMP_NUMBER` is never used at all; employee numbers come from `MAX()+1` with a `SEQ_EMPLOYEE` fallback (RACE-01) |

---

## 2. Security Findings

### SEC-01 — Authentication accepts any password (CRITICAL)

**Location:** `plsql/packages/PKG_SECURITY.pkb:30-80`

```sql
FUNCTION authenticate(
    p_username   IN VARCHAR2,
    p_password   IN VARCHAR2,
    p_ip_address IN VARCHAR2 DEFAULT NULL
) RETURN NUMBER IS
    v_emp_id     NUMBER;
    v_session_id NUMBER;
    v_stored_hash VARCHAR2(200);   -- never assigned
    v_input_hash  VARCHAR2(200);   -- never assigned
BEGIN
    -- Look up user
    SELECT EMP_ID INTO v_emp_id
    FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username)
    AND EMPLOYMENT_STATUS = 'ACTIVE';
    ...
    -- NOTE: In the real system, passwords are stored in a separate
    -- USER_CREDENTIALS table. For this legacy codebase, we simulate
    -- authentication against a simplified model.

    -- Create session
    SELECT SEQ_USER_SESSION.NEXTVAL INTO v_session_id FROM DUAL;
```

**Issue:** `p_password` is never read. `hash_password` (line 14) is never invoked from `authenticate`, and `v_stored_hash` / `v_input_hash` are declared and never used. Any caller supplying a valid active employee email receives an `ACTIVE` session row and a session ID.

**Impact:** Complete authentication bypass for every account, including grade ≥ 8 accounts that `has_permission` grants full access to (SEC-10). `HRMS_LOGIN.xml:75-79` and every form's `WHEN-NEW-FORM-INSTANCE` session check are therefore decorative.

**Recommendation:** Implement the `USER_CREDENTIALS` table referenced in the comment, store per-user salt + PBKDF2/bcrypt-class verifier, and make `authenticate` fail closed when no credential row exists. Treat the missing table as a schema gap, not a stub to be tolerated.

---

### SEC-02 — Hard-coded encryption key, and it is the wrong length for AES-256 (CRITICAL)

**Location:** `plsql/packages/PKG_SECURITY.pkb:6-7`, used at `:179-207`

```sql
-- VULNERABILITY: Encryption key hard-coded in source
c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
```

```sql
v_raw := DBMS_CRYPTO.ENCRYPT(
    src => UTL_RAW.CAST_TO_RAW(p_ssn),
    typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
    key => c_encryption_key
);
```

**Issue:** Two defects in one line. (a) The key is a literal in version-controlled source, so anyone with repo read access can decrypt every `EMPLOYEES.SSN_ENCRYPTED` value (`schema/tables/01_core_tables.sql:108`, documented as AES-256 at `:146`). (b) The literal is **30 characters = 30 bytes**; `ENCRYPT_AES256` requires exactly 32. `encrypt_ssn` and `decrypt_ssn` therefore raise a key-length error on every call. Because `decrypt_ssn` swallows all exceptions (SEC-13), that failure surfaces as the string `***DECRYPT_ERROR***` rather than an error.

**Impact:** SSN encryption is simultaneously compromised (key in source) and non-functional (wrong key size). Any code path that stores an SSN today fails, so the column is likely empty or populated out-of-band.

**Recommendation:** Move to Oracle TDE column encryption or a wallet/`DBMS_CREDENTIAL`-sourced key; never a package constant. Fix the key length, add a per-row IV, and rotate the exposed key on the assumption it is compromised.

---

### SEC-03 — MD5, unsalted, for password hashing (CRITICAL)

**Location:** `plsql/packages/PKG_SECURITY.pkb:10-24`

```sql
-- WEAKNESS: Uses MD5 - should use stronger algorithm
FUNCTION hash_password(p_password IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
    RETURN RAWTOHEX(
        DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(p_password), DBMS_CRYPTO.HASH_MD5)
    );
END hash_password;
```

**Issue:** MD5 is collision-broken and, being unsalted and single-round, is trivially reversed by rainbow tables for any realistic password. It is also GPU-brute-forceable at billions of hashes/second. Compounding SEC-01, this function is dead code — nothing in the repository calls it.

**Impact:** If credential storage is ever wired up as written, the entire password database is recoverable from a single table read. Fails PCI-DSS 8.3.1, NIST SP 800-63B, and SOC 2 CC6.1.

**Recommendation:** Replace with a memory-hard KDF; if constrained to `DBMS_CRYPTO`, use `HASH_SH512` with a per-user 32-byte random salt and ≥100k iterations of stretching, and plan migration to an external identity provider.

---

### SEC-04 — SQL injection via string concatenation in `search_employees` (HIGH)

**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:440-499` (injection points at `:467`, `:471`, `:475`, `:479`, `:483`)

```sql
-- BUG: SQL injection possible via p_last_name if called with unvalidated input
-- (Forms LOV passes validated values, but direct calls are vulnerable)
...
IF p_last_name IS NOT NULL THEN
    -- VULNERABILITY: String concatenation instead of bind variable
    v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
END IF;
...
IF p_dept_id IS NOT NULL THEN
    v_sql := v_sql || 'AND e.DEPT_ID = ' || p_dept_id || ' ';
END IF;
...
OPEN p_cursor FOR v_sql;
```

**Issue:** Five parameters are concatenated into the statement text. The `VARCHAR2` ones (`p_last_name`, `p_first_name`, `p_status`, `p_location_code`) allow quote-breaking injection; a payload such as `X'' UNION SELECT ... FROM DUAL --` rewrites the projected query. The in-code excuse ("Forms LOV passes validated values") does not hold: the procedure is a public package API callable by any session with EXECUTE.

**Impact:** Arbitrary data exfiltration through a `SYS_REFCURSOR` the caller already receives, under the privileges of the `HRMS` schema owner.

**Recommendation:** Build the predicate with bind placeholders and `OPEN p_cursor FOR v_sql USING ...`, or replace the whole procedure with a static query using `(p_last_name IS NULL OR UPPER(LAST_NAME) LIKE ...)` predicates.

---

### SEC-05 — No account lockout, plus a timing oracle on username validity (HIGH)

**Location:** `plsql/packages/PKG_SECURITY.pkb:26-57`; `forms/xml-exports/HRMS_LOGIN.xml:10-13`

```sql
-- VULNERABILITY: No brute-force protection (no lockout after N failures)
...
WHEN NO_DATA_FOUND THEN
    -- VULNERABILITY: Timing attack - different response time for
    -- invalid user vs invalid password
    RAISE_APPLICATION_ERROR(-20301, 'Invalid username or password');
```

**Issue:** There is no failed-attempt counter, no lockout, no delay, and no CAPTCHA (`HRMS_LOGIN.xml:12-13`). `USER_SESSIONS` (`schema/tables/04_performance_tables.sql:153`) records sessions but no failures, so there is no data to lock out on. The early `NO_DATA_FOUND` exit also distinguishes unknown from known usernames by timing and by control flow.

**Impact:** Unlimited credential stuffing and username enumeration. (Moot while SEC-01 stands, but blocking on the SEC-01 fix.)

**Recommendation:** Add `FAILED_LOGIN_COUNT` / `LOCKED_UNTIL` to the credential table, lock after N failures with exponential backoff, and return one uniform error after a constant-time code path.

---

### SEC-06 — `change_password` verifies nothing and persists nothing (HIGH)

**Location:** `plsql/packages/PKG_SECURITY.pkb:211-234`

```sql
PROCEDURE change_password(
    p_emp_id       IN NUMBER,
    p_old_password IN VARCHAR2,
    p_new_password IN VARCHAR2
) IS
BEGIN
    IF LENGTH(p_new_password) < 8 THEN ... END IF;
    IF NOT REGEXP_LIKE(p_new_password, '[A-Z]') THEN ... END IF;
    IF NOT REGEXP_LIKE(p_new_password, '[0-9]') THEN ... END IF;

    -- NOTE: Actual password update would go to USER_CREDENTIALS table
    -- This is a stub for the legacy system model

    PKG_AUDIT.log_action('USER_CREDENTIALS', p_emp_id, 'UPDATE', USER);
END change_password;
```

**Issue:** `p_old_password` is never read (no re-authentication), `p_emp_id` is never authorized against the caller's session (any user can invoke it for any employee), and no credential is written. It does, however, write an audit row claiming the password changed. The complexity rules also hard-code `8` rather than reading `SYSTEM_PARAMETERS.SECURITY.PASSWORD_MIN_LENGTH` (`data/seed/01_reference_data.sql:193-194`).

**Impact:** The audit trail asserts password rotations that never happened — a compliance-evidence defect on top of the missing implementation.

**Recommendation:** Implement against the credential table; verify `p_old_password`; bind the operation to the authenticated session rather than an arbitrary `p_emp_id`; source complexity rules from `SYSTEM_PARAMETERS`.

---

### SEC-07 — Hard-coded SMTP configuration in package body (HIGH)

**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:6-10`

```sql
-- Hard-coded SMTP config (should be in SYSTEM_PARAMETERS)
c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
c_smtp_port    CONSTANT NUMBER := 25;
c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
c_from_name    CONSTANT VARCHAR2(100) := 'HRMS System';
```

**Issue:** The same values already exist as configuration (`SYSTEM_PARAMETERS.NOTIFICATION.SMTP_HOST` / `FROM_ADDRESS`, seeded at `data/seed/01_reference_data.sql:195-198`), so the two will drift. Port 25 with no `UTL_SMTP` STARTTLS negotiation and no authentication means all HR notification traffic — names, leave reasons, termination notices — crosses the network in cleartext.

**Impact:** Configuration changes require a package recompile in production; PII travels unencrypted; an open relay on 25 can be abused for spoofed internal mail.

**Recommendation:** Read host/port/sender from `PKG_COMMON.get_param`, require TLS + SMTP AUTH with wallet-stored credentials, and remove the duplicated constants.

---

### SEC-08 — Integration credentials stored in cleartext parameter table (HIGH)

**Location:** `plsql/packages/PKG_INTEGRATION.pks:8-13`; `schema/tables/04_performance_tables.sql:110-124`

```sql
-- Known issues:
--   - GL posting uses flat file exchange (UTL_FILE) instead of API
--   - Benefits feed format is vendor-specific (ADP format)
--   - No retry logic for failed file transfers
--   - FTP credentials stored in SYSTEM_PARAMETERS table (cleartext)
```

**Issue:** `SYSTEM_PARAMETERS.PARAM_VALUE` is a plain `VARCHAR2(4000)` with no encryption, no column-level access control, and no exclusion from the audit `NEW_VALUES` payloads that `PKG_COMMON.log_error` writes. Any account able to read the parameter table (including everything that calls `PKG_COMMON.get_param`) reads the FTP credentials for the payroll GL and benefits feeds.

**Impact:** Compromise of the credentials that move payroll and benefits data to external processors. Note the credential rows are not in the seeded data, so this is a production-configuration exposure rather than a repo secret leak.

**Recommendation:** Move transfer credentials into an Oracle Wallet / `DBMS_CREDENTIAL` object, restrict `SYSTEM_PARAMETERS` reads to a `SECURITY` group via a wrapper API, and add a parameter-group deny-list to the logging helpers.

---

### SEC-09 — Duplicate-email accounts silently authenticate the lowest `EMP_ID` (MEDIUM)

**Location:** `plsql/packages/PKG_SECURITY.pkb:51-57`

```sql
WHEN TOO_MANY_ROWS THEN
    -- Multiple employees with same email - use first active one
    SELECT MIN(EMP_ID) INTO v_emp_id
    FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(p_username)
    AND EMPLOYMENT_STATUS = 'ACTIVE';
```

**Issue:** `EMPLOYEES` has no unique constraint on `EMAIL` (`schema/tables/01_core_tables.sql:134-142` — only `UK_EMP_NUMBER`). The uniqueness comment in `trg_employees.sql:40-41` claims a constraint exists; it does not. On collision, `authenticate` resolves to the oldest matching record.

**Impact:** Identity confusion at login: a rehired or duplicated record can hijack the session identity, and every downstream `has_permission` decision uses the wrong `EMP_ID`.

**Recommendation:** Add `CONSTRAINT UK_EMP_EMAIL UNIQUE (EMAIL)` (after de-duplication), and make `TOO_MANY_ROWS` fail closed rather than picking a winner.

---

### SEC-10 — Authorization is hard-coded grade arithmetic with a default-allow tail (MEDIUM)

**Location:** `plsql/packages/PKG_SECURITY.pkb:129-174`

```sql
-- Grade >= 8: Full access to all modules
IF v_grade_id >= 8 THEN RETURN TRUE; END IF;
IF p_action = 'VIEW' AND v_grade_id >= 5 THEN RETURN TRUE; END IF;
IF p_module = 'LEAVE' AND p_action IN ('CREATE', 'VIEW') THEN RETURN TRUE; END IF;
IF p_module = 'EMPLOYEE' AND p_action = 'VIEW' THEN RETURN TRUE; END IF;
```

**Issue:** There is no roles/permissions model (the code says as much at `:132`). Authorization is a function of `JOB_GRADES.GRADE_ID`, so an HR-unrelated director (grade ≥ 8) gets full payroll access, and the `EMPLOYEE`/`VIEW` rule grants every authenticated user read access to *all* employee records, not their own — the comment says "own profile" but no `p_emp_id` scoping is applied.

**Impact:** Broad over-entitlement, notably company-wide employee data readable by every user; salary-band changes silently change access rights.

**Recommendation:** Introduce `ROLES`, `PERMISSIONS`, `EMPLOYEE_ROLES` tables and replace grade arithmetic with an explicit grant lookup plus row-level scoping (own record vs. own department vs. all).

---

### SEC-11 — Session timeout hard-coded and enforced on database clock (MEDIUM)

**Location:** `plsql/packages/PKG_SECURITY.pkb:8`, `:98-127`

```sql
c_session_timeout_min CONSTANT NUMBER := 30;
...
IF (SYSDATE - v_login_time) * 24 * 60 > c_session_timeout_min THEN
```

**Issue:** `SYSTEM_PARAMETERS.SECURITY.SESSION_TIMEOUT_MIN` is seeded with `30` (`data/seed/01_reference_data.sql:191-192`) and ignored. Timeout is measured from `LOGIN_TIME` only — there is no `LAST_ACTIVITY` column, so this is an absolute cap, not an idle timeout, and activity never extends a session. `SYSDATE` is server-local and not DST/timezone safe for multi-region use (README notes 3 regional offices).

**Impact:** Users are logged out mid-task at 30 minutes regardless of activity; the documented tunable does nothing; DST transitions shift enforcement by an hour.

**Recommendation:** Read the parameter at runtime, add `LAST_ACTIVITY_TIME` maintained by `is_session_valid` for true idle timeout, and use `SYSTIMESTAMP`/`TIMESTAMP WITH TIME ZONE`.

---

### SEC-12 — Login credentials transmitted in cleartext by the Forms applet (MEDIUM)

**Location:** `forms/xml-exports/HRMS_LOGIN.xml:10-13`, `:45-51`, `:62-102`

```
Known Issues:
  - Password field transmitted in cleartext (Forms applet limitation)
  - No account lockout after failed attempts
  - No CAPTCHA or 2FA support
```

**Issue:** The password item is `ConcealData="Yes"` (masked on screen) but is passed as a plain bind to `PKG_SECURITY.authenticate` over the Forms/WebLogic channel. The form has no second factor and no rate limiting of its own.

**Impact:** Credentials are recoverable by anyone able to observe the applet channel if HTTPS/Forms socket encryption is not enforced end-to-end.

**Recommendation:** Terminate TLS in front of WebLogic and enable Forms message encryption; longer term, move authentication to an SSO/OIDC provider so the applet never handles a password.

---

### SEC-13 — `decrypt_ssn` masks failures as a plausible-looking value (LOW)

**Location:** `plsql/packages/PKG_SECURITY.pkb:192-207`

```sql
EXCEPTION
    WHEN OTHERS THEN
        RETURN '***DECRYPT_ERROR***';
END decrypt_ssn;
```

**Issue:** A blanket `WHEN OTHERS` converts key-length errors (SEC-02), padding errors, and data corruption into an ordinary return value. Callers cannot distinguish "no SSN", "corrupted SSN", and "crypto misconfigured", and nothing is logged.

**Impact:** SEC-02's total failure of SSN crypto is invisible in production; the sentinel can be persisted or exported downstream as if it were data.

**Recommendation:** Log via `PKG_COMMON.log_error` and re-raise; let callers decide.

---

## 3. Data Integrity & Correctness Findings

### DATA-01 — `TRG_EMP_BEFORE_UPDATE` writes to six non-existent columns (CRITICAL)

**Location:** `plsql/triggers/trg_employees.sql:76-110` vs. DDL at `schema/tables/01_core_tables.sql:152-177`

```sql
-- trg_employees.sql:78-85
INSERT INTO EMPLOYEE_HISTORY (
    HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE,
    OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON
) VALUES (
    SEQ_EMP_HISTORY.NEXTVAL, :NEW.EMP_ID, 'STATUS_CHANGE', SYSDATE,
    :OLD.EMPLOYMENT_STATUS, :NEW.EMPLOYMENT_STATUS,
    NVL(:NEW.MODIFIED_BY, USER), 'Triggered by status update'
);
```

```sql
-- 01_core_tables.sql:152-160 (actual columns)
CREATE TABLE HRMS.EMPLOYEE_HISTORY (
    HIST_ID              NUMBER(15)      NOT NULL,
    EMP_ID               NUMBER(10)      NOT NULL,
    CHANGE_TYPE          VARCHAR2(30)    NOT NULL,
    EFFECTIVE_DATE       DATE            NOT NULL,
    OLD_DEPT_ID          NUMBER(10),
    NEW_DEPT_ID          NUMBER(10),
    ...
```

**Issue:** All three inserts in the trigger (`:78`, `:90`, `:102`) name `HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON` — none of which exist. The table uses `HIST_ID`, `EFFECTIVE_DATE`, typed `OLD_*`/`NEW_*` pairs, and `CREATED_BY`; `CREATED_BY` is `NOT NULL` and is never supplied. Independently, the trigger's `CHANGE_TYPE` values `'DEPARTMENT_CHANGE'` (`:94`) and `'JOB_CHANGE'` (`:106`) are not in `CHK_CHANGE_TYPE` (`:173-176`, which allows `'TRANSFER'`, `'PROMOTION'`, …). The correct column list exists two files away in `PKG_EMPLOYEE.log_history` (`plsql/packages/PKG_EMPLOYEE.pkb:157-169`), confirming the trigger was written against an earlier schema.

**Impact:** The trigger fails to compile (`ORA-00904: invalid identifier`), so **every `UPDATE` on `EMPLOYEES` fails** while it is in an invalid state — status changes, transfers, promotions, terminations, and rehires all break. Wherever the trigger is absent instead, employment-status history is silently not recorded.

**Recommendation:** Rewrite the trigger against current DDL (or delete it and rely on `PKG_EMPLOYEE.log_history`, which is already correct), and add a schema-drift check to CI that diffs DML column lists against DDL — the mechanical check used for this report found all three sites in seconds.

---

### DATA-02 — Seed data references three non-existent columns and omits a `NOT NULL` key (CRITICAL)

**Location:** `data/seed/01_reference_data.sql:11`, `:14`, `:17`, `:23-41`, `:182-200`

```sql
-- :11  LOCATIONS has PHONE_NUMBER, not PHONE
INSERT INTO LOCATIONS (LOCATION_CODE, ..., COUNTRY_CODE, PHONE, ACTIVE_FLAG, ...)

-- :23  JOB_GRADES has no GRADE_LEVEL column, and GRADE_CODE is NOT NULL + UNIQUE
INSERT INTO JOB_GRADES (GRADE_ID, GRADE_NAME, GRADE_LEVEL, MIN_SALARY, MAX_SALARY, ...)

-- :182 SYSTEM_PARAMETERS has PARAM_DESCRIPTION, not DESCRIPTION
INSERT INTO SYSTEM_PARAMETERS (PARAM_ID, PARAM_GROUP, PARAM_CODE, PARAM_VALUE, DESCRIPTION, ...)
```

**Issue:** 23 seed statements are invalid against the shipped DDL: 3 `LOCATIONS` rows (`PHONE`), 10 `JOB_GRADES` rows (`GRADE_LEVEL`, plus the missing `NOT NULL` `GRADE_CODE`), and 10 `SYSTEM_PARAMETERS` rows (`DESCRIPTION`).

**Impact:** A clean-environment install fails at seed time with `ORA-00904` / `ORA-01400`. `LOCATIONS`, `JOB_GRADES`, and `SYSTEM_PARAMETERS` end up empty, which cascades: `EMPLOYEES.LOCATION_CODE` FK inserts fail, `PKG_VALIDATION.validate_salary_for_grade` returns `'Invalid grade ID'` for everything (`plsql/packages/PKG_VALIDATION.pkb:45-47`), and every `PKG_COMMON.get_param` call returns `NULL` (`plsql/packages/PKG_COMMON.pkb:78-80`) — silently, because `NO_DATA_FOUND` is swallowed.

**Recommendation:** Correct the column names, supply `GRADE_CODE`, and gate the seed scripts in CI by running them against a scratch schema.

---

### DATA-03 — Mutating-table error in `TRG_EMP_BEFORE_INSERT` (CRITICAL)

**Location:** `plsql/triggers/trg_employees.sql:40-54`

```sql
-- Validate email uniqueness (also enforced by unique constraint, but
-- this trigger provides a better error message)
DECLARE
    v_count NUMBER;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM EMPLOYEES
    WHERE UPPER(EMAIL) = UPPER(:NEW.EMAIL)
    AND ACTIVE_FLAG = 'Y';
    ...
```

**Issue:** A row-level trigger on `EMPLOYEES` queries `EMPLOYEES`, which raises `ORA-04091: table HRMS.EMPLOYEES is mutating, trigger/function may not see it`. The justifying comment is also wrong: there is no unique constraint on `EMAIL` (see SEC-09), so this trigger is the *only* uniqueness enforcement — and it cannot run.

**Impact:** Every `INSERT INTO EMPLOYEES` fails, including `PKG_EMPLOYEE.create_employee`. Hiring is non-functional. If the trigger is dropped to work around it, duplicate emails become possible and feed SEC-09.

**Recommendation:** Delete the check and add `UK_EMP_EMAIL` (mapping `ORA-00001` to a friendly message in the calling package); if a friendly message must live in a trigger, use a compound trigger with a statement-level `AFTER` section.

---

### DATA-04 — Rehire is impossible: the sanctioned path is blocked by its own trigger (CRITICAL)

**Location:** `plsql/triggers/trg_employees.sql:69-74` vs. `plsql/packages/PKG_EMPLOYEE.pkb:750-771`

```sql
-- trg_employees.sql:69-74
-- Prevent reactivation of terminated employees via direct UPDATE
-- (should go through PKG_EMPLOYEE.rehire_employee instead)
IF :OLD.EMPLOYMENT_STATUS = 'TERMINATED' AND :NEW.EMPLOYMENT_STATUS = 'ACTIVE' THEN
    RAISE_APPLICATION_ERROR(-20503,
        'Cannot directly reactivate a terminated employee. Use the rehire process.');
END IF;
```

```sql
-- PKG_EMPLOYEE.pkb:761-771 — the "rehire process" is a plain UPDATE
UPDATE EMPLOYEES SET
    EMPLOYMENT_STATUS  = 'ACTIVE',
    HIRE_DATE          = p_rehire_date,
    ...
WHERE EMP_ID = p_emp_id;
```

**Issue:** The trigger cannot distinguish a "direct" `UPDATE` from one issued inside `PKG_EMPLOYEE.rehire_employee` — both are the same DML. There is no context flag (e.g. a package variable or `SYS_CONTEXT` namespace) that the trigger consults. So `rehire_employee` always raises `ORA-20503`.

**Impact:** No terminated employee can ever be rehired through the application. Operations must disable the trigger or patch rows directly, bypassing all history logging.

**Recommendation:** Have `rehire_employee` set a `SYS_CONTEXT` flag (via a secured `DBMS_SESSION.SET_CONTEXT` procedure) that the trigger checks, or move the reactivation guard out of the trigger into the package API and revoke direct DML on `EMPLOYEES`. Separately, `rehire_employee` overwrites `HIRE_DATE` (`:763`), destroying original-hire-date history and corrupting `VW_ACTIVE_EMPLOYEES.TENURE_YEARS` (`schema/views/hrms_views.sql:15`) — add `ORIGINAL_HIRE_DATE` instead.

---

### DATA-05 — `VW_LEAVE_SUMMARY.AVAILABLE` omits pending leave, contradicting the table (HIGH)

**Location:** `schema/views/hrms_views.sql:96` vs. `schema/tables/03_leave_tables.sql:47`

```sql
-- View:
lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE,

-- Table (virtual column):
AVAILABLE NUMBER(6,2) GENERATED ALWAYS AS
    (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL,
```

**Issue:** The view recomputes `AVAILABLE` and drops `- PENDING`, even though it selects `lb.PENDING` on the adjacent line (`:95`). Server-side enforcement uses the table's column (`PKG_LEAVE.get_leave_balance`), so the view over-reports by exactly the pending total. `PKG_LEAVE.submit_leave_request` increments `PENDING` at `plsql/packages/PKG_LEAVE.pkb:176-182`, so the discrepancy appears the moment a request is filed.

**Impact:** Forms LOVs, Oracle Reports, and any BI tool reading the view show employees more leave than they can actually book; requests then fail validation at submit time with "Insufficient leave balance" (`PKG_LEAVE.pkb:150-152`), a classic "the report said I had days left" support escalation.

**Recommendation:** Select the table's `AVAILABLE` column directly rather than recomputing it — that is the whole point of the virtual column.

---

### DATA-06 — `VW_PAYROLL_LATEST` uses a single global `MAX(RUN_ID)` (HIGH)

**Location:** `schema/views/hrms_views.sql:109-129`

```sql
WHERE pr.RUN_ID = (
    SELECT MAX(pr2.RUN_ID)
    FROM PAYROLL_RUNS pr2
    WHERE pr2.STATUS = 'APPROVED'
)
```

**Issue:** "Latest payroll per employee" is implemented as "the one globally highest approved `RUN_ID`". Any off-cycle or correction run (`RUN_TYPE` supports non-`REGULAR` runs, `PKG_PAYROLL.create_payroll_run:232-234`) becomes *the* latest run for everyone. Employees absent from that run disappear from the view entirely, and `PERIOD_NAME` is whatever period that one run belongs to.

**Impact:** Pay-stub and net-pay reporting silently omits employees and mixes periods after any bonus or correction run.

**Recommendation:** Correlate per employee and period, e.g. `ROW_NUMBER() OVER (PARTITION BY pd.EMP_ID ORDER BY pr.RUN_DATE DESC, pr.RUN_ID DESC) = 1`, and expose `RUN_TYPE` so consumers can filter.

---

### DATA-07 — Salary joins can fan out rows in two views (HIGH)

**Location:** `schema/views/hrms_views.sql:32-35`, `:79`

```sql
-- VW_ACTIVE_EMPLOYEES
LEFT JOIN SALARY_RECORDS sr ON e.EMP_ID = sr.EMP_ID
    AND sr.ACTIVE_FLAG = 'Y'
    AND sr.EFFECTIVE_DATE <= SYSDATE
    AND (sr.END_DATE IS NULL OR sr.END_DATE > SYSDATE)

-- VW_EMPLOYEE_COMPENSATION
JOIN SALARY_RECORDS sr ON e.EMP_ID = sr.EMP_ID AND sr.ACTIVE_FLAG = 'Y'
```

**Issue:** Nothing guarantees one active salary row per employee — `SALARY_RECORDS` has no unique constraint or exclusion on `(EMP_ID, ACTIVE_FLAG='Y')`, and `PKG_PAYROLL.create_salary_record` is called from three places in `PKG_EMPLOYEE` (`:275`, `:617`, `:778`). `VW_EMPLOYEE_COMPENSATION` doesn't even date-filter, so every historical row flagged `'Y'` multiplies the employee.

**Impact:** Headcount and compensation reports double-count employees; `COMPA_RATIO` averages become wrong. Because it is an `INNER JOIN`, `VW_EMPLOYEE_COMPENSATION` also *drops* employees with no active salary record.

**Recommendation:** Add a partial unique index enforcing one active record per employee, and use `KEEP (DENSE_RANK LAST ORDER BY EFFECTIVE_DATE)` or a lateral top-1 join in both views.

---

### DATA-08 — `expire_carryover` double-subtracts when re-run (HIGH)

**Location:** `plsql/packages/PKG_LEAVE.pkb:605-622`

```sql
-- BUG: If run twice on same day, can double-subtract
PROCEDURE expire_carryover(p_user IN VARCHAR2 DEFAULT USER) IS
BEGIN
    UPDATE LEAVE_BALANCES SET
        ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
        CARRYOVER_FROM_PREV = 0,
        ...
    WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE)
    AND CARRYOVER_FROM_PREV > 0;
```

**Issue:** The `CARRYOVER_FROM_PREV > 0` predicate does make the statement idempotent *as written* — but only because the same statement zeroes the source column. Any partial failure, or any subsequent `process_carryover` run that repopulates `CARRYOVER_FROM_PREV` (`:580-598`) for a balance whose `CARRYOVER_EXPIRY_DT` is already in the past, re-applies the subtraction. There is no `CARRYOVER_EXPIRED_DATE` marker recording that expiry already happened, and the procedure `COMMIT`s unconditionally with no error handler.

**Impact:** Silent, permanent erosion of employee leave balances that is nearly impossible to reconstruct — `ADJUSTMENT` is a single scalar with no per-event ledger.

**Recommendation:** Record expiry events in `LEAVE_ACCRUAL_LOG` (which already exists for exactly this purpose, `schema/tables/03_leave_tables.sql:96-109`) and make the update conditional on the absence of a matching log row; remove the blind `COMMIT`.

---

### DATA-09 — Half-day requests are always 0.5 days regardless of range (MEDIUM)

**Location:** `plsql/packages/PKG_LEAVE.pkb:128-138`

```sql
IF p_half_day_flag = 'Y' THEN
    v_total_days := 0.5;
ELSE
    v_total_days := calculate_business_days(
        p_start_date, p_end_date, v_emp_rec.LOCATION_CODE);
END IF;
```

**Issue:** With `HALF_DAY_FLAG = 'Y'`, `p_end_date` is ignored. `CHK_LR_DATES` only requires `END_DATE >= START_DATE`, so a two-week request flagged half-day is booked as 0.5 days. `HALF_DAY_PERIOD` ('AM'/'PM') is also never used in `check_leave_overlap` (`:45-62`), so two half-day requests for opposite halves of the same day are rejected as overlapping while a half-day and a full day on the same date are treated as one conflict.

**Impact:** Under-deduction of leave balances (audit/payroll exposure) and false-positive overlap rejections for legitimate AM/PM splits.

**Recommendation:** Reject `HALF_DAY_FLAG = 'Y'` unless `START_DATE = END_DATE` (as a `CHECK` constraint plus a package guard), and make overlap detection period-aware.

---

### DATA-10 — Leave-year attribution keyed on start-date year (MEDIUM)

**Location:** `plsql/packages/PKG_LEAVE.pkb:182`, `:248`, `:302`, `:352`, `:360`

```sql
AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```

**Issue:** A request spanning a year boundary (e.g. 28 Dec – 4 Jan) posts its entire `PENDING`/`USED` amount to the start year's balance row. `LEAVE_BALANCES` is keyed `(EMP_ID, LEAVE_TYPE_ID, CALENDAR_YEAR)` (`schema/tables/03_leave_tables.sql:57`), and no code splits days across the two rows.

**Impact:** Year-end requests overdraw the prior year (possibly below zero, since `AVAILABLE` is virtual and unconstrained) and under-consume the new year, corrupting both years' utilization reporting.

**Recommendation:** Split the request into per-year segments at submission, or move to an event-ledger balance model where the year is derived per leave day.

---

### DATA-11 — Soft-delete model is inconsistent and the delete trigger contradicts its comment (MEDIUM)

**Location:** `plsql/triggers/trg_employees.sql:114-129`

```sql
-- TRG_EMP_AFTER_DELETE
-- Soft delete: instead of actual deletion, marks record as inactive
-- NOTE: This trigger converts DELETE into an UPDATE, ...
CREATE OR REPLACE TRIGGER HRMS.TRG_EMP_INSTEAD_OF_DELETE
BEFORE DELETE ON HRMS.EMPLOYEES
FOR EACH ROW
BEGIN
    RAISE_APPLICATION_ERROR(-20504,
        'Direct deletion not allowed. ...');
END TRG_EMP_INSTEAD_OF_DELETE;
```

**Issue:** Three inconsistencies in 16 lines: the comment header names a non-existent `AFTER DELETE` trigger, the trigger name says `INSTEAD_OF` but it is a `BEFORE DELETE` row trigger (INSTEAD OF applies only to views), and it converts nothing — it hard-fails. Separately, "inactive" has two independent encodings, `ACTIVE_FLAG` and `EMPLOYMENT_STATUS='TERMINATED'`, and queries pick inconsistently: `VW_ACTIVE_EMPLOYEES` requires both (`schema/views/hrms_views.sql:36-37`), `VW_ORG_HIERARCHY` and `VW_EMPLOYEE_COMPENSATION` check only `EMPLOYMENT_STATUS` (`:54`, `:80`), and `PKG_SECURITY.authenticate` checks only `EMPLOYMENT_STATUS` (`plsql/packages/PKG_SECURITY.pkb:45`) — so a soft-deleted employee (`ACTIVE_FLAG='N'`, status still `ACTIVE`) can still log in.

**Impact:** Forms `DELETE_RECORD` raises an unhandled error for users; soft-deleted employees remain in the org chart, in compensation reporting, and able to authenticate.

**Recommendation:** Collapse to a single lifecycle column (`EMPLOYMENT_STATUS`) with `ACTIVE_FLAG` as a generated column if callers need it, and normalize every predicate to one helper (`PKG_EMPLOYEE.is_active`).

---

### DATA-12 — Holiday matching is exact-date and ignores observed holidays (MEDIUM)

**Location:** `plsql/packages/PKG_LEAVE.pkb:6-10`, `:25-29`; `plsql/packages/PKG_VALIDATION.pkb:90-94`

```sql
-- BUG: Does not handle "observed" holidays (e.g., if July 4 falls on
-- Saturday, the observed Friday is not excluded)
...
SELECT COUNT(*) INTO v_holiday_count
FROM HOLIDAYS
WHERE HOLIDAY_DATE = v_date
```

**Issue:** `HOLIDAYS.HOLIDAY_DATE` is a `DATE` with no `TRUNC` guarantee (no check constraint, no trigger), and the predicate compares it raw to a truncated loop variable — any row seeded with a time component never matches. Observed-holiday shifting is unimplemented despite `FLOATING_FLAG` existing on the table (`schema/tables/03_leave_tables.sql:119`). The location predicate `(LOCATION_CODE IS NULL OR LOCATION_CODE = p_location_code)` also matches global holidays for every site, so a site-specific holiday list cannot suppress a global entry.

**Impact:** Leave-day counts are wrong around observed holidays and for any non-truncated holiday row, in both the leave engine and the validation package.

**Recommendation:** Add `CHECK (HOLIDAY_DATE = TRUNC(HOLIDAY_DATE))`, compare with `TRUNC`, and add an `OBSERVED_DATE` column that the business-day calculation uses.

---

## 4. Race Conditions

### RACE-01 — `MAX()+1` employee numbering with an inconsistent sequence fallback (HIGH)

**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:39-55`; unused sequence at `schema/sequences/hrms_sequences.sql:19-21`

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
        -- Fallback: use sequence-based number
        RETURN c_emp_number_prefix || '-' || LPAD(SEQ_EMPLOYEE.NEXTVAL, 6, '0');
END generate_emp_number;
```

**Issue:** No `FOR UPDATE`, no lock, no uniqueness retry. Two concurrent hires read the same `MAX`, and since the value is assigned in the Forms `PRE-INSERT` trigger (`forms/xml-exports/HRMS_EMPLOYEE.xml:323-327`) — potentially seconds before commit — the window is wide. The `UK_EMP_NUMBER` constraint turns the collision into a raw `ORA-00001` at commit time, after the user has finished data entry. The `WHEN OTHERS` fallback draws from `SEQ_EMPLOYEE` (the `EMP_ID` sequence, `hrms_sequences.sql:13`) — not `SEQ_EMP_NUMBER`, which exists at `:21` and is never referenced anywhere — so the fallback produces numbers from a different, unrelated series and can itself collide. The blanket handler also masks genuine errors, including a `TO_NUMBER` failure on any manually-entered non-numeric `EMP_NUMBER`.

**Impact:** Failed hires under concurrency (README: ~200 concurrent users), duplicate-key errors surfacing at commit, and two incompatible numbering series in one column.

**Recommendation:** Use `SEQ_EMP_NUMBER.NEXTVAL` unconditionally (it exists for this), or a `DEFAULT ON NULL` identity expression on the column; delete the fallback and the `WHEN OTHERS`.

---

### RACE-02 — Payroll run created against an unlocked period status (HIGH)

**Location:** `plsql/packages/PKG_PAYROLL.pkb:240-260`; contrast the correct pattern at `:190-208`

```sql
-- create_payroll_run — no lock
SELECT STATUS INTO v_status
FROM PAY_PERIODS
WHERE PERIOD_ID = p_period_id;

IF v_status = 'CLOSED' THEN
    RAISE_APPLICATION_ERROR(-20102, ...);
END IF;

SELECT SEQ_PAYROLL_RUN.NEXTVAL INTO v_run_id FROM DUAL;
INSERT INTO PAYROLL_RUNS (...) VALUES (...);
```

```sql
-- close_pay_period — locks correctly (:195-196)
WHERE PERIOD_ID = p_period_id
FOR UPDATE;
```

**Issue:** The same package demonstrates the correct pattern 40 lines earlier. In `create_payroll_run` the check-then-insert is not atomic: `close_pay_period` can commit between the `SELECT` and the `INSERT`, attaching a new run to a closed period. Nothing in the schema prevents it — `PAYROLL_RUNS` has no constraint tying `STATUS` to its period's state.

**Impact:** Payroll runs against closed periods — a financial-reconciliation and audit defect, since the closed period has already been reported to GL (`PKG_INTEGRATION.generate_gl_journal`).

**Recommendation:** Add `FOR UPDATE` to the status read (matching `close_pay_period`), and re-validate inside the same transaction as the insert.

---

### RACE-03 — Leave balance check-then-update permits double-spending (HIGH)

**Location:** `plsql/packages/PKG_LEAVE.pkb:146-182`

```sql
IF v_leave_type.ACCRUAL_FLAG = 'Y' THEN
    v_balance := get_leave_balance(p_emp_id, p_leave_type_id);
    IF v_balance < v_total_days THEN
        RAISE_APPLICATION_ERROR(-20201, 'Insufficient leave balance. ...');
    END IF;
END IF;
...
INSERT INTO LEAVE_REQUESTS (...);

UPDATE LEAVE_BALANCES
SET PENDING = PENDING + v_total_days, ...
WHERE EMP_ID = p_emp_id AND LEAVE_TYPE_ID = p_leave_type_id
AND CALENDAR_YEAR = EXTRACT(YEAR FROM p_start_date);
```

**Issue:** The balance is read without `FOR UPDATE` roughly 35 lines before the `PENDING` increment, with an insert and an overlap check in between. Two concurrent submissions both pass the check and both increment `PENDING`. `AVAILABLE` is a virtual column with no `CHECK (AVAILABLE >= 0)`, so the database will not catch the overdraft either. The `UPDATE` also does not verify `SQL%ROWCOUNT` — if no balance row exists for that year (see DATA-10), the request is created with no balance impact at all.

**Impact:** Employees can exceed their entitlement by submitting concurrent requests; leave liability on the balance sheet is understated.

**Recommendation:** `SELECT ... FOR UPDATE` the balance row before validating, add `CHECK (AVAILABLE >= 0)` as a backstop, and assert `SQL%ROWCOUNT = 1` after the update.

---

### RACE-04 — Overlap detection is not serialized (MEDIUM)

**Location:** `plsql/packages/PKG_LEAVE.pkb:45-62`, called at `:141-144`

```sql
SELECT COUNT(*) INTO v_count
FROM LEAVE_REQUESTS
WHERE EMP_ID = p_emp_id
AND STATUS IN ('PENDING', 'APPROVED')
...
```

**Issue:** A `COUNT(*)` on uncommitted-invisible rows cannot prevent two concurrent submissions from each seeing zero overlaps and both inserting. There is no constraint or exclusion index backing the rule.

**Impact:** Duplicate/overlapping approved leave for the same employee and dates, which then double-deducts on approval.

**Recommendation:** Serialize per employee (`SELECT ... FROM EMPLOYEES WHERE EMP_ID = :id FOR UPDATE` as a mutex, which RACE-03's fix already needs) and re-check after acquiring it.

---

## 5. Performance Findings

### PERF-01 — One holiday query per calendar day (HIGH)

**Location:** `plsql/packages/PKG_LEAVE.pkb:12-40`

```sql
WHILE v_date <= TRUNC(p_end_date) LOOP
    IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
        SELECT COUNT(*) INTO v_holiday_count
        FROM HOLIDAYS
        WHERE HOLIDAY_DATE = v_date
        ...
    END IF;
    v_date := v_date + 1;
END LOOP;
```

**Issue:** A context switch and a query per weekday in the range. A one-year sabbatical costs ~260 round trips; `HOLIDAYS` has only a primary-key index on `HOLIDAY_ID` (`schema/tables/03_leave_tables.sql:123`), so each one is a full scan. `calculate_business_days` is called on every leave submission (`:132`).

**Impact:** Submission latency grows linearly with request length and table size; multiplied across ~200 concurrent users this is a measurable CPU sink for a computation that should be a single query.

**Recommendation:** Replace the loop with one set-based query against a generated date range (`CONNECT BY LEVEL` or a calendar table) anti-joined to `HOLIDAYS`, and add an index on `(HOLIDAY_DATE, ACTIVE_FLAG, LOCATION_CODE)`.

---

### PERF-02 — SMTP connection opened and torn down per notification (HIGH)

**Location:** `plsql/packages/PKG_NOTIFICATION.pkb:78-107`

```sql
FOR notif_rec IN (
    SELECT ... FROM NOTIFICATION_QUEUE WHERE STATUS = 'PENDING' ...
) LOOP
    BEGIN
        -- Open SMTP connection
        v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
        UTL_SMTP.HELO(v_connection, c_smtp_host);
        ...
        UTL_SMTP.QUIT(v_connection);
```

**Issue:** TCP connect + HELO + QUIT for every single message inside the batch loop. At a typical 50–200 ms handshake, a 500-message batch spends most of its wall time on connection setup. There is also no rate limiting (documented at `PKG_NOTIFICATION.pks:8-11`) and no retry backoff — the failure path increments `RETRY_COUNT` (`:120-124`) but nothing ever consults it, so permanently-failing addresses are retried forever by the next batch.

**Impact:** Notification batches take minutes instead of seconds; bursty connection churn can trip relay rate limits and get the HRMS host throttled or blocked.

**Recommendation:** Open one connection per batch and reuse it (reconnecting only on error), honour `RETRY_COUNT` with exponential backoff and a dead-letter threshold, and cap per-run send volume.

---

### PERF-03 — Row-by-row payroll calculation with partial commits (HIGH)

**Location:** `plsql/packages/PKG_PAYROLL.pkb:265-347`

```sql
-- BUG: Cursor loop - should use BULK COLLECT + FORALL
FOR emp_rec IN (SELECT e.EMP_ID FROM EMPLOYEES e WHERE ...) LOOP
    BEGIN
        calculate_employee_pay(p_run_id, emp_rec.EMP_ID, v_period_id, p_user);
        v_emp_count := v_emp_count + 1;
    EXCEPTION
        WHEN OTHERS THEN
            v_error_count := v_error_count + 1;
            INSERT INTO PAYROLL_DETAILS (...) VALUES (..., 'ERROR', ...);
    END;

    -- Commit every 50 employees to avoid long transactions
    -- ISSUE: Partial commits mean a failure leaves payroll half-calculated
    IF MOD(v_emp_count, 50) = 0 THEN
        COMMIT;
    END IF;
END LOOP;
```

**Issue:** Beyond the row-by-row processing the comments acknowledge, the commit condition is subtly wrong: `v_emp_count` only increments on *success*, so the counter stalls whenever errors occur and the commit cadence drifts. `MOD(v_emp_count, 50) = 0` also fires repeatedly while the count is stuck at a multiple of 50, and the error-path `INSERT` runs *after* `calculate_employee_pay` has already raised — inside a transaction that may include that procedure's partial writes, which are committed along with the error row.

**Impact:** Non-restartable payroll: a mid-run failure leaves some employees calculated and committed, others not, with no run-level rollback. Combined with the unlocked period check (RACE-02), recovery is manual.

**Recommendation:** Process in bounded batches with `BULK COLLECT`/`FORALL`, use a savepoint per employee so the error row is the only thing that survives a failure, drive the commit cadence off the total iteration count, and make the run resumable by tracking per-employee completion state.

---

### PERF-04 — 28 of 29 sequences are `NOCACHE` (MEDIUM)

**Location:** `schema/sequences/hrms_sequences.sql:9-49`

```sql
CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
...
CREATE SEQUENCE HRMS.SEQ_AUDIT START WITH 1 INCREMENT BY 1 CACHE 100;  -- the only cached one
```

**Issue:** `NOCACHE` forces a recursive `SYS.SEQ$` update and redo write per `NEXTVAL`. The high-traffic sequences are all uncached: `SEQ_PAYROLL_DETAIL` (`:29`) is called once per pay element per employee per run — the single hottest sequence in the system — plus `SEQ_LEAVE_REQUEST`, `SEQ_NOTIFICATION`, `SEQ_USER_SESSION`, `SEQ_EMP_HISTORY`. Ironically `SEQ_AUDIT`, the one that is cached, is the one whose gaps would matter least.

**Impact:** Row-cache lock contention (`enq: SQ`) and extra redo on every insert-heavy batch — directly compounding PERF-03.

**Recommendation:** `ALTER SEQUENCE ... CACHE 100` (or 1000 for `SEQ_PAYROLL_DETAIL`) for all surrogate-key sequences. Gaps are irrelevant for surrogate keys; if a gapless series is genuinely required for a business identifier, that requirement needs its own allocator table, not `NOCACHE`.

---

### PERF-05 — `CONNECT BY` org hierarchy in a view and a package (MEDIUM)

**Location:** `schema/views/hrms_views.sql:42-57`; `plsql/packages/PKG_EMPLOYEE.pkb:818-840`

```sql
-- WARNING: Performance degrades significantly with >500 employees
CREATE OR REPLACE VIEW HRMS.VW_ORG_HIERARCHY AS
SELECT ..., LEVEL AS ORG_LEVEL,
       SYS_CONNECT_BY_PATH(FIRST_NAME || ' ' || LAST_NAME, ' > ') AS ORG_PATH,
       CONNECT_BY_ISLEAF AS IS_LEAF
FROM EMPLOYEES
WHERE EMPLOYMENT_STATUS = 'ACTIVE'
START WITH MANAGER_EMP_ID IS NULL
CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
ORDER SIBLINGS BY LAST_NAME;
```

**Issue:** The view walks the whole tree from every root with no depth bound and materializes a string path per row, then `ORDER SIBLINGS BY` forces a sort at every level. `MANAGER_EMP_ID` has no index (only the `FK_EMP_MANAGER` constraint, which Oracle does not index automatically), so each level is a full scan of `EMPLOYEES`. Predicates pushed by callers (e.g. "subtree under employee X") cannot be applied before the walk. `PKG_EMPLOYEE.get_org_chart` does bound depth via `AND LEVEL <= p_max_depth` (`:836`) and is the better of the two.

**Impact:** Org-chart screens and reports degrade super-linearly; a management cycle in `MANAGER_EMP_ID` (nothing prevents one) raises `ORA-01436` and takes the view down entirely.

**Recommendation:** Index `MANAGER_EMP_ID`, replace `CONNECT BY` with a recursive CTE that accepts a root and depth as parameters (so pruning happens during the walk), and add a `NOCYCLE`/validation guard against management loops.

---

### PERF-06 — Day-by-day loops in the shared utility package (MEDIUM)

**Location:** `plsql/packages/PKG_COMMON.pkb:129-165`

```sql
FUNCTION business_days_between(...) RETURN NUMBER IS
BEGIN
    WHILE v_date <= TRUNC(p_end_date) LOOP
        IF TO_CHAR(v_date, 'DY', 'NLS_DATE_LANGUAGE=AMERICAN') NOT IN ('SAT', 'SUN') THEN
            v_count := v_count + 1;
        END IF;
        v_date := v_date + 1;
    END LOOP;
```

**Issue:** Pure-arithmetic weekday counting done by iteration; it is a closed-form calculation. `add_business_days` (`:151-165`) has the same shape plus a hazard: `WHILE v_added < p_days` with a negative `p_days` returns the input unchanged (silently wrong rather than erroring), and these two functions disagree with `PKG_LEAVE.calculate_business_days` because they ignore `HOLIDAYS` entirely — the same question gets two different answers depending on which helper a caller picks.

**Impact:** Wasted CPU on hot paths, plus inconsistent business-day semantics across modules.

**Recommendation:** Compute weekday counts in closed form, delegate holiday-aware counting to a single shared implementation, and raise on negative inputs.

---

### PERF-07 — Autonomous-transaction logging commits per row (MEDIUM)

**Location:** `plsql/packages/PKG_COMMON.pkb:16`, `:46`; `plsql/packages/PKG_AUDIT.pkb:14`; `plsql/packages/PKG_EMPLOYEE.pkb:155`; `plsql/packages/PKG_NOTIFICATION.pkb:27`

```sql
PROCEDURE log_action(...) IS
    PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
    INSERT INTO AUDIT_LOG (...) VALUES (...);
    COMMIT;
```

**Issue:** Five separate procedures open an independent transaction and commit per call. `PKG_AUDIT.log_action` is invoked from row-level triggers on `SALARY_RECORDS`, `LEAVE_REQUESTS`, and `DEPARTMENTS` (`plsql/triggers/trg_audit.sql:32`, `:51`, `:77`), so a bulk salary update performs one extra transaction — with its own redo flush — per affected row. Each autonomous call also consumes a session transaction slot; nested inside a long payroll run these accumulate.

**Impact:** Redo/log-file-sync amplification on every DML batch, and `ORA-01555`-class exposure in long-running jobs.

**Recommendation:** Buffer audit rows in a PL/SQL collection and flush with a single `FORALL` per statement (compound triggers make this straightforward), reserving autonomous transactions for error logging on the failure path only.

---

## 6. Validation Drift (Forms PLL vs. server-side PL/SQL)

### VAL-01 — Email validation: client `INSTR` logic rejects subdomains the server accepts (HIGH)

**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:14-41` vs. `plsql/packages/PKG_COMMON.pkb:265-268` (via `plsql/packages/PKG_VALIDATION.pkb:50-55`)

```sql
-- Client (PLL):
v_dot_pos := INSTR(p_email, '.', v_at_pos);
IF v_dot_pos = 0 OR v_dot_pos = v_at_pos + 1 OR v_dot_pos = LENGTH(p_email) THEN
    RETURN FALSE;
END IF;
-- BUG: Only checks for one dot after @, rejects valid subdomains
RETURN TRUE;
```

```sql
-- Server (PKG_COMMON):
RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

**Issue:** Two unrelated implementations of one rule. The client accepts `user@company` + any dot (so `a@b.c` passes, though the server requires a ≥2-char TLD) and, per its own comment, is meant to reject subdomains — though as written `user@mail.company.com` actually passes the `INSTR` checks, so the *comment* is also wrong. Conversely the client accepts strings the server rejects: `user@domain.c`, and any address containing characters outside the server's character class (e.g. `us er@x.com`).

**Impact:** Divergent accept/reject sets between the form field (`HRMS_EMPLOYEE.xml:370-377`) and the API. Users see a field accepted in the form and rejected on save, or — worse — an address the client blocks that a batch/API path admits.

**Recommendation:** Delete the client implementation and have the PLL call `PKG_VALIDATION.validate_email_format` so exactly one regex exists. Where a round trip per keystroke is unacceptable, generate the client copy from the server pattern rather than hand-writing it.

---

### VAL-02 — NULL handling diverges, and the server returns a `NULL` BOOLEAN (MEDIUM)

**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:25-27` vs. `plsql/packages/PKG_COMMON.pkb:265-268`

```sql
-- Client: explicit
IF p_email IS NULL THEN
    RETURN TRUE;  -- NULL is valid (not required check)
END IF;
```

**Issue:** The server has no NULL guard. `REGEXP_LIKE(NULL, ...)` yields `NULL`, so `is_valid_email(NULL)` returns a `NULL` BOOLEAN — neither `TRUE` nor `FALSE`. Callers written as `IF NOT PKG_VALIDATION.validate_email_format(x) THEN raise` (the pattern in `HRMS_EMPLOYEE.xml:377`) take the *false* branch on `NULL`, so validation is skipped rather than failed. The same hazard applies to `is_valid_phone` and `is_valid_ssn` (`:270-280`).

**Impact:** Three-valued-logic bugs that make NULL inputs pass or fail depending on how each caller phrases the test — the most easily overlooked class of validation drift.

**Recommendation:** Make the server functions NULL-explicit (`RETURN p_email IS NULL OR REGEXP_LIKE(...)`, matching the documented "NULL is valid" contract) and never return a nullable BOOLEAN from a validation API.

---

### VAL-03 — SSN validation: client enforces structural rules the server does not (MEDIUM)

**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:65-90` vs. `plsql/packages/PKG_COMMON.pkb:277-280`

```sql
-- Client: rejects all-zero groups
IF SUBSTR(v_digits, 1, 3) = '000' OR
   SUBSTR(v_digits, 4, 2) = '00' OR
   SUBSTR(v_digits, 6, 4) = '0000' THEN
    RETURN FALSE;
END IF;
```

```sql
-- Server: digit count only
RETURN REGEXP_LIKE(REGEXP_REPLACE(p_ssn, '[^0-9]', ''), '^\d{9}$');
```

**Issue:** The client rejects invalid SSA area/group/serial patterns; the server accepts `000-00-0000`. The client's `TRANSLATE(p_ssn, '0123456789-', '0123456789')` also only strips hyphens, while the server strips all non-digits — so `123 45 6789` fails client-side and passes server-side.

**Impact:** Placeholder SSNs enter through any non-Forms path (batch load, direct API), then fail downstream tax reporting where the client rule would have caught them.

**Recommendation:** Move the structural rules into `PKG_COMMON.is_valid_ssn` and have the PLL delegate.

---

### VAL-04 — Salary validation: NULL contract differs, and the "cache" is a live query (MEDIUM)

**Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:101-135` vs. `plsql/packages/PKG_VALIDATION.pkb:17-48`

```sql
-- Client:
-- BUG: Uses a hard-coded cache that's populated at form startup
-- and never refreshed. ...
IF p_salary IS NULL OR p_grade_id IS NULL THEN
    RETURN NULL;                    -- NULL means "valid"
END IF;
-- Direct DB query (not cached - contradicts the comment above)
SELECT MIN_SALARY, MAX_SALARY INTO v_min, v_max FROM JOB_GRADES WHERE GRADE_ID = p_grade_id;
```

```sql
-- Server:
IF p_salary IS NULL OR p_grade_id IS NULL THEN
    RETURN 'Salary and grade are required';   -- non-NULL means "invalid"
END IF;
```

**Issue:** Both return "NULL = valid, message = invalid", but they disagree on NULL inputs: the client treats a missing salary as acceptable, the server as a required-field error. Their messages also differ in format (`'Below minimum ($60,000)'` vs. `'Salary $50,000.00 is below minimum for grade Mid-Level ($60,000.00)'`), so the same rejection reads differently depending on entry path. The stale-cache comment is stale itself — there is no cache, as the code's own next comment admits.

**Impact:** Salaries can be saved NULL through the form and then rejected by server-side callers; inconsistent user-facing messaging; a misleading comment that invites someone to "fix" a caching bug that does not exist.

**Recommendation:** Have the PLL call `PKG_VALIDATION.validate_salary_for_grade` directly and delete the duplicate along with its comment.

---

### VAL-05 — Date-range validation exists only server-side (LOW)

**Location:** `plsql/packages/PKG_VALIDATION.pkb:6-15`, `:71-76` vs. `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:92-99`

```sql
-- Server has both:
FUNCTION validate_date_range(p_start_date, p_end_date) RETURN BOOLEAN  -- FALSE if either is NULL
FUNCTION is_future_date(p_date) RETURN BOOLEAN

-- Client has only:
FUNCTION validate_date_not_future(p_date) RETURN BOOLEAN  -- TRUE if NULL
```

**Issue:** No client counterpart to `validate_date_range`, so start/end ordering is only caught on submit (e.g. `PKG_LEAVE.pkb:116-118`). The two future-date helpers are near-inverses with opposite NULL behaviour (client `TRUE` for NULL, server `is_future_date(NULL)` returns `NULL`), inviting confusion about which to call.

**Impact:** Users lose entered data on a round trip that client-side validation could have prevented; NULL semantics differ again.

**Recommendation:** Add a client `validate_date_range` delegating to the server function, and align NULL behaviour explicitly.

---

## 7. Architectural Anti-Patterns

### ARCH-01 — Package dependency cycle risk, and the documented cycle is not the real one (HIGH)

**Location:** `plsql/packages/PKG_SECURITY.pkb:75`; `plsql/packages/PKG_EMPLOYEE.pkb:273-275`, `:617`, `:778`; claims at `plsql/packages/PKG_EMPLOYEE.pks:9`, `plsql/packages/PKG_PAYROLL.pks:9`, `README.md:127`

Actual body-level references:

```
PKG_SECURITY  -> PKG_AUDIT, PKG_EMPLOYEE
PKG_EMPLOYEE  -> PKG_AUDIT, PKG_COMMON, PKG_NOTIFICATION, PKG_PAYROLL
PKG_PAYROLL   -> PKG_AUDIT, PKG_COMMON
PKG_LEAVE     -> PKG_AUDIT, PKG_NOTIFICATION
```

**Issue:** Three files and the README state there is a circular dependency between `PKG_EMPLOYEE` and `PKG_PAYROLL`. There is not: `PKG_PAYROLL` never references `PKG_EMPLOYEE` in its body. The real structural problem is different and undocumented — `PKG_SECURITY` (authentication) depends on `PKG_EMPLOYEE` (`:75`, for `set_session_context`), which depends on `PKG_PAYROLL`, which means the authentication package cannot be compiled or patched without the payroll package's spec being valid. Combined with the documented-but-absent cycle, any developer trying to "break the cycle" will look in the wrong place.

**Impact:** A single invalid package spec cascades into failed authentication; the 3,000+ line packages the README flags (`:122`) cannot be split without unwinding this chain first. Documentation drift actively misdirects remediation.

**Recommendation:** Move `set_session_context` into `PKG_COMMON` (it manipulates session state, not employee data) to sever the `PKG_SECURITY` → `PKG_EMPLOYEE` edge, and correct the three stale comments. Add a dependency-cycle check over `ALL_DEPENDENCIES` to CI.

---

### ARCH-02 — Time & attendance import parses nothing (MEDIUM)

**Location:** `plsql/packages/PKG_INTEGRATION.pkb:150-186`

```sql
UTL_FILE.GET_LINE(v_file, v_line);

IF v_line IS NOT NULL AND SUBSTR(v_line, 1, 1) != '#' THEN
    -- Parse CSV: emp_number,date,hours_regular,hours_overtime
    -- TODO: Implement actual parsing and database update
    v_imported := v_imported + 1;
END IF;
...
PKG_COMMON.log_info('PKG_INTEGRATION', 'import_time_attendance',
    'Imported: ' || v_imported || ', Errors: ' || v_errors, p_user);
```

**Issue:** The procedure reads the file, counts lines, and discards them — then logs a success message reporting the line count as `Imported`. The header comment (`:151-152`) claims it "Reads time data from CSV file and updates payroll".

**Impact:** Worse than a missing feature: the batch scheduler and the audit log both report successful imports of data that was never stored. Overtime hours silently never reach payroll, and there is no failure signal to alert on.

**Recommendation:** Either implement the parse-and-apply (with a staging table and per-row error capture) or make the procedure raise `ORA-20xxx 'not implemented'` so the scheduler fails loudly. Do not log success for work not performed.

---

### ARCH-03 — 2024 federal tax brackets hard-coded while `TAX_BRACKETS` exists (MEDIUM)

**Location:** `plsql/packages/PKG_PAYROLL.pkb:602-681`; unused table at `schema/tables/02_payroll_tables.sql:159-177`

```sql
-- NOTE: Hard-coded 2024 brackets - should read from TAX_BRACKETS table
...
-- 2024 Federal tax brackets (Single)
-- TODO: Read from TAX_BRACKETS table instead of hard-coding
IF p_filing_status = 'SINGLE' OR p_filing_status = 'MARRIED_SEPARATE' THEN
    IF v_taxable <= 11600 THEN
        v_tax := v_taxable * 0.10;
    ELSIF v_taxable <= 47150 THEN
        v_tax := 1160 + (v_taxable - 11600) * 0.12;
    ...
```

**Issue:** Rates, thresholds, standard deductions, and allowance amounts are compiled into the package body (with `SEQ_TAX_BRACKET` and a `TAX_BRACKETS` table sitting unused). `MARRIED_SEPARATE` is folded into the `SINGLE` brackets, which is only coincidentally close, and any filing status other than the three named ones falls through with `v_tax := 0` — no error, no withholding. `EMPLOYEE_TAX_INFO.TAX_YEAR` exists (`02_payroll_tables.sql:178-202`) but the calculation ignores it, so historical or future-year runs silently apply 2024 rates.

**Impact:** Every tax-year change requires a production package recompile; a mis-typed filing status produces zero federal withholding — an IRS-liability defect rather than a maintainability one.

**Recommendation:** Load brackets from `TAX_BRACKETS` keyed by `(TAX_YEAR, FILING_STATUS)`, resolve the year from the pay period, and raise on an unrecognized filing status instead of returning 0.

---

### ARCH-04 — Flat-file `UTL_FILE` integrations with no retry or acknowledgment (MEDIUM)

**Location:** `plsql/packages/PKG_INTEGRATION.pkb:6-9`, `:16-30`, `:140-147`; documented at `plsql/packages/PKG_INTEGRATION.pks:8-13`

```sql
c_gl_output_dir       CONSTANT VARCHAR2(30) := 'GL_FEED_OUT';
c_benefits_output_dir CONSTANT VARCHAR2(30) := 'BENEFITS_FEED_OUT';
c_time_input_dir      CONSTANT VARCHAR2(30) := 'TIME_ATTENDANCE_IN';
...
v_file := UTL_FILE.FOPEN(c_gl_output_dir, v_filename, 'W', 32767);
UTL_FILE.PUT_LINE(v_file, 'H|HRMS_PAYROLL|' || TO_CHAR(SYSDATE, 'YYYY-MM-DD') || '|' || p_run_id);
```

**Issue:** GL and benefits data leave the database as pipe-delimited files on an Oracle directory object, picked up by an external FTP process using cleartext credentials (SEC-08). There is no acknowledgment, no idempotency key beyond the filename, and no retry (stated at `pks:11`). The filename embeds only `RUN_ID` and date, so re-running a feed for the same run on the same day silently overwrites (`'W'` mode) — and re-running on a *different* day produces a second file the downstream system will happily import again. Field values are concatenated unescaped, so any `|` in a description corrupts the record layout.

**Impact:** Duplicate or lost GL journal postings with no automated detection; a delimiter in free-text data misaligns columns in a financial feed.

**Recommendation:** Replace with an API/queue integration (or at minimum a staging table plus acknowledgment file), add a sequence-numbered idempotency key per feed, escape or reject delimiter characters, and reconcile posted totals against `PAYROLL_RUNS.TOTAL_GROSS`.

---

### ARCH-05 — Fiscal-year rule hard-coded despite a configuration parameter (MEDIUM)

**Location:** `plsql/packages/PKG_COMMON.pkb:167-195`; parameter at `data/seed/01_reference_data.sql:187-188`; noted at `plsql/packages/PKG_REPORTING.pks:10`

```sql
-- get_fiscal_year (fiscal year starts Oct 1)
FUNCTION get_fiscal_year(p_date IN DATE DEFAULT SYSDATE) RETURN NUMBER IS
BEGIN
    IF EXTRACT(MONTH FROM p_date) >= 10 THEN
        RETURN EXTRACT(YEAR FROM p_date) + 1;
    ELSE
        RETURN EXTRACT(YEAR FROM p_date);
    END IF;
END get_fiscal_year;
```

**Issue:** `SYSTEM_PARAMETERS.PAYROLL.FISCAL_YEAR_START = '10'` is seeded and never read. `get_fiscal_quarter` (`:184-195`) independently hard-codes the same October boundary as a month-list `CASE`, so the rule exists in two places and must be changed in both. The `CASE` has no `ELSE`, which is safe only because months 1–12 are exhaustive.

**Impact:** A fiscal-calendar change (acquisition, jurisdiction change) requires code edits in multiple packages, while the parameter that appears to control it does nothing — a trap for whoever tries the configuration route first.

**Recommendation:** Derive both functions from `PKG_COMMON.get_param_number('PAYROLL', 'FISCAL_YEAR_START')` with a cached package-level value, and delete the duplicated month logic.

---

### ARCH-06 — Audit payloads built by string concatenation (MEDIUM)

**Location:** `plsql/packages/PKG_COMMON.pkb:24-25`, `:53-54`; `plsql/triggers/trg_audit.sql:20-29`, `:56-57`

```sql
-- PKG_COMMON.log_error
'{"package":"' || p_package || '","procedure":"' || p_procedure ||
'","message":"' || REPLACE(SUBSTR(p_message, 1, 3000), '"', '\"') || '"}',

-- trg_audit.sql
v_new_json := '{"emp_id":' || :NEW.EMP_ID ||
              ',"salary":' || :NEW.BASE_SALARY ||
              ',"effective":"' || TO_CHAR(:NEW.EFFECTIVE_DATE, 'YYYY-MM-DD') || '"}';
```

**Issue:** Five sites hand-build JSON into `AUDIT_LOG.OLD_VALUES`/`NEW_VALUES`. `log_error` escapes only double quotes — a backslash, newline, or control character in `SQLERRM` produces invalid JSON. `log_info` (`:53-54`) escapes nothing at all. The trigger interpolates `NUMBER` values without `TO_CHAR`, so NLS decimal-separator settings (comma in many locales) emit `"salary":50000,00` — structurally broken JSON. Oracle 19c has native `JSON_OBJECT`.

**Impact:** Audit records that cannot be parsed by downstream compliance tooling, discovered only when someone tries to query them — typically during an audit. `AUDIT_LOG` is also a plain `CLOB` with no `IS JSON` check constraint, so nothing rejects malformed payloads at write time.

**Recommendation:** Use `JSON_OBJECT(...)` at all five sites and add `CONSTRAINT CHK_AUDIT_JSON CHECK (NEW_VALUES IS JSON)`.

---

### ARCH-07 — Termination leaves access, benefits, and final pay unimplemented (LOW)

**Location:** `plsql/packages/PKG_EMPLOYEE.pkb:737-739`

```sql
-- TODO: Integrate with benefits system to trigger COBRA
-- TODO: Revoke system access via PKG_SECURITY
-- TODO: Calculate final pay via PKG_PAYROLL.calculate_final_pay
```

**Issue:** `terminate_employee` updates status, logs history, and notifies the manager, but three offboarding steps are TODOs. Notably, nothing invalidates the terminated employee's `USER_SESSIONS` rows, and `PKG_SECURITY.logout` is never called — an active session survives termination until the 30-minute absolute timeout (SEC-11).

**Impact:** Terminated employees retain application access for up to 30 minutes; COBRA notification and final-pay calculation are manual, off-system steps.

**Recommendation:** Invalidate all `USER_SESSIONS` for the employee inside `terminate_employee`, and either implement or explicitly document the benefits/final-pay handoffs as manual with a checklist.

---

### ARCH-08 — Business rules triplicated across Forms, DB triggers, and packages (LOW)

**Location:** `plsql/triggers/trg_employees.sql:1-6`; `forms/xml-exports/HRMS_EMPLOYEE.xml:323-380`; `plsql/packages/PKG_EMPLOYEE.pkb`

```sql
-- These triggers enforce business rules at the database level,
-- duplicating logic that also exists in PKG_EMPLOYEE and Forms triggers.
-- This is a common anti-pattern in legacy Oracle Forms applications.
```

**Issue:** Audit-column defaulting, status defaulting, and validation exist in all three layers, and they have already drifted (DATA-01's trigger targets a schema version the packages do not; VAL-01–VAL-05 are the client/server half of the same problem). `HRMS_COMMON_LIB.pll.sql:32-36` contains a similar artifact — `MESSAGE` called twice with a comment asserting Forms requires it.

**Impact:** Every rule change needs three coordinated edits; the layers cannot be tested independently; migration effort is multiplied because the authoritative rule set has to be reconstructed from three drifted copies.

**Recommendation:** Designate the PL/SQL packages as the single source of truth, reduce DB triggers to audit-column defaulting only, and make Forms/PLL code call package APIs rather than reimplementing rules. Do this before any UI migration — the drift is the migration risk.

---

### ARCH-09 — README architecture figures do not match the repository (LOW)

**Location:** `README.md:33-47`, `:119-127`

```
| Forms Modules    |  | PL/SQL Packages  |  | Oracle Reports   |
| 18 forms         |  | 12 packages      |  | 8 reports        |
...
|   42 tables           |
|   15 views            |
|   200+ triggers       |
```

**Issue:** Actual contents: 6 Forms XML exports, 11 packages, 30 tables, 6 views, 2 trigger scripts (7 triggers), 29 sequences, 0 reports. The directory listing at `:54-65` also names files that do not exist (`HRMS_DEPARTMENT.xml`, `HRMS_REPORTS.xml`, `HRMS_LOV.xml`, `HRMS_TOOLBAR.xml`, `PKG_DEPARTMENT`), and `plsql/procedures/`, `plsql/functions/`, `plsql/types/`, `schema/indexes/`, `schema/constraints/`, `config/`, `docs/` are absent or empty. The "Known Technical Debt" list at `:119-127` also asserts the `PKG_EMPLOYEE`/`PKG_PAYROLL` cycle that ARCH-01 shows does not exist.

**Impact:** Scoping and estimation off by a factor of ~3-5 for anyone planning migration from the README; the missing `schema/indexes/` directory in particular hides that the only indexes in the estate are constraint-backed ones (see PERF-01, PERF-05).

**Recommendation:** Regenerate the counts and directory listing from the repository, and add a CI check that fails when they drift.

---

## 8. Prioritized Remediation Roadmap

Effort is expressed in engineering sessions (one focused implementation pass with verification), not calendar time.

### Phase 1 — Critical security (do first; blocks any production use)

| # | Finding | Why first | Effort |
|---|---|---|---|
| 1 | SEC-01 authentication bypass | Every other control is void while any password is accepted. Requires the `USER_CREDENTIALS` table that SEC-03/SEC-06 also depend on. | 2 sessions |
| 2 | SEC-03 MD5 → salted KDF | Same change set as SEC-01; do not implement credential storage twice. | included above |
| 3 | SEC-06 `change_password` | Completes the credential lifecycle; add caller-session authorization. | 1 session |
| 4 | SEC-02 encryption key | Key is exposed *and* the wrong length — SSN crypto is both broken and non-functional. Requires key rotation and re-encryption of existing data. | 2 sessions |
| 5 | SEC-04 SQL injection | Mechanical fix (bind variables) in one procedure. | 0.5 session |
| 6 | SEC-05 lockout + timing | Depends on the credential table from step 1. | 1 session |
| 7 | SEC-08 integration credentials | Wallet migration; coordinate with whoever owns the FTP endpoints. | 1 session |

**Exit criteria:** no code path authenticates without verifying a salted hash; no key or credential literal anywhere in the repository; `search_employees` uses only bind variables.

### Phase 2 — Data integrity (do before any data migration)

| # | Finding | Why here | Effort |
|---|---|---|---|
| 1 | DATA-01 trigger/DDL mismatch | `EMPLOYEES` updates fail outright; nothing downstream can be tested until fixed. | 0.5 session |
| 2 | DATA-02 seed column mismatch | Blocks clean-environment provisioning, so blocks verifying everything else. | 0.5 session |
| 3 | DATA-03 mutating-table trigger | `EMPLOYEES` inserts fail; fix together with adding `UK_EMP_EMAIL` (SEC-09). | 0.5 session |
| 4 | DATA-04 rehire deadlock | Whole business flow is unreachable. | 1 session |
| 5 | DATA-05, DATA-06, DATA-07 view defects | Wrong numbers reaching reports and BI; cheap, isolated SQL fixes. | 1 session |
| 6 | DATA-08 carryover erosion | Silent, unrecoverable balance loss — add the `LEAVE_ACCRUAL_LOG` ledger. | 1 session |
| 7 | RACE-01, RACE-02, RACE-03, RACE-04 | Concurrency correctness; RACE-03's row lock also fixes RACE-04. | 2 sessions |
| 8 | DATA-09, DATA-10, DATA-11, DATA-12 | Leave-accounting and lifecycle consistency. | 2 sessions |

**Exit criteria:** a clean-schema install seeds successfully; hire / transfer / terminate / rehire / leave-submit all complete end-to-end; concurrent-submission tests cannot overdraw a balance or double-allocate an employee number.

### Phase 3 — Performance (do before scaling or migration cutover)

| # | Finding | Notes | Effort |
|---|---|---|---|
| 1 | PERF-04 sequence caching | One `ALTER` script; largest win per unit of effort. | 0.25 session |
| 2 | PERF-01 set-based business days | Also unifies with PERF-06's duplicate implementations. | 1 session |
| 3 | PERF-03 payroll batching + restartability | Depends on RACE-02's period locking. | 2 sessions |
| 4 | PERF-02 SMTP connection reuse + retry policy | Includes honouring the ignored `RETRY_COUNT`. | 1 session |
| 5 | PERF-05 index `MANAGER_EMP_ID`, recursive CTE | Add the cycle guard at the same time. | 1 session |
| 6 | PERF-07 buffered audit writes | Compound triggers; measure redo before/after. | 1 session |

**Exit criteria:** payroll for the full employee set is restartable and completes without per-row commits; leave submission is O(1) queries; no `NOCACHE` on surrogate-key sequences.

### Phase 4 — Modernization (structural; unblocks UI migration)

| # | Finding | Notes | Effort |
|---|---|---|---|
| 1 | ARCH-01 dependency chain | Move `set_session_context` to `PKG_COMMON`; add the CI cycle check. Prerequisite for splitting the large packages. | 1 session |
| 2 | ARCH-08 + VAL-01…VAL-05 rule consolidation | Collapse client/server duplicates into package APIs. This is the main migration de-risking item: the drift *is* the risk. | 3 sessions |
| 3 | ARCH-03 tax brackets → `TAX_BRACKETS` | Removes the annual recompile and the zero-withholding fall-through. | 1 session |
| 4 | ARCH-02 time & attendance | Implement or fail loudly; stop logging false success. | 1 session |
| 5 | ARCH-04 flat-file → API/queue | Coordinate with GL and benefits vendors. | 3 sessions |
| 6 | ARCH-05, ARCH-06, ARCH-07, SEC-07, SEC-10, SEC-11, SEC-12, SEC-13, ARCH-09 | Configuration externalization, native JSON audit, RBAC model, session handling, doc accuracy. | 4 sessions |

**Exit criteria:** one authoritative implementation per business rule; no hard-coded configuration that duplicates a `SYSTEM_PARAMETERS` entry; a dependency-cycle and schema-drift check in CI.

### Cross-cutting recommendation

Two of the seven CRITICAL findings (DATA-01 and DATA-02, plus the `CHK_CHANGE_TYPE` violation inside DATA-01) are pure schema drift and were located mechanically by diffing every `INSERT`/`UPDATE` column list against `CREATE TABLE` DDL. That check takes seconds to run and should be the first CI job added — before any remediation begins, so it catches regressions introduced during Phases 1–4.

---

## Appendix — Finding Index

| ID | Severity | Category | Location |
|---|---|---|---|
| SEC-01 | CRITICAL | Security | `plsql/packages/PKG_SECURITY.pkb:30-80` |
| SEC-02 | CRITICAL | Security | `plsql/packages/PKG_SECURITY.pkb:6-7`, `:179-207` |
| SEC-03 | CRITICAL | Security | `plsql/packages/PKG_SECURITY.pkb:10-24` |
| SEC-04 | HIGH | Security | `plsql/packages/PKG_EMPLOYEE.pkb:440-499` |
| SEC-05 | HIGH | Security | `plsql/packages/PKG_SECURITY.pkb:26-57` |
| SEC-06 | HIGH | Security | `plsql/packages/PKG_SECURITY.pkb:211-234` |
| SEC-07 | HIGH | Security | `plsql/packages/PKG_NOTIFICATION.pkb:6-10` |
| SEC-08 | HIGH | Security | `plsql/packages/PKG_INTEGRATION.pks:8-13` |
| SEC-09 | MEDIUM | Security | `plsql/packages/PKG_SECURITY.pkb:51-57` |
| SEC-10 | MEDIUM | Security | `plsql/packages/PKG_SECURITY.pkb:129-174` |
| SEC-11 | MEDIUM | Security | `plsql/packages/PKG_SECURITY.pkb:8`, `:98-127` |
| SEC-12 | MEDIUM | Security | `forms/xml-exports/HRMS_LOGIN.xml:10-13`, `:45-51` |
| SEC-13 | LOW | Security | `plsql/packages/PKG_SECURITY.pkb:192-207` |
| DATA-01 | CRITICAL | Data integrity | `plsql/triggers/trg_employees.sql:76-110` |
| DATA-02 | CRITICAL | Data integrity | `data/seed/01_reference_data.sql:11-41`, `:182-200` |
| DATA-03 | CRITICAL | Data integrity | `plsql/triggers/trg_employees.sql:40-54` |
| DATA-04 | CRITICAL | Data integrity | `plsql/triggers/trg_employees.sql:69-74`, `plsql/packages/PKG_EMPLOYEE.pkb:750-771` |
| DATA-05 | HIGH | Data integrity | `schema/views/hrms_views.sql:96` |
| DATA-06 | HIGH | Data integrity | `schema/views/hrms_views.sql:109-129` |
| DATA-07 | HIGH | Data integrity | `schema/views/hrms_views.sql:32-35`, `:79` |
| DATA-08 | HIGH | Data integrity | `plsql/packages/PKG_LEAVE.pkb:605-622` |
| DATA-09 | MEDIUM | Data integrity | `plsql/packages/PKG_LEAVE.pkb:128-138` |
| DATA-10 | MEDIUM | Data integrity | `plsql/packages/PKG_LEAVE.pkb:182` and 4 others |
| DATA-11 | MEDIUM | Data integrity | `plsql/triggers/trg_employees.sql:114-129` |
| DATA-12 | MEDIUM | Data integrity | `plsql/packages/PKG_LEAVE.pkb:25-29`, `plsql/packages/PKG_VALIDATION.pkb:90-94` |
| RACE-01 | HIGH | Race condition | `plsql/packages/PKG_EMPLOYEE.pkb:39-55` |
| RACE-02 | HIGH | Race condition | `plsql/packages/PKG_PAYROLL.pkb:240-260` |
| RACE-03 | HIGH | Race condition | `plsql/packages/PKG_LEAVE.pkb:146-182` |
| RACE-04 | MEDIUM | Race condition | `plsql/packages/PKG_LEAVE.pkb:45-62` |
| PERF-01 | HIGH | Performance | `plsql/packages/PKG_LEAVE.pkb:12-40` |
| PERF-02 | HIGH | Performance | `plsql/packages/PKG_NOTIFICATION.pkb:78-107` |
| PERF-03 | HIGH | Performance | `plsql/packages/PKG_PAYROLL.pkb:265-347` |
| PERF-04 | MEDIUM | Performance | `schema/sequences/hrms_sequences.sql:9-49` |
| PERF-05 | MEDIUM | Performance | `schema/views/hrms_views.sql:42-57`, `plsql/packages/PKG_EMPLOYEE.pkb:818-840` |
| PERF-06 | MEDIUM | Performance | `plsql/packages/PKG_COMMON.pkb:129-165` |
| PERF-07 | MEDIUM | Performance | `plsql/packages/PKG_AUDIT.pkb:14` and 4 others |
| VAL-01 | HIGH | Validation drift | `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:14-41` vs `plsql/packages/PKG_COMMON.pkb:265-268` |
| VAL-02 | MEDIUM | Validation drift | `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:25-27` vs `plsql/packages/PKG_COMMON.pkb:265-268` |
| VAL-03 | MEDIUM | Validation drift | `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:65-90` vs `plsql/packages/PKG_COMMON.pkb:277-280` |
| VAL-04 | MEDIUM | Validation drift | `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:101-135` vs `plsql/packages/PKG_VALIDATION.pkb:17-48` |
| VAL-05 | LOW | Validation drift | `plsql/packages/PKG_VALIDATION.pkb:6-15` vs `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:92-99` |
| ARCH-01 | HIGH | Architecture | `plsql/packages/PKG_SECURITY.pkb:75`, `plsql/packages/PKG_EMPLOYEE.pkb:273-275` |
| ARCH-02 | MEDIUM | Architecture | `plsql/packages/PKG_INTEGRATION.pkb:150-186` |
| ARCH-03 | MEDIUM | Architecture | `plsql/packages/PKG_PAYROLL.pkb:602-681` |
| ARCH-04 | MEDIUM | Architecture | `plsql/packages/PKG_INTEGRATION.pkb:6-9`, `:16-30` |
| ARCH-05 | MEDIUM | Architecture | `plsql/packages/PKG_COMMON.pkb:167-195` |
| ARCH-06 | MEDIUM | Architecture | `plsql/packages/PKG_COMMON.pkb:24-25`, `plsql/triggers/trg_audit.sql:20-29` |
| ARCH-07 | LOW | Architecture | `plsql/packages/PKG_EMPLOYEE.pkb:737-739` |
| ARCH-08 | LOW | Architecture | `plsql/triggers/trg_employees.sql:1-6` |
| ARCH-09 | LOW | Architecture | `README.md:33-47` |
