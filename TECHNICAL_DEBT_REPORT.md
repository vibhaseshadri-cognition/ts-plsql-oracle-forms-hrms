# Technical Debt Report — ts-plsql-oracle-forms-hrms

**Repository:** `vibhaseshadri-cognition/ts-plsql-oracle-forms-hrms`
**Stack:** Oracle Forms 12c, Oracle Reports, Oracle Database 19c, PL/SQL, WebLogic
**Report date:** 2026-07-20
**Scope:** Static analysis of `plsql/` packages & triggers, `schema/` tables/views/sequences, `forms/` PLL libraries & XML exports, and `data/seed/`.

---

## Executive Summary

This legacy Oracle Forms/PL/SQL HRMS carries substantial technical debt spanning security, data integrity, concurrency, performance, and architecture. The most urgent problems are not stylistic — several are **runtime-breaking or security-critical**:

- **Authentication is effectively bypassed**: `PKG_SECURITY.authenticate` never validates the supplied password. Any known active email returns a valid session.
- **Passwords are hashed with MD5** and a **symmetric encryption key is hard-coded** in source.
- **A core audit trigger references columns that do not exist** in `EMPLOYEE_HISTORY`, so any department/job/status change to `EMPLOYEES` fails at runtime (`ORA-00904`), breaking `PKG_EMPLOYEE.transfer_employee` / `promote_employee`.
- **Seed scripts reference non-existent / omit mandatory columns**, so a clean install of reference data fails.

These should be treated as release blockers. A prioritized remediation roadmap is provided at the end.

### Severity counts

| Severity | Count |
|----------|-------|
| CRITICAL | 7 |
| HIGH     | 9 |
| MEDIUM   | 15 |
| LOW      | 5 |
| **Total**| **36** |

### Category breakdown

| Category | Findings | IDs |
|----------|----------|-----|
| Security | 10 | SEC-01 … SEC-10 |
| Race conditions | 2 | RACE-01, RACE-02 |
| Performance | 6 | PERF-01 … PERF-06 |
| Validation drift | 4 | DRIFT-01 … DRIFT-04 |
| Circular dependencies | 1 | CIRC-01 |
| Architectural anti-patterns | 7 | ARCH-01 … ARCH-07 |
| Data integrity | 6 | DATA-01 … DATA-06 |

---

## 1. Security Vulnerabilities

### SEC-01 — Passwords hashed with MD5 (unsalted)
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb:14-24`
- **Snippet:**
  ```sql
  FUNCTION hash_password(p_password IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
      RETURN RAWTOHEX(
          DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(p_password), DBMS_CRYPTO.HASH_MD5)
      );
  END hash_password;
  ```
- **Issue:** MD5 is cryptographically broken and used with no salt and no work factor.
- **Impact:** Trivial offline cracking / rainbow-table recovery of any exposed hash; identical passwords produce identical hashes.
- **Recommendation:** Replace with a salted, adaptive KDF (`DBMS_CRYPTO.HASH` with SHA-512 plus a per-user random salt at minimum; prefer PBKDF2/bcrypt-style iteration). Force a password reset on migration.

### SEC-02 — Hard-coded encryption key in source
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb:6-7`
- **Snippet:**
  ```sql
  -- VULNERABILITY: Encryption key hard-coded in source
  c_encryption_key RAW(32) := UTL_RAW.CAST_TO_RAW('HR$ystem_3ncrypt10n_K3y_2024!!');
  ```
- **Issue:** The symmetric key used for SSN encryption/decryption is committed to version control.
- **Impact:** Anyone with repo access can decrypt all PII; key rotation is impossible without a code change and redeploy.
- **Recommendation:** Move the key to Oracle Wallet / TDE or an external KMS; load at runtime. Rotate the key and re-encrypt existing data. Purge the key from git history.

### SEC-03 — SQL injection via dynamic-SQL string concatenation
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:445-499` (`search_employees`)
- **Snippet:**
  ```sql
  IF p_last_name IS NOT NULL THEN
      v_sql := v_sql || 'AND UPPER(e.LAST_NAME) LIKE UPPER(''' || p_last_name || '%'') ';
  END IF;
  ```
- **Issue:** User-supplied search parameters (last name, first name, department, status, location, dates) are concatenated directly into a dynamic query.
- **Impact:** Classic SQL injection — data exfiltration, auth-context abuse, potential DoS.
- **Recommendation:** Use bind variables with `DBMS_SQL` / `OPEN ... FOR ... USING`, or `DBMS_ASSERT` for identifiers. Never concatenate raw input.

### SEC-04 — Hard-coded SMTP config; cleartext mail over port 25 (no TLS)
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:6-10, 78-135`
- **Snippet:**
  ```sql
  c_smtp_host    CONSTANT VARCHAR2(100) := 'smtp.internal.company.com';
  c_smtp_port    CONSTANT NUMBER := 25;
  c_from_address CONSTANT VARCHAR2(100) := 'hrms-noreply@company.com';
  ```
- **Issue:** SMTP host/port/from are hard-coded (should be in `SYSTEM_PARAMETERS`); mail is sent unauthenticated in cleartext on port 25 with no STARTTLS.
- **Impact:** HR notifications (PII) transit unencrypted; environment portability requires code changes.
- **Recommendation:** Externalize to `SYSTEM_PARAMETERS`; use authenticated SMTP with TLS.

### SEC-05 — No account lockout / brute-force protection
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_SECURITY.pkb:26-80`
- **Issue:** `authenticate` records no failed-attempt counter and never locks accounts (the vulnerability is even acknowledged in a comment).
- **Impact:** Unlimited online password guessing.
- **Recommendation:** Track failed attempts, apply throttling/lockout and alerting.

### SEC-06 — Timing side-channel between invalid user and invalid password
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_SECURITY.pkb:46-57`
- **Issue:** Different code paths / response times for unknown user vs. bad password (acknowledged in-code).
- **Impact:** Username enumeration.
- **Recommendation:** Constant-time flow; identical generic error and comparable latency for all failures.

### SEC-07 — Authentication bypass: password never verified
- **Severity:** CRITICAL
- **Location:** `plsql/packages/PKG_SECURITY.pkb:30-80`
- **Snippet:**
  ```sql
  -- Look up user
  SELECT EMP_ID INTO v_emp_id FROM EMPLOYEES
  WHERE UPPER(EMAIL) = UPPER(p_username) AND EMPLOYMENT_STATUS = 'ACTIVE';
  -- NOTE: ... we simulate authentication against a simplified model.
  -- Create session  (no comparison of p_password against any stored hash)
  ```
- **Issue:** `authenticate` looks up the employee by email and immediately creates a session. The `p_password` argument is **never compared** to any stored credential.
- **Impact:** Complete authentication bypass — knowing any active employee's email grants a valid session. This is the single most severe defect in the codebase.
- **Recommendation:** Implement real credential verification against a `USER_CREDENTIALS` store using SEC-01's hardened hashing; fail closed.

### SEC-08 — Password-change routine is a stub; weak complexity rules
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_SECURITY.pkb:211-234` (`change_password`)
- **Snippet:**
  ```sql
  -- NOTE: Actual password update would go to USER_CREDENTIALS table
  -- This is a stub for the legacy system model
  ```
- **Issue:** Complexity is validated but the password is never persisted; there is no real credential lifecycle.
- **Impact:** Users cannot actually change passwords; false sense of security.
- **Recommendation:** Implement persistence with history/expiry; enforce robust complexity centrally.

### SEC-09 — `decrypt_ssn` swallows errors and returns a sentinel string
- **Severity:** LOW
- **Location:** `plsql/packages/PKG_SECURITY.pkb` (SSN encrypt/decrypt helpers)
- **Issue:** Decryption failures are caught and a placeholder/error string is returned rather than raising.
- **Impact:** Corrupt/garbage SSNs can silently propagate into reports and downstream feeds.
- **Recommendation:** Fail loudly; log and raise a defined exception.

### SEC-10 — Coarse, hard-coded authorization logic
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_SECURITY.pkb` (`has_permission` / role checks)
- **Issue:** Role/permission checks are simplistic and embedded in code rather than data-driven.
- **Impact:** Hard to audit, easy to grant excessive access; privilege drift.
- **Recommendation:** Move to a data-driven RBAC model with least privilege.

---

## 2. Race Conditions

### RACE-01 — `MAX()+1` employee-number generation without locking
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:36-55` (`generate_emp_number`)
- **Snippet:**
  ```sql
  SELECT NVL(MAX(TO_NUMBER(SUBSTR(EMP_NUMBER, 5))), 0) + 1
  INTO v_max_num FROM EMPLOYEES
  WHERE EMP_NUMBER LIKE c_emp_number_prefix || '-%';
  ```
- **Issue:** No `FOR UPDATE` / serialization; concurrent inserts compute the same max. The `WHEN OTHERS` fallback switches to `SEQ_EMPLOYEE`, producing an inconsistent numbering scheme.
- **Impact:** Duplicate employee numbers / unique-constraint violations under concurrency; inconsistent IDs.
- **Recommendation:** Use a dedicated sequence (`SEQ_EMP_NUMBER` already exists) as the single source of truth.

### RACE-02 — Leave balance check-then-update without `FOR UPDATE`
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_LEAVE.pkb:86-103, 175-182` (`submit_leave_request`)
- **Issue:** Available balance is read for validation and later decremented, but the initial read does not lock the `LEAVE_BALANCES` row.
- **Impact:** Two concurrent requests can both pass validation and over-draw the balance (negative available leave).
- **Recommendation:** `SELECT ... FOR UPDATE` on the balance row before validating, or enforce via a serialized update with a check constraint.

---

## 3. Performance Issues

### PERF-01 — Day-by-day loop with a per-day query in business-day calc
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_LEAVE.pkb:21-37`
- **Snippet:**
  ```sql
  WHILE v_date <= TRUNC(p_end_date) LOOP
      ...
      SELECT COUNT(*) INTO v_holiday_count FROM HOLIDAYS WHERE HOLIDAY_DATE = v_date ...;
      v_date := v_date + 1;
  END LOOP;
  ```
- **Issue:** One `HOLIDAYS` lookup per day in the range.
- **Impact:** N queries per request; scales poorly for long ranges / batch runs.
- **Recommendation:** Fetch holidays in one set-based query; compute weekdays with date arithmetic (no row-by-row loop).

### PERF-02 — Additional day-by-day loops for business-day math
- **Severity:** LOW
- **Location:** `plsql/packages/PKG_COMMON.pkb:139-145, 158-165`
- **Issue:** `calculate_business_days` / `add_business_days` iterate one day at a time.
- **Impact:** Unnecessary CPU for wide date ranges.
- **Recommendation:** Replace with set-based / arithmetic day-count formulas.

### PERF-03 — `CONNECT BY` org hierarchy without depth guard in the view
- **Severity:** MEDIUM
- **Location:** `schema/views/hrms_views.sql:47-57` (`VW_ORG_HIERARCHY`); `plsql/packages/PKG_EMPLOYEE.pkb:827-838` (`get_org_chart`)
- **Snippet:**
  ```sql
  -- WARNING: Performance degrades significantly with >500 employees
  ... START WITH MANAGER_EMP_ID IS NULL CONNECT BY PRIOR EMP_ID = MANAGER_EMP_ID
  ```
- **Issue:** Full-tree hierarchical traversal; the view has no depth cap and the warning is acknowledged in-code.
- **Impact:** Degrades sharply as headcount grows; risk of cycles if data integrity slips.
- **Recommendation:** Add depth limits / `NOCYCLE`, index `MANAGER_EMP_ID`, and consider materialized snapshots for reporting.

### PERF-04 — SMTP connection opened per notification inside a loop
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_NOTIFICATION.pkb:78-135` (`process_queue`)
- **Snippet:**
  ```sql
  v_connection := UTL_SMTP.OPEN_CONNECTION(c_smtp_host, c_smtp_port);
  ... -- send one message
  UTL_SMTP.QUIT(v_connection);
  ```
- **Issue:** A new TCP/SMTP session is established and torn down for every queued email.
- **Impact:** High latency and connection churn on large batches.
- **Recommendation:** Open one connection and reuse it for the batch (or use a mail relay/queue).

### PERF-05 — `NOCACHE` on virtually all sequences
- **Severity:** LOW
- **Location:** `schema/sequences/hrms_sequences.sql:9-49`
- **Snippet:**
  ```sql
  CREATE SEQUENCE HRMS.SEQ_EMPLOYEE START WITH 10000 INCREMENT BY 1 NOCACHE;
  ```
- **Issue:** Nearly every sequence is `NOCACHE` (only `SEQ_AUDIT` caches). The file itself notes gaps for `SEQ_EMP_NUMBER`.
- **Impact:** Extra recursive dictionary I/O and contention on high-volume inserts.
- **Recommendation:** Apply a sensible `CACHE` (e.g. 20–100) to high-throughput sequences; accept gaps.

### PERF-06 — Row-by-row payroll processing with mid-loop commits
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:294-347` (`calculate_payroll`)
- **Issue:** Employees are processed one at a time with a `COMMIT` every 50 rows.
- **Impact:** Slow batch throughput; partial commits leave a run half-calculated on failure (see ARCH-06).
- **Recommendation:** Set-based / bulk (`FORALL`, `BULK COLLECT`) processing within a single transactional boundary per run.

---

## 4. Validation Drift (Forms PLL vs. server-side packages)

### DRIFT-01 — Email validation differs between client and server
- **Severity:** MEDIUM
- **Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:17-41` vs `plsql/packages/PKG_COMMON.pkb:265-268`
- **Snippet (server):**
  ```sql
  RETURN REGEXP_LIKE(p_email, '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
  ```
- **Issue:** The PLL performs a stricter, hand-rolled check (rejects valid subdomains, per its own comment) while the server regex is more permissive.
- **Impact:** Values accepted by the server are rejected in the form (and vice versa) — inconsistent UX and data.
- **Recommendation:** Single source of truth — have the form call the server validator (`PKG_VALIDATION`/`PKG_COMMON`).

### DRIFT-02 — Salary-range validation: stale-cache comment vs. live query
- **Severity:** MEDIUM
- **Location:** `forms/libraries/HRMS_VALIDATION_LIB.pll.sql:108-135`
- **Issue:** Comments claim a cached `JOB_GRADES` range is used, but the code issues a direct query; client behavior (soft warning) also differs from the server's hard error (`PKG_VALIDATION`).
- **Impact:** Misleading documentation and inconsistent enforcement of grade salary bands.
- **Recommendation:** Remove stale comments; centralize salary-band validation server-side.

### DRIFT-03 — Date-range validation split across three layers
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_VALIDATION.pkb:6-15`, `forms/libraries/HRMS_VALIDATION_LIB.pll.sql`, plus `CHK_LR_DATES` in `schema/tables/03_leave_tables.sql:89`
- **Issue:** The PLL checks "not in the past", the server checks `end >= start` and null handling, and the table has its own check constraint — no single owner.
- **Impact:** Divergent rules; edge cases accepted in one layer, rejected in another.
- **Recommendation:** Consolidate date rules server-side and let the DB constraint be the backstop.

### DRIFT-04 — Grade salary check is a soft warning on create, hard error elsewhere
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb` (`create_employee`) vs `plsql/packages/PKG_VALIDATION.pkb:17-48`
- **Issue:** `create_employee` treats out-of-band salary as a warning; `PKG_VALIDATION` raises.
- **Impact:** Employees can be created outside their grade band, bypassing the intended control.
- **Recommendation:** Enforce a single policy for all write paths.

---

## 5. Circular Dependencies

### CIRC-01 — `PKG_EMPLOYEE` ⇄ `PKG_PAYROLL`
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_EMPLOYEE.pkb:273-280, 617-626`
- **Snippet:**
  ```sql
  -- NOTE: Circular dependency - calls PKG_PAYROLL.create_salary_record
  -- which in turn may call PKG_EMPLOYEE.is_active for validation
  ```
- **Issue:** `PKG_EMPLOYEE` (create/promote) calls `PKG_PAYROLL.create_salary_record`, which calls back into `PKG_EMPLOYEE` — a mutual dependency, acknowledged in-code.
- **Impact:** Fragile recompilation order (`INVALID` package states), harder testing/refactoring.
- **Recommendation:** Extract shared validation (`is_active`, salary rules) into a lower-level package both depend on, breaking the cycle.

---

## 6. Architectural Anti-Patterns

### ARCH-01 — Autonomous-transaction overuse for logging/notifications
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_AUDIT.pkb:14`, `PKG_COMMON.pkb:16,46`, `PKG_NOTIFICATION.pkb:27-28`
- **Issue:** `PRAGMA AUTONOMOUS_TRANSACTION` with independent `COMMIT`/`ROLLBACK` is used broadly for logging.
- **Impact:** Audit rows can persist for actions the parent later rolls back (and vice versa), skewing the audit trail; masks failures via blanket `WHEN OTHERS`.
- **Recommendation:** Reserve autonomous transactions for true fire-and-forget audit; ensure audit consistency is intentional and documented.

### ARCH-02 — `UTL_FILE` flat-file integrations with hard-coded directory objects
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_INTEGRATION.pkb:6-9`, `PKG_PAYROLL.pkb:822-894`
- **Snippet:**
  ```sql
  c_gl_output_dir CONSTANT VARCHAR2(30) := 'GL_FEED_OUT';
  ```
- **Issue:** GL/benefits/time feeds and the pay register are file-based with directory names baked into code.
- **Impact:** Brittle integrations, environment coupling, error-prone parsing.
- **Recommendation:** Externalize directory config; move toward API/staging-table integration with validation.

### ARCH-03 — Stub / TODO implementations in production paths
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_INTEGRATION.pkb:153-203` (`import_time_attendance` "TODO: implement actual parsing"; LDAP/AD `sync_org_structure` placeholder), `PKG_REPORTING.pkb:196-204` (`refresh_reporting_tables` placeholder), `PKG_PAYROLL.pkb:784-785` (YTD placeholders), `PKG_SECURITY.pkb:211-234` (see SEC-08)
- **Issue:** Multiple externally-callable routines are stubs that silently "succeed".
- **Impact:** Silent no-ops (e.g. time import increments a counter but writes nothing); reports show placeholder `0` YTD values.
- **Recommendation:** Implement or explicitly disable/raise `NOT_IMPLEMENTED`; never return success from a stub.

### ARCH-04 — Hard-coded fiscal-year start (Oct 1)
- **Severity:** LOW
- **Location:** `plsql/packages/PKG_COMMON.pkb:170-195` (`get_fiscal_year`)
- **Issue:** Fiscal year boundary is hard-coded.
- **Impact:** Wrong fiscal grouping if policy changes / for other orgs.
- **Recommendation:** Drive from `SYSTEM_PARAMETERS`.

### ARCH-05 — Hard-coded 2024 tax brackets and wage base (with an unused table)
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:7-14, 643-685`; unused `TAX_BRACKETS` table in `schema/tables/02_payroll_tables.sql`
- **Snippet:**
  ```sql
  c_ss_wage_base_2024 CONSTANT NUMBER := 168600;
  c_standard_deduction_single CONSTANT NUMBER := 14600;
  ```
- **Issue:** Federal brackets, SS wage base and standard deductions are constants for tax year 2024, even though a `TAX_BRACKETS` table exists and is ignored.
- **Impact:** Payroll is silently wrong for any other tax year; annual code change required.
- **Recommendation:** Read effective-dated rates from `TAX_BRACKETS`/config.

### ARCH-06 — Mid-loop commits produce partial-state batches
- **Severity:** MEDIUM
- **Location:** `plsql/packages/PKG_PAYROLL.pkb:294-347`; `PKG_LEAVE.pkb:602, 622`
- **Issue:** Batch routines commit inside loops; on error a payroll run / carryover is left half-applied.
- **Impact:** Non-atomic financial operations; difficult recovery/reconciliation.
- **Recommendation:** One transaction per logical run with checkpoint/restart, or idempotent re-runnable design.

### ARCH-07 — Duplicated (and divergent) employee-history logging
- **Severity:** MEDIUM
- **Location:** `plsql/triggers/trg_employees.sql:76-110` vs `plsql/packages/PKG_EMPLOYEE.pkb` (`log_history`, used by transfer/promote)
- **Issue:** Both a row trigger and the package write `EMPLOYEE_HISTORY`, with different column sets (the trigger's set is invalid — see DATA-01).
- **Impact:** Double/conflicting history semantics; the trigger path is outright broken.
- **Recommendation:** Choose one mechanism (prefer the package) and remove the other.

---

## 7. Data Integrity Risks

### DATA-01 — `TRG_EMP_BEFORE_UPDATE` inserts non-existent columns into `EMPLOYEE_HISTORY`
- **Severity:** CRITICAL
- **Location:** `plsql/triggers/trg_employees.sql:78-110` vs table DDL `schema/tables/01_core_tables.sql:152-177`
- **Trigger uses:** `HISTORY_ID, EMP_ID, CHANGE_TYPE, CHANGE_DATE, OLD_VALUE, NEW_VALUE, CHANGED_BY, CHANGE_REASON`
- **Table actually has:** `HIST_ID, EMP_ID, CHANGE_TYPE, EFFECTIVE_DATE, OLD_DEPT_ID/NEW_DEPT_ID, OLD_JOB_ID/NEW_JOB_ID, OLD_MANAGER_ID/NEW_MANAGER_ID, OLD_SALARY/NEW_SALARY, OLD_LOCATION/NEW_LOCATION, REASON_CODE, COMMENTS, CREATED_BY, CREATED_DATE`
- **Issue:** `HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE`, `CHANGED_BY`, `CHANGE_REASON` do not exist. Every `UPDATE` to `EMPLOYEES` that changes status, department, or job fires this trigger and fails with `ORA-00904: invalid identifier`.
- **Impact:** Core employee mutations are broken at runtime, including `PKG_EMPLOYEE.transfer_employee` (`...pkb:543-550`) and `promote_employee` (`...pkb:610-614`). This is a release blocker.
- **Recommendation:** Rewrite the trigger against the real columns (or delete it in favor of `PKG_EMPLOYEE.log_history`, per ARCH-07).

### DATA-02 — Trigger `CHANGE_TYPE` values violate `CHK_CHANGE_TYPE`
- **Severity:** HIGH
- **Location:** `plsql/triggers/trg_employees.sql:94, 106` vs `schema/tables/01_core_tables.sql:173-176`
- **Issue:** The trigger writes `CHANGE_TYPE = 'DEPARTMENT_CHANGE'` and `'JOB_CHANGE'`, but the check constraint only allows `HIRE, TRANSFER, PROMOTION, DEMOTION, SALARY_CHANGE, TERMINATION, REHIRE, LEAVE_START, LEAVE_END, STATUS_CHANGE`.
- **Impact:** Even after DATA-01 is fixed, these inserts would fail the check constraint (`ORA-02290`).
- **Recommendation:** Map to allowed values (`TRANSFER` / `PROMOTION`) and add tests covering the constraint.

### DATA-03 — Seed `JOB_GRADES` uses a non-existent column and omits a mandatory one
- **Severity:** CRITICAL
- **Location:** `data/seed/01_reference_data.sql:23-42` vs `schema/tables/01_core_tables.sql:57-71`
- **Snippet:**
  ```sql
  INSERT INTO JOB_GRADES (GRADE_ID, GRADE_NAME, GRADE_LEVEL, MIN_SALARY, MAX_SALARY, ...)
  ```
- **Issue:** `JOB_GRADES` has no `GRADE_LEVEL` column, and its `GRADE_CODE VARCHAR2(10) NOT NULL` (unique) is never supplied.
- **Impact:** Reference-data load fails (`ORA-00904` for `GRADE_LEVEL`, or `ORA-01400` on `GRADE_CODE`), blocking a clean install. Downstream FKs (`JOB_TITLES → JOB_GRADES`) then cascade-fail.
- **Recommendation:** Fix the seed to insert `GRADE_CODE` and drop `GRADE_LEVEL` (or add the column to DDL if intended).

### DATA-04 — Seed `LOCATIONS` references `PHONE`, table column is `PHONE_NUMBER`
- **Severity:** HIGH
- **Location:** `data/seed/01_reference_data.sql:11-18` vs `schema/tables/01_core_tables.sql:35-45`
- **Issue:** The seed inserts a `PHONE` column; the table defines `PHONE_NUMBER`.
- **Impact:** `ORA-00904` — location reference data fails to load, cascading to employee/department seeds that reference `LOCATION_CODE`.
- **Recommendation:** Rename the seed column to `PHONE_NUMBER`.

### DATA-05 — `VW_LEAVE_SUMMARY.AVAILABLE` omits `PENDING`, contradicting the table's generated column
- **Severity:** MEDIUM
- **Location:** `schema/views/hrms_views.sql:96` vs `schema/tables/03_leave_tables.sql:47`
- **Snippet:**
  ```sql
  -- view:
  lb.OPENING_BALANCE + lb.ACCRUED - lb.USED + lb.ADJUSTMENT AS AVAILABLE
  -- table generated column:
  AVAILABLE ... GENERATED ALWAYS AS (OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING) VIRTUAL
  ```
- **Issue:** The view's `AVAILABLE` does not subtract `PENDING`, while the table's generated `AVAILABLE` (and `PKG_LEAVE.get_leave_balance`) do.
- **Impact:** The summary view overstates available leave versus every other code path — users may request leave they don't have.
- **Recommendation:** Align the view expression with the generated column (subtract `PENDING`), or select the generated column directly.

### DATA-06 — `expire_carryover` is non-idempotent (double-subtracts)
- **Severity:** HIGH
- **Location:** `plsql/packages/PKG_LEAVE.pkb:605-623`
- **Snippet:**
  ```sql
  -- BUG: If run twice on same day, can double-subtract
  UPDATE LEAVE_BALANCES SET
      ADJUSTMENT = ADJUSTMENT - CARRYOVER_FROM_PREV,
      CARRYOVER_FROM_PREV = 0
  WHERE CARRYOVER_EXPIRY_DT <= TRUNC(SYSDATE) AND CARRYOVER_FROM_PREV > 0;
  ```
- **Issue:** Although it zeroes `CARRYOVER_FROM_PREV`, the routine is a re-runnable job with no run-guard, and the acknowledged risk is corrupting `ADJUSTMENT` if invoked in overlapping windows / re-processed.
- **Impact:** Silent, hard-to-detect corruption of employee leave balances.
- **Recommendation:** Make it idempotent with a processed-marker / run log and a single transactional boundary.

---

## Prioritized Migration Roadmap

### Phase 1 — Critical security (immediate)
1. **SEC-07** implement real password verification (close the auth bypass).
2. **SEC-01 / SEC-02** replace MD5 with salted adaptive hashing; move the encryption key to a wallet/KMS, rotate, re-encrypt, purge from history.
3. **SEC-03** parameterize `search_employees` with bind variables.
4. **SEC-05 / SEC-06** add lockout/throttling and constant-time auth responses.

### Phase 2 — Data integrity (release blockers)
1. **DATA-01 / DATA-02** fix or remove `TRG_EMP_BEFORE_UPDATE` so employee mutations work (unblocks transfer/promote).
2. **DATA-03 / DATA-04** fix seed scripts so a clean install loads reference data.
3. **DATA-05** align `VW_LEAVE_SUMMARY` availability math.
4. **DATA-06** make carryover expiry idempotent.
5. **ARCH-07** consolidate history logging to one mechanism.

### Phase 3 — Performance
1. **PERF-04** reuse a single SMTP connection per batch.
2. **PERF-06 / ARCH-06** convert payroll to set-based, single-transaction runs.
3. **PERF-01 / PERF-02** eliminate day-by-day loops (set-based holidays/business days).
4. **PERF-03** add depth guard / `NOCYCLE` and index `MANAGER_EMP_ID`.
5. **PERF-05** enable `CACHE` on high-throughput sequences.

### Phase 4 — Modernization
1. **ARCH-05** externalize tax rates into `TAX_BRACKETS`/config; remove 2024 constants.
2. **ARCH-02 / ARCH-03** replace `UTL_FILE` stubs with real, validated integrations (or fail explicitly).
3. **ARCH-04** externalize fiscal-year config.
4. **CIRC-01** break the `PKG_EMPLOYEE ⇄ PKG_PAYROLL` cycle via a shared base package.
5. **DRIFT-01…04** unify client/server validation with a single server-side source of truth.
6. **SEC-04 / SEC-08 / SEC-09 / SEC-10** externalize SMTP config with TLS, implement password lifecycle, fail loudly on decrypt errors, adopt data-driven RBAC.

---

*Report generated from static analysis of the repository at branch head. No runnable application/test harness exists in the repo; validation is limited to `sqlfluff` and `xmllint`.*
