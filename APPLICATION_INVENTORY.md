# Application Inventory — Oracle Forms/PL/SQL HRMS Estate

## Overview

| Layer | Component Type | Count |
|-------|---------------|-------|
| UI | Forms Modules (XML exports) | 6 |
| UI | PL/SQL Libraries (PLL) | 2 |
| UI | Menu Modules | 1 |
| Business Logic | PL/SQL Packages | 11 (22 files: .pks + .pkb) |
| Data Access | Database Triggers | 6 (across 2 files) |
| Data Access | Tables | 25 (across 4 files) |
| Data Access | Sequences | 22 |
| Data Access | Views | 6 |

**Architecture**: Oracle Forms 12c → WebLogic 12c → Oracle Database 19c (HRMS schema)

---

## 1. Forms Modules (`forms/xml-exports/`)

| Filename | Purpose | Layer | Key Dependencies |
|----------|---------|-------|-----------------|
| `HRMS_LOGIN.xml` | User authentication form. Collects username/password, calls PKG_SECURITY.authenticate, establishes session via GLOBAL variables. | UI | PKG_SECURITY, HRMS_COMMON_LIB, HRMS_VALIDATION_LIB |
| `HRMS_EMPLOYEE.xml` | Master-detail employee management. 5 data blocks (EMPLOYEE, JOB_INFO, SALARY, DEPENDENTS, EMP_HISTORY) with tabbed canvas for personal info, job, compensation, dependents, and history. | UI | PKG_EMPLOYEE, PKG_SECURITY, PKG_COMMON, HRMS_COMMON_LIB, HRMS_VALIDATION_LIB |
| `HRMS_LEAVE.xml` | Leave request submission and approval workflow. Blocks: LEAVE_REQUEST, NEW_REQUEST, LEAVE_BALANCE, LEAVE_APPROVAL, TEAM_CALENDAR. LOV for leave types. | UI | PKG_LEAVE, PKG_SECURITY, HRMS_COMMON_LIB, HRMS_VALIDATION_LIB |
| `HRMS_PAYROLL.xml` | Payroll processing — pay period management, payroll run creation, calculation, and approval. | UI | PKG_PAYROLL, PKG_SECURITY, HRMS_COMMON_LIB, HRMS_VALIDATION_LIB |
| `HRMS_PERFORMANCE.xml` | Performance review cycle management — review creation, self-assessment, manager review, goal tracking. 4 data blocks. | UI | PKG_PERFORMANCE, PKG_SECURITY, HRMS_COMMON_LIB, HRMS_VALIDATION_LIB |
| `HRMS_MENU.xml` | MDI parent navigation form. Main menu bar launches all other forms via OPEN_FORM. Role-based menu item visibility. | UI | All other forms (launches them), PKG_SECURITY (role checks) |

---

## 2. PL/SQL Libraries (`forms/libraries/`)

| Filename | Purpose | Layer | Key Dependencies |
|----------|---------|-------|-----------------|
| `HRMS_COMMON_LIB.pll.sql` | Shared UI utility library. Provides message display (show_message, show_error, show_confirm), date formatting, navigation helpers (go_to_form), LOV population, and form-level security checks. | Utility | Forms built-in packages (MESSAGE, GO_BLOCK, EXECUTE_QUERY) |
| `HRMS_VALIDATION_LIB.pll.sql` | Client-side validation library. Validates email format, phone numbers, SSN format, salary-for-grade ranges, date ranges, and required fields. Called from WHEN-VALIDATE-ITEM triggers. | Utility | JOB_GRADES table (salary range lookup), Forms built-ins |

---

## 3. Menu Modules (`forms/menus/`)

| Filename | Purpose | Layer | Key Dependencies |
|----------|---------|-------|-----------------|
| `HRMS_MENU.mmb.sql` | Main application menu definition. Hierarchical menu with items: File (Login/Logout/Exit), Employee, Leave, Payroll, Performance, Reports, Administration (Users, Parameters, Audit Log). Role-based enable/disable via PKG_SECURITY.has_role. | UI | PKG_SECURITY, all forms modules |

---

## 4. PL/SQL Packages (`plsql/packages/`)

| Filename | Purpose | Layer | Key Dependencies |
|----------|---------|-------|-----------------|
| `PKG_COMMON.pks` / `.pkb` | Base utility package. Error/info logging (autonomous transaction), configuration parameter access (SYSTEM_PARAMETERS), date utilities (business_days_between, add_business_days, fiscal year/quarter), formatting (phone, SSN masking, currency, name), validation (email, phone, SSN regex). | Utility | None (base package) |
| `PKG_AUDIT.pks` / `.pkb` | Centralized audit trail. log_action (autonomous transaction writes to AUDIT_LOG with IP and session), purge_old_records, get_change_history (returns REF CURSOR). | Utility | None (base package) |
| `PKG_VALIDATION.pks` / `.pkb` | Centralized validation. Date range validation, salary-for-grade validation, email/phone format (delegates to PKG_COMMON), employee number format check, future date check, business day check (checks HOLIDAYS table), required fields check. | Business Logic | PKG_COMMON |
| `PKG_NOTIFICATION.pks` / `.pkb` | Notification queue management. Queues email/SMS/in-app notifications (autonomous transaction), processes queue via UTL_SMTP (batch of 50), retry logic (max 3), cancellation. Hard-coded SMTP config. | Integration | PKG_COMMON |
| `PKG_SECURITY.pks` / `.pkb` | Authentication and authorization. Password hashing (MD5), authenticate (username/password → session_id), session creation/validation/termination, role checking (has_role, has_permission), SSN encryption/decryption (AES-256 with hard-coded key). | Business Logic | PKG_COMMON, PKG_AUDIT, DBMS_CRYPTO |
| `PKG_EMPLOYEE.pks` / `.pkb` | Employee lifecycle management. CRUD operations, employee number generation (race condition: uses MAX+1), hire, transfer, promote, terminate, rehire. Manages EMPLOYEES, EMPLOYEE_HISTORY, SALARY_RECORDS. | Business Logic | PKG_SECURITY, PKG_PAYROLL, PKG_COMMON, PKG_AUDIT, PKG_NOTIFICATION |
| `PKG_PAYROLL.pks` / `.pkb` | Payroll processing engine. Pay period creation (monthly/biweekly), payroll run lifecycle (create → calculate → approve → pay), tax calculation (federal/state with brackets), deduction processing, YTD tracking, GL journal generation trigger. | Business Logic | PKG_EMPLOYEE, PKG_COMMON, PKG_AUDIT |
| `PKG_LEAVE.pks` / `.pkb` | Leave management. Submit/approve/reject/cancel requests, balance tracking, accrual processing, carryover management, overlap detection, business day calculation (location-aware holidays). | Business Logic | PKG_EMPLOYEE, PKG_COMMON, PKG_AUDIT, PKG_NOTIFICATION |
| `PKG_PERFORMANCE.pks` / `.pkb` | Performance review management. Review cycle CRUD (create/open/close), individual review management, self-assessment/manager review submission, goal tracking with progress, rating distribution, team review queries. | Business Logic | PKG_EMPLOYEE, PKG_COMMON, PKG_AUDIT, PKG_NOTIFICATION |
| `PKG_REPORTING.pks` / `.pkb` | Report generation. Headcount, compensation summary, turnover, new hires, leave utilization, payroll summary, EEO compliance reports. All return REF CURSORs. refresh_reporting_tables for nightly denormalization. | Data Access | PKG_EMPLOYEE, PKG_PAYROLL, PKG_COMMON |
| `PKG_INTEGRATION.pks` / `.pkb` | External system integration. GL journal generation (pipe-delimited flat file via UTL_FILE), ADP benefits feed export (fixed-width format), time/attendance CSV import (stub), org structure sync (placeholder). | Integration | PKG_COMMON, PKG_PAYROLL, PKG_EMPLOYEE |

---

## 5. Database Triggers (`plsql/triggers/`)

| Filename | Trigger Name | Purpose | Layer | Dependencies |
|----------|-------------|---------|-------|-------------|
| `trg_audit.sql` | TRG_SALARY_AUDIT | AFTER INSERT/UPDATE/DELETE on SALARY_RECORDS. Logs all salary changes as JSON to AUDIT_LOG for compliance. | Data Access | PKG_AUDIT.log_action |
| `trg_audit.sql` | TRG_LEAVE_REQUEST_AUDIT | AFTER UPDATE OF STATUS on LEAVE_REQUESTS. Logs leave status transitions. | Data Access | PKG_AUDIT.log_action |
| `trg_audit.sql` | TRG_DEPARTMENT_AUDIT | AFTER INSERT/UPDATE/DELETE on DEPARTMENTS. Tracks org structure changes. | Data Access | PKG_AUDIT.log_action |
| `trg_employees.sql` | TRG_EMP_BEFORE_INSERT | BEFORE INSERT on EMPLOYEES. Sets audit columns, defaults (ACTIVE_FLAG, EMPLOYMENT_STATUS), validates hire date (≤180 days future), checks email uniqueness. | Data Access | EMPLOYEES table |
| `trg_employees.sql` | TRG_EMP_BEFORE_UPDATE | BEFORE UPDATE on EMPLOYEES. Sets MODIFIED_BY/DATE, prevents direct reactivation of terminated employees, logs status/department/job changes to EMPLOYEE_HISTORY. | Data Access | EMPLOYEE_HISTORY table |
| `trg_employees.sql` | TRG_EMP_INSTEAD_OF_DELETE | BEFORE DELETE on EMPLOYEES. Prevents physical deletion — raises error to enforce soft-delete pattern. | Data Access | None (raises error) |

---

## 6. Schema Objects — Tables (`schema/tables/`)

| Filename | Tables Defined | Domain | Layer |
|----------|---------------|--------|-------|
| `01_core_tables.sql` | DEPARTMENTS, LOCATIONS, JOB_GRADES, JOB_TITLES, EMPLOYEES, EMPLOYEE_HISTORY, EMPLOYEE_DEPENDENTS, EMERGENCY_CONTACTS | Employee | Data Access |
| `02_payroll_tables.sql` | SALARY_RECORDS, PAY_ELEMENTS, EMPLOYEE_PAY_ELEMENTS, PAY_PERIODS, PAYROLL_RUNS, PAYROLL_DETAILS, TAX_BRACKETS, EMPLOYEE_TAX_INFO, EMPLOYEE_BANK_ACCOUNTS | Payroll | Data Access |
| `03_leave_tables.sql` | LEAVE_TYPES, LEAVE_BALANCES, LEAVE_REQUESTS, LEAVE_ACCRUAL_LOG, HOLIDAYS | Leave | Data Access |
| `04_performance_tables.sql` | REVIEW_CYCLES, PERFORMANCE_REVIEWS, PERFORMANCE_GOALS, AUDIT_LOG, SYSTEM_PARAMETERS, NOTIFICATION_QUEUE, USER_SESSIONS, LOOKUP_VALUES | Performance / System | Data Access |

---

## 7. Schema Objects — Sequences (`schema/sequences/hrms_sequences.sql`)

| Sequence | Purpose | Start | Cache |
|----------|---------|-------|-------|
| SEQ_DEPARTMENT | Department surrogate keys | 100 | NOCACHE |
| SEQ_LOCATION | Location surrogate keys | 100 | NOCACHE |
| SEQ_JOB_GRADE | Job grade surrogate keys | 100 | NOCACHE |
| SEQ_JOB_TITLE | Job title surrogate keys | 100 | NOCACHE |
| SEQ_EMPLOYEE | Employee surrogate keys | 10000 | NOCACHE |
| SEQ_EMP_HISTORY | Employee history surrogate keys | 1 | NOCACHE |
| SEQ_DEPENDENT | Dependent surrogate keys | 1 | NOCACHE |
| SEQ_EMERGENCY_CONTACT | Emergency contact surrogate keys | 1 | NOCACHE |
| SEQ_EMP_NUMBER | Employee number generation (unused — PKG_EMPLOYEE uses MAX+1) | 1000 | NOCACHE |
| SEQ_SALARY | Salary record surrogate keys | 1 | NOCACHE |
| SEQ_PAY_ELEMENT | Pay element surrogate keys | 1 | NOCACHE |
| SEQ_EMP_PAY_ELEMENT | Employee pay element surrogate keys | 1 | NOCACHE |
| SEQ_PAY_PERIOD | Pay period surrogate keys | 1 | NOCACHE |
| SEQ_PAYROLL_RUN | Payroll run surrogate keys | 1 | NOCACHE |
| SEQ_PAYROLL_DETAIL | Payroll detail surrogate keys | 1 | NOCACHE |
| SEQ_TAX_BRACKET | Tax bracket surrogate keys | 1 | NOCACHE |
| SEQ_LEAVE_TYPE | Leave type surrogate keys | 1 | NOCACHE |
| SEQ_LEAVE_BALANCE | Leave balance surrogate keys | 1 | NOCACHE |
| SEQ_LEAVE_REQUEST | Leave request surrogate keys | 1 | NOCACHE |
| SEQ_LEAVE_ACCRUAL | Leave accrual log surrogate keys | 1 | NOCACHE |
| SEQ_HOLIDAY | Holiday surrogate keys | 1 | NOCACHE |
| SEQ_REVIEW_CYCLE | Review cycle surrogate keys | 1 | NOCACHE |
| SEQ_PERF_REVIEW | Performance review surrogate keys | 1 | NOCACHE |
| SEQ_PERF_GOAL | Performance goal surrogate keys | 1 | NOCACHE |
| SEQ_AUDIT | Audit log surrogate keys | 1 | CACHE 100 |
| SEQ_NOTIFICATION | Notification queue surrogate keys | 1 | NOCACHE |
| SEQ_USER_SESSION | User session surrogate keys | 1 | NOCACHE |
| SEQ_SYSTEM_PARAM | System parameter surrogate keys | 1 | NOCACHE |
| SEQ_LOOKUP | Lookup value surrogate keys | 1 | NOCACHE |

---

## 8. Schema Objects — Views (`schema/views/hrms_views.sql`)

| View Name | Purpose | Layer | Key Dependencies |
|-----------|---------|-------|-----------------|
| VW_ACTIVE_EMPLOYEES | Denormalized view of active employees with department, job, manager, location, and current salary. Used by Forms LOVs and reports. | Data Access | EMPLOYEES, DEPARTMENTS, JOB_TITLES, JOB_GRADES, LOCATIONS, SALARY_RECORDS |
| VW_ORG_HIERARCHY | Hierarchical org chart using CONNECT BY PRIOR. Returns org level, path, and leaf status. Performance degrades with >500 employees. | Data Access | EMPLOYEES |
| VW_EMPLOYEE_COMPENSATION | Current compensation with compa-ratio calculation (salary vs grade midpoint). | Data Access | EMPLOYEES, DEPARTMENTS, JOB_TITLES, JOB_GRADES, SALARY_RECORDS |
| VW_LEAVE_SUMMARY | Current-year leave balances with utilization percentage per employee per leave type. | Data Access | LEAVE_BALANCES, EMPLOYEES, DEPARTMENTS, LEAVE_TYPES |
| VW_PAYROLL_LATEST | Latest approved payroll run details per employee — gross, taxes, deductions, net. | Data Access | PAYROLL_DETAILS, EMPLOYEES, PAYROLL_RUNS, PAY_PERIODS |
| VW_PENDING_APPROVALS | Unified view of pending items across modules (leave requests + performance reviews awaiting action). | Data Access | LEAVE_REQUESTS, EMPLOYEES, LEAVE_TYPES, PERFORMANCE_REVIEWS, REVIEW_CYCLES |
