# HRMS Migration Strategy

> **Application**: Oracle Forms 12c HRMS · **Database**: Oracle 19c  
> **Users**: ~200 concurrent across 3 regional offices (HQ New York, Chicago, San Francisco)  
> **Scope**: 18 Forms, 12 PL/SQL packages, 42 tables, 15 views, 200+ triggers, 8 Oracle Reports

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture Overview](#2-current-architecture-overview)
3. [Migration Analysis by Functional Area](#3-migration-analysis-by-functional-area)
   - [3.1 Login / Authentication](#31-login--authentication)
   - [3.2 Employee Management](#32-employee-management)
   - [3.3 Leave Management](#33-leave-management)
   - [3.4 Payroll Processing](#34-payroll-processing)
   - [3.5 Performance Reviews](#35-performance-reviews)
   - [3.6 Reporting](#36-reporting)
   - [3.7 Integration](#37-integration)
   - [3.8 Navigation Shell](#38-navigation-shell)
4. [Summary Recommendation Matrix](#4-summary-recommendation-matrix)
5. [Recommended Hybrid Approach](#5-recommended-hybrid-approach)
6. [Total Effort Estimate](#6-total-effort-estimate)
7. [Risk Register](#7-risk-register)
8. [Migration Sequencing Roadmap](#8-migration-sequencing-roadmap)

---

## 1. Executive Summary

This document evaluates three migration strategies for the legacy HRMS application:

| Strategy | Description |
|----------|-------------|
| **Strangler Fig** | Incremental replacement; new services coexist with Oracle Forms via database-shared-state or API adapters |
| **Big-Bang Rewrite** | Complete replacement with Java Spring Boot (REST API) + React (SPA) |
| **Re-Platform (Oracle APEX)** | Move the UI from Forms 12c to APEX while preserving the Oracle 19c database and as much PL/SQL as possible |

**Bottom line**: A **hybrid approach** is recommended—APEX re-platform for the majority of CRUD-heavy modules, a Spring Boot microservice for payroll and integration (where the business rules need modernization), and a greenfield React SPA only for the reporting/analytics layer. Estimated total effort for the hybrid path: **76–106 person-weeks** (~18–24 months with a 5-person team).

---

## 2. Current Architecture Overview

```
┌────────────────────────────────────────────────────────────┐
│  Oracle Forms 12c  (client applet via WebLogic)            │
│  ┌──────────┐ ┌──────────────┐ ┌───────────┐ ┌──────────┐ │
│  │HRMS_LOGIN│ │HRMS_EMPLOYEE │ │HRMS_LEAVE │ │HRMS_MENU │ │
│  └──────────┘ └──────────────┘ └───────────┘ └──────────┘ │
│  ┌──────────────┐ ┌────────────────┐ ┌───────────────────┐ │
│  │HRMS_PAYROLL  │ │HRMS_PERFORMANCE│ │ HRMS_REPORTS (rdf)│ │
│  └──────────────┘ └────────────────┘ └───────────────────┘ │
│  Libraries: HRMS_COMMON_LIB.pll, HRMS_VALIDATION_LIB.pll  │
│  Menu: HRMS_MENU.mmb                                       │
└──────────────────┬─────────────────────────────────────────┘
                   │  PL/SQL calls (thick-client → DB)
┌──────────────────▼─────────────────────────────────────────┐
│  Oracle Database 19c                                        │
│  Packages:                                                  │
│    PKG_SECURITY, PKG_EMPLOYEE, PKG_LEAVE, PKG_PAYROLL,     │
│    PKG_PERFORMANCE, PKG_REPORTING, PKG_INTEGRATION,         │
│    PKG_COMMON, PKG_AUDIT, PKG_NOTIFICATION, PKG_VALIDATION │
│  Tables: 42 (EMPLOYEES, DEPARTMENTS, SALARY_RECORDS,        │
│    PAY_PERIODS, PAYROLL_RUNS, PAYROLL_DETAILS, LEAVE_*,     │
│    PERFORMANCE_*, AUDIT_LOG, USER_SESSIONS, etc.)           │
│  Views: 15 (VW_ACTIVE_EMPLOYEES, VW_ORG_HIERARCHY,         │
│    VW_EMPLOYEE_COMPENSATION, VW_LEAVE_SUMMARY,              │
│    VW_PAYROLL_LATEST, etc.)                                 │
│  Sequences: 25 (SEQ_EMPLOYEE, SEQ_PAYROLL_RUN, etc.)        │
│  Triggers: 200+ (TRG_EMP_BEFORE_INSERT, TRG_SALARY_AUDIT…) │
│  External: UTL_FILE → flat files, UTL_SMTP → email          │
└─────────────────────────────────────────────────────────────┘
```

### Key Technical Debt Affecting Migration Choices

| ID | Issue | Severity | Relevant Code |
|----|-------|----------|---------------|
| SEC-01 | MD5 password hashing | CRITICAL | `PKG_SECURITY.pkb` line 25: `DBMS_OBFUSCATION_TOOLKIT.md5` |
| SEC-02 | Hard-coded AES-256 encryption key | CRITICAL | `PKG_SECURITY.pkb` line 7: `c_encryption_key` constant |
| SEC-03 | No account lockout / no 2FA | HIGH | `PKG_SECURITY.authenticate()` — no failed-attempt tracking |
| SEC-04 | Cleartext password over Forms applet | HIGH | `HRMS_LOGIN.xml` — Forms limitation |
| RACE-01 | Employee number generation race | MEDIUM | `PKG_EMPLOYEE.pkb` lines 39-55: `MAX()+1` instead of sequence |
| RACE-02 | Payroll period overlap check without locking | MEDIUM | `PKG_PAYROLL.create_pay_periods()` |
| ARCH-01 | Circular dependency PKG_EMPLOYEE ↔ PKG_PAYROLL | MEDIUM | `PKG_EMPLOYEE.pkb` line 275 calls `PKG_PAYROLL.create_salary_record` |
| ARCH-02 | Validation drift: `HRMS_VALIDATION_LIB.pll` vs `PKG_VALIDATION` | MEDIUM | Client email regex rejects subdomains; server allows them |
| ARCH-03 | Trigger-based soft delete converts DELETE to error | LOW | `TRG_EMP_INSTEAD_OF_DELETE` raises -20504 |
| PERF-01 | VW_ORG_HIERARCHY CONNECT BY degrades >500 employees | MEDIUM | `hrms_views.sql` line 46 |
| PERF-02 | Row-by-row payroll calculation (cursor loop) | MEDIUM | `PKG_PAYROLL.calculate_payroll` line 296 |
| INTEG-01 | UTL_FILE flat-file integration with no retry | HIGH | `PKG_INTEGRATION.pkb` — `GL_FEED_OUT`, `BENEFITS_FEED_OUT` |
| INTEG-02 | Hard-coded SMTP config | LOW | `PKG_NOTIFICATION.pkb` lines 6-10 |
| DATA-01 | Hard-coded 2024 tax brackets in PL/SQL constants | MEDIUM | `PKG_PAYROLL.pkb` lines 6-14: `c_ss_wage_base_2024`, `c_ss_rate` |

---

## 3. Migration Analysis by Functional Area

### 3.1 Login / Authentication

**Current State**: `HRMS_LOGIN.xml` → `PKG_SECURITY.authenticate()` → `USER_SESSIONS` table. MD5 hashing, hard-coded AES key, no lockout, no 2FA, cleartext password transport. Permission model in `PKG_SECURITY.has_permission()` uses a grade-based RBAC (grade ≥ 8 = full access, grade ≥ 5 = view all, etc.).

#### Strangler Fig

- **Coexistence**: Deploy an OAuth 2.0/OIDC identity provider (e.g., Keycloak, Azure AD) alongside the legacy system. The Forms login continues to work, but new modules authenticate via tokens.
- **Adapters needed**: A thin PL/SQL wrapper that validates JWT tokens and maps OIDC claims to `USER_SESSIONS` rows so legacy Forms can still call `PKG_SECURITY.is_session_valid()`.
- **Sequencing**: Authentication should be strangled **first** — all other modules depend on it.
- **Duration**: 4–6 weeks.

#### Big-Bang Rewrite (Spring Boot + React)

- **Scope**: Spring Security with OAuth 2.0 / OIDC integration. React login page with PKCE flow. Replace `PKG_SECURITY` entirely.
- **Architecture**: `AuthController` → Spring Security filter chain → JWT issuance. Role model maps from `JOB_GRADES.GRADE_LEVEL` to Spring roles (`ROLE_ADMIN`, `ROLE_MANAGER`, `ROLE_USER`).
- **Testing**: Parallel-run both auth systems; compare session creation rates and permission outcomes for 2 weeks.
- **Risk**: HIGH — any auth failure locks out all 200 users. Requires rollback plan (DNS switch back to Forms endpoint).
- **Duration**: 6–8 weeks.

#### Re-Platform (Oracle APEX)

- **APEX mapping**: APEX has built-in authentication schemes (Custom, LDAP, Social Sign-In). Replace Forms login with an APEX Custom Authentication scheme calling a refactored `PKG_SECURITY.authenticate_v2()` that uses `DBMS_CRYPTO` with bcrypt or PBKDF2 via a Java stored procedure.
- **PL/SQL reuse**: ~60% — `has_permission()` logic can be reused as an APEX Authorization Scheme. `encrypt_ssn`/`decrypt_ssn` can be reused directly. `authenticate()` must be rewritten to fix MD5.
- **APEX constraints**: APEX session management replaces `USER_SESSIONS`; the custom session table becomes redundant. APEX's built-in session timeout and CSRF protection handle SEC-03/SEC-04.
- **Duration**: 3–4 weeks.

#### Recommendation

| Approach | Fit (1-5) |
|----------|-----------|
| Strangler Fig | 4 |
| Big-Bang | 3 |
| APEX | **5** |

**Recommended: APEX Re-Platform.** APEX's built-in auth infrastructure directly addresses SEC-01 through SEC-04 with minimal custom code. The grade-based permission model in `PKG_SECURITY.has_permission()` maps cleanly to APEX Authorization Schemes.

**Prerequisites**: (1) Provision APEX workspace on the 19c database, (2) Create refactored `PKG_SECURITY.authenticate_v2()` with bcrypt hashing, (3) Migrate `USER_CREDENTIALS` table to use new hash format with backward-compatible dual-check during transition.

**Effort**: **M (3–4 person-weeks)**

---

### 3.2 Employee Management

**Current State**: `HRMS_EMPLOYEE.xml` is the most complex form — 5 data blocks (`EMPLOYEE`, `SALARY`, `DEPENDENTS`, `EMERGENCY_CONTACTS`, `EMP_HISTORY`), 4 tab pages, 8 LOVs, master-detail relationships. Backend: `PKG_EMPLOYEE` (966 lines) with `create_employee`, `update_employee`, `transfer_employee`, `terminate_employee`, `rehire_employee`. Circular dependency with `PKG_PAYROLL` via `create_salary_record`. Triggers: `TRG_EMP_BEFORE_INSERT`, `TRG_EMP_BEFORE_UPDATE`, `TRG_EMP_INSTEAD_OF_DELETE`.

#### Strangler Fig

- **Coexistence**: Build a new Employee Service (REST API) that reads/writes the same `EMPLOYEES`, `SALARY_RECORDS`, `EMPLOYEE_DEPENDENTS`, `EMERGENCY_CONTACTS`, `EMPLOYEE_HISTORY` tables. Legacy Forms and new React UI coexist — both hit the same database. Database triggers provide a consistency safety net.
- **Adapters**: A change-data-capture (CDC) adapter or shared-database approach. No API adapter needed since both systems talk to the same schema. However, the new service must respect the trigger behavior (e.g., `TRG_EMP_INSTEAD_OF_DELETE` prevents hard deletes — new service must implement soft-delete pattern matching the `ACTIVE_FLAG = 'N'` convention).
- **Sequencing**: Employee management is a **dependency for all other modules**. Must be migrated early (2nd after auth) but can start with read-only views (employee profile) before enabling write operations.
- **Duration**: 10–14 weeks (due to complexity of 5 sub-entities and 8 LOVs).

#### Big-Bang Rewrite (Spring Boot + React)

- **Scope**: `EmployeeController` with REST endpoints for CRUD on all 5 sub-entities. React form with tabbed layout (Personal, Salary, Dependents, Emergency Contacts, History). State management via React Query for server-state + Zustand/Redux for UI state.
- **Architecture**:
  ```
  POST   /api/employees          → create_employee
  PUT    /api/employees/{id}     → update_employee
  GET    /api/employees/{id}     → get employee + eager-load tabs
  GET    /api/employees/{id}/salary-history
  GET    /api/employees/{id}/dependents
  POST   /api/employees/{id}/transfer
  POST   /api/employees/{id}/terminate
  ```
- **Testing**: Generate parity test suite from seed data (`02_employee_data.sql` — 25 employees across departments). Verify all state transitions: ACTIVE→ON_LEAVE→ACTIVE, ACTIVE→TERMINATED, TERMINATED→(rehire)→ACTIVE.
- **Risk**: MEDIUM-HIGH — the circular dependency between `PKG_EMPLOYEE` and `PKG_PAYROLL` must be untangled. In Spring Boot, use an `EmployeeService` → `SalaryService` one-way dependency with events for the reverse direction.
- **Duration**: 12–16 weeks.

#### Re-Platform (Oracle APEX)

- **APEX mapping**: Master-detail form maps directly to an APEX Interactive Grid (master) with Detail sub-regions (tabbed). The 8 LOVs (`LOV_DEPARTMENT`, `LOV_JOB_TITLE`, `LOV_MANAGER`, `LOV_LOCATION`, etc.) map to APEX LOV (Popup or Select List) components backed by the same queries. The 4 tab pages become APEX Sub-Regions with Tab display.
- **PL/SQL reuse**: ~80% — `PKG_EMPLOYEE` procedures (`create_employee`, `update_employee`, `transfer_employee`, `terminate_employee`) can be called directly from APEX page processes. The `validate_manager` recursive loop (line 88–131) works as-is.
- **APEX constraints**: APEX's Interactive Grid handles multi-row edit/save natively. The `TRG_EMP_INSTEAD_OF_DELETE` trigger quirk (Forms works around it with `CLEAR_RECORD`) is handled naturally in APEX by never issuing DELETE — use a "Deactivate" button calling `PKG_EMPLOYEE.terminate_employee()` instead. BLOB `PHOTO_BLOB` column can use APEX File Browse item.
- **Duration**: 6–8 weeks.

#### Recommendation

| Approach | Fit (1-5) |
|----------|-----------|
| Strangler Fig | 3 |
| Big-Bang | 3 |
| APEX | **5** |

**Recommended: APEX Re-Platform.** The master-detail, tab-page, LOV-heavy structure of `HRMS_EMPLOYEE.xml` is exactly the pattern APEX is designed for. 80% of `PKG_EMPLOYEE` PL/SQL can be reused with minimal refactoring. The circular dependency with `PKG_PAYROLL` remains in the database layer and doesn't need to be resolved for APEX.

**Prerequisites**: (1) Fix `generate_emp_number` race condition (RACE-01) — switch from `MAX()+1` to `SEQ_EMP_NUMBER.NEXTVAL`, (2) Consolidate validation drift between `HRMS_VALIDATION_LIB.pll` and `PKG_VALIDATION` into a single server-side layer, (3) APEX workspace must be provisioned.

**Effort**: **L (8–10 person-weeks)**

---

### 3.3 Leave Management

**Current State**: `HRMS_LEAVE.xml` — 5 data blocks (`LEAVE_REQUEST`, `NEW_REQUEST`, `LEAVE_BALANCE`, `PENDING_APPROVAL`, `TEAM_CAL`), 4 tab pages, 3 LOVs. Backend: `PKG_LEAVE` (673 lines) with `submit_leave_request`, `approve_leave_request`, `reject_leave_request`, `cancel_leave_request`, `run_accrual`, `year_end_carryover`. Tables: `LEAVE_TYPES`, `LEAVE_BALANCES` (with `AVAILABLE` virtual column), `LEAVE_REQUESTS`, `LEAVE_ACCRUAL_LOG`, `HOLIDAYS`. Known bugs: `calculate_business_days` doesn't handle observed holidays; half-day overlap detection is incomplete.

#### Strangler Fig

- **Coexistence**: Deploy a Leave microservice with its own REST API. During transition, the microservice reads/writes the same `LEAVE_*` tables. The Forms `HRMS_LEAVE` continues to work for users who haven't been migrated.
- **Adapters**: Shared-database — no adapter needed. The `LEAVE_BALANCES.AVAILABLE` virtual column (`GENERATED ALWAYS AS …`) ensures consistent balance computation whether accessed from Forms or the new API.
- **Sequencing**: Leave can be strangled **independently** of payroll. The approval workflow (`PENDING_APPROVAL` block) is self-contained. The team calendar view can be a quick early win.
- **Duration**: 6–8 weeks.

#### Big-Bang Rewrite (Spring Boot + React)

- **Scope**: `LeaveController` with endpoints for submit/approve/reject/cancel. React UI with a calendar component (e.g., FullCalendar) for the team calendar view. Balance tracking as a read model.
  ```
  POST   /api/leave/requests         → submit
  PUT    /api/leave/requests/{id}/approve
  PUT    /api/leave/requests/{id}/reject
  GET    /api/leave/balance/{empId}
  GET    /api/leave/team-calendar?dept={id}&month={m}
  ```
- **Testing**: Validate accrual calculations against `LEAVE_ACCRUAL_LOG` historical data. Test all status transitions (PENDING→APPROVED→TAKEN, PENDING→REJECTED, APPROVED→CANCELLED). Verify `LEAVE_BALANCES` arithmetic: `OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING`.
- **Risk**: MEDIUM — business-day calculation bugs (observed holidays) can be fixed during rewrite. The `LEAVE_TYPES` configuration (accrual rates, carryover, min tenure) must be accurately replicated.
- **Duration**: 8–10 weeks.

#### Re-Platform (Oracle APEX)

- **APEX mapping**: `LEAVE_REQUEST` block → Interactive Report + Form page. `NEW_REQUEST` → APEX modal dialog form. `LEAVE_BALANCE` → Classic Report region. `PENDING_APPROVAL` → Interactive Report filtered by `APPROVER_EMP_ID = :APP_USER_EMP_ID`. `TEAM_CAL` → APEX Calendar region using `LEAVE_REQUESTS` as source with `START_DATE`/`END_DATE`.
- **PL/SQL reuse**: ~85% — `submit_leave_request`, `approve_leave_request`, `reject_leave_request`, `cancel_leave_request`, `run_accrual`, `year_end_carryover` can all be called directly from APEX processes. Fix the `calculate_business_days` bug (observed holidays) during migration.
- **APEX constraints**: The APEX Calendar plug-in handles date-range events well. The half-day flag (`HALF_DAY_FLAG`, `HALF_DAY_PERIOD` columns) needs a custom display treatment (AM/PM indicator on the calendar). The `LEAVE_BALANCES.AVAILABLE` virtual column works directly in APEX reports.
- **Duration**: 5–7 weeks.

#### Recommendation

| Approach | Fit (1-5) |
|----------|-----------|
| Strangler Fig | 3 |
| Big-Bang | 3 |
| APEX | **5** |

**Recommended: APEX Re-Platform.** The approval workflow, calendar view, and balance tracking are all first-class APEX components. 85% of `PKG_LEAVE` is reusable. The team calendar maps directly to the APEX Calendar region.

**Prerequisites**: (1) Fix `calculate_business_days` to handle observed holidays by joining the `HOLIDAYS` table with an `OBSERVED_DATE` column (schema change required), (2) Fix half-day overlap detection in `submit_leave_request`.

**Effort**: **M (5–7 person-weeks)**

---

### 3.4 Payroll Processing

**Current State**: `HRMS_PAYROLL.xml` — 4 data blocks (`PAY_PERIOD`, `PAYROLL_RUN`, `PAYROLL_DETAIL`, `PAYSLIP_SUMMARY`), 3 tab pages, 3 LOVs. Requires elevated permissions (`PAYROLL VIEW` check via `PKG_SECURITY.has_permission`). Backend: `PKG_PAYROLL` (897 lines) with `create_pay_periods`, `create_payroll_run`, `calculate_payroll`, `calculate_employee_pay`, `calculate_federal_tax`, `calculate_state_tax`, `approve_payroll_run`, `reverse_payroll_run`. Tables: `PAY_PERIODS`, `PAYROLL_RUNS` (status: PENDING→CALCULATING→CALCULATED→APPROVED→PAID→REVERSED), `PAYROLL_DETAILS`, `TAX_BRACKETS`, `EMPLOYEE_TAX_INFO`, `BANK_ACCOUNTS`, `PAY_ELEMENTS`. Known issues: hard-coded 2024 tax constants (`c_ss_wage_base_2024 := 168600`, `c_ss_rate := 0.062`), cursor-loop processing (should be bulk), partial commits every 50 employees, race condition in pay period creation.

#### Strangler Fig

- **Coexistence**: This is the **hardest module to strangle** due to the transactional nature of payroll runs. A new Payroll Service must either own the full run or defer to the legacy system. Partial coexistence (e.g., new service handles tax calc, old handles pay periods) creates dangerous split-brain scenarios.
- **Adapters**: An event-based adapter where the new service publishes a `PayrollRunCompleted` event and the legacy system reads the results from `PAYROLL_DETAILS` — but this adds complexity with minimal benefit.
- **Sequencing**: Payroll should be strangled **last** among core modules. The risk of financial errors is too high for incremental replacement.
- **Duration**: 14–18 weeks.

#### Big-Bang Rewrite (Spring Boot + React)

- **Scope**: `PayrollService` with proper transactional boundaries (replace the COMMIT-every-50-rows anti-pattern). Extract tax constants to a configuration service backed by the `TAX_BRACKETS` table (which already exists but is bypassed by the hard-coded constants in `PKG_PAYROLL.pkb` lines 6–14). Use Spring Batch for bulk payroll calculation.
- **Architecture**:
  ```
  POST   /api/payroll/periods        → create_pay_periods
  POST   /api/payroll/runs           → create & trigger calculation
  GET    /api/payroll/runs/{id}      → status + summary
  POST   /api/payroll/runs/{id}/approve
  POST   /api/payroll/runs/{id}/reverse
  GET    /api/payroll/payslip/{empId}/{periodId}
  ```
  Key decisions: (1) Spring Batch `ItemReader` → `ItemProcessor` → `ItemWriter` replaces cursor loop, (2) All tax brackets from `TAX_BRACKETS` table (no constants), (3) Proper pessimistic locking for pay period creation.
- **Testing**: Run shadow payroll for 3 pay periods — calculate via both old and new systems, compare `PAYROLL_DETAILS.AMOUNT` for every employee × element. Zero-tolerance for discrepancies.
- **Risk**: HIGH — payroll errors directly affect employee pay. Requires extensive parallel-run validation. Hard-coded tax brackets must be data-driven.
- **Duration**: 16–20 weeks.

#### Re-Platform (Oracle APEX)

- **APEX mapping**: `PAY_PERIOD` → Interactive Report. `PAYROLL_RUN` → Form with status-driven button display (Calculate/Approve/Reverse). `PAYROLL_DETAIL` → Interactive Report with drill-down. `PAYSLIP_SUMMARY` → Classic Report. The APEX UI is straightforward, but the core problem is in `PKG_PAYROLL` — APEX doesn't solve the hard-coded tax brackets, cursor-loop performance, or partial-commit transactional issues.
- **PL/SQL reuse**: ~50% — UI-facing procedures (`create_pay_periods`, `create_payroll_run`, `approve_payroll_run`) can be reused. However, `calculate_payroll` and `calculate_employee_pay` need significant refactoring: (1) replace cursor loop with `BULK COLLECT + FORALL`, (2) read tax rates from `TAX_BRACKETS` table instead of constants, (3) fix the partial-commit anti-pattern.
- **APEX constraints**: APEX can display payroll data effectively, but the calculation engine runs server-side in PL/SQL regardless. APEX doesn't help with the batch-processing architecture. For a payroll system, the backend logic matters more than the UI framework.
- **Duration**: 10–14 weeks (UI: 4 weeks + backend refactoring: 6–10 weeks).

#### Recommendation

| Approach | Fit (1-5) |
|----------|-----------|
| Strangler Fig | 2 |
| Big-Bang | **4** |
| APEX | 3 |

**Recommended: Big-Bang Rewrite.** Payroll is the one area where the PL/SQL backend needs fundamental rearchitecting (data-driven tax brackets, bulk processing, proper transaction management). APEX only solves the UI; a Spring Boot service with Spring Batch provides the right abstractions for batch payroll processing. The circular dependency with `PKG_EMPLOYEE` is cleanly resolved in the service layer.

**Prerequisites**: (1) Populate `TAX_BRACKETS` table with all current federal and state tax brackets (table exists but is bypassed), (2) Document all pay element calculations for parity testing, (3) Set up shadow payroll infrastructure for parallel-run validation, (4) Break circular dependency: new `PayrollService` depends on `EmployeeService`; reverse calls become async events.

**Effort**: **XL (16–20 person-weeks)**

---

### 3.5 Performance Reviews

**Current State**: `HRMS_PERFORMANCE.xml` — 4 data blocks (`REVIEW_CYCLE`, `PERFORMANCE_REVIEW`, `PERFORMANCE_GOAL`, `REVIEW_DETAIL`), 3 tab pages. Backend: `PKG_PERFORMANCE` (320 lines) with `create_review_cycle`, `initiate_reviews`, `submit_self_review`, `submit_manager_review`, `acknowledge_review`, `add_goal`, `update_goal_progress`, `get_team_reviews`, `get_rating_distribution`. Tables: `REVIEW_CYCLES` (status: DRAFT→OPEN→IN_PROGRESS→CALIBRATION→CLOSED), `PERFORMANCE_REVIEWS` (status: NOT_STARTED→SELF_REVIEW→MANAGER_REVIEW→MEETING_SCHEDULED→COMPLETED→ACKNOWLEDGED), `PERFORMANCE_GOALS`. Uses CLOB fields for narrative assessments (`SELF_ASSESSMENT`, `MANAGER_ASSESSMENT`, `STRENGTHS`, `DEVELOPMENT_PLAN`).

#### Strangler Fig

- **Coexistence**: A Performance microservice runs alongside Forms. During review season, users can access either system. Both read/write the same `PERFORMANCE_*` tables. The status machine (NOT_STARTED → … → ACKNOWLEDGED) is enforced in `PKG_PERFORMANCE`, which both systems invoke.
- **Adapters**: Shared-database. The `get_team_reviews` cursor-based output can be exposed as a REST endpoint.
- **Sequencing**: Performance reviews are **seasonally used** (typically Q4 for annual reviews). Can be strangled during off-season with minimal disruption.
- **Duration**: 6–8 weeks.

#### Big-Bang Rewrite (Spring Boot + React)

- **Scope**: `PerformanceController` + React multi-step form wizard for review submission. Rich text editor for CLOB narrative fields. Goal tracking dashboard.
  ```
  POST   /api/reviews/cycles           → create cycle
  POST   /api/reviews/cycles/{id}/initiate
  PUT    /api/reviews/{id}/self-review
  PUT    /api/reviews/{id}/manager-review
  PUT    /api/reviews/{id}/acknowledge
  CRUD   /api/reviews/{id}/goals
  GET    /api/reviews/team?managerId={id}&cycleId={id}
  GET    /api/reviews/distribution?cycleId={id}&deptId={id}
  ```
- **Testing**: Import historical review data from `PERFORMANCE_REVIEWS` and `PERFORMANCE_GOALS`. Verify rating distribution (`get_rating_distribution`) matches for past cycles.
- **Risk**: LOW-MEDIUM — performance reviews are self-contained with no financial impact. The CLOB fields need careful migration (character encoding, formatting preservation).
- **Duration**: 8–12 weeks.

#### Re-Platform (Oracle APEX)

- **APEX mapping**: `REVIEW_CYCLE` → Interactive Report + Form. `PERFORMANCE_REVIEW` → Form with conditional display based on status (show self-assessment fields when `STATUS = 'SELF_REVIEW'`, manager fields when `STATUS = 'MANAGER_REVIEW'`). `PERFORMANCE_GOAL` → Interactive Grid (inline editing for progress updates). `REVIEW_DETAIL` → Classic Report. CLOB fields map to APEX Rich Text Editor items (`CKEDITOR5`).
- **PL/SQL reuse**: ~90% — `PKG_PERFORMANCE` is clean, well-structured code with no major technical debt. All procedures can be called directly from APEX page processes. The rating label CASE expression (Exceptional/Exceeds/Meets/Needs Improvement/Unsatisfactory) works as-is.
- **APEX constraints**: None significant. APEX handles CLOB fields well with Rich Text Editor. The `get_team_reviews` and `get_rating_distribution` ref-cursor functions can back APEX Classic Reports directly.
- **Duration**: 4–6 weeks.

#### Recommendation

| Approach | Fit (1-5) |
|----------|-----------|
| Strangler Fig | 3 |
| Big-Bang | 3 |
| APEX | **5** |

**Recommended: APEX Re-Platform.** `PKG_PERFORMANCE` is the cleanest package in the codebase (320 lines, no circular dependencies, no hard-coded constants, no race conditions). 90% of the PL/SQL is directly reusable. APEX's Rich Text Editor, Interactive Grid, and conditional display are a natural fit.

**Prerequisites**: (1) None blocking — this is the lowest-risk migration area.

**Effort**: **M (4–6 person-weeks)**

---

### 3.6 Reporting

**Current State**: `PKG_REPORTING` (207 lines) exposes 7 reports via ref-cursor procedures: `headcount_report`, `compensation_report`, `turnover_report`, `new_hires_report`, `leave_utilization_report`, `payroll_summary_report`, `eeo_compliance_report`. Also includes `refresh_reporting_tables` for denormalized reporting data (noted as "stale during business hours"). Oracle Reports `.rdf` files for print-formatted output. Supporting views: `VW_ACTIVE_EMPLOYEES`, `VW_ORG_HIERARCHY`, `VW_EMPLOYEE_COMPENSATION`, `VW_LEAVE_SUMMARY`, `VW_PAYROLL_LATEST`. Known issues: hard-coded fiscal year start (Oct 1) in `PKG_REPORTING`, VW_ORG_HIERARCHY degrades with >500 employees due to CONNECT BY.

#### Strangler Fig

- **Coexistence**: Deploy a new reporting UI (React + charting library) that queries the same database views and `PKG_REPORTING` procedures via a thin REST API layer. Legacy Oracle Reports continue to run for users who need PDF/print output.
- **Adapters**: A Spring Boot wrapper that calls `PKG_REPORTING` procedures and returns JSON. The existing views (`VW_ACTIVE_EMPLOYEES`, `VW_EMPLOYEE_COMPENSATION`, etc.) serve both systems.
- **Sequencing**: Reporting is **read-only** — can be strangled at any time without affecting transactional modules. Ideal early candidate for demonstrating migration progress to stakeholders.
- **Duration**: 6–8 weeks.

#### Big-Bang Rewrite (Spring Boot + React)

- **Scope**: `ReportingController` with parameterized endpoints. React dashboard with charts (Recharts/Chart.js) for headcount, compensation, turnover trends. Export to PDF/Excel replaces Oracle Reports.
  ```
  GET /api/reports/headcount?date={d}&deptId={id}
  GET /api/reports/compensation?deptId={id}
  GET /api/reports/turnover?start={d}&end={d}
  GET /api/reports/leave-utilization?year={y}&deptId={id}
  GET /api/reports/payroll-summary?periodId={id}
  GET /api/reports/eeo-compliance?date={d}
  GET /api/reports/org-chart?deptId={id}
  ```
  Replace CONNECT BY org chart with a recursive CTE or materialized path approach for the new org chart component (e.g., D3.js tree visualization).
- **Testing**: Run each report for a given date range, compare output row-by-row against `PKG_REPORTING` cursor results.
- **Risk**: LOW — reporting is read-only. The org chart performance fix (replace CONNECT BY with a materialized adjacency list or CTE) is a net improvement.
- **Duration**: 8–12 weeks.

#### Re-Platform (Oracle APEX)

- **APEX mapping**: Each report procedure → APEX Interactive Report page. APEX provides built-in CSV/PDF/Excel export. Org chart → APEX D3 Tree Chart plug-in. Dashboards → APEX Dashboard page with Chart regions (bar, pie, line). The `refresh_reporting_tables` denormalization can be replaced with APEX's built-in data caching or materialized views refreshed via DBMS_SCHEDULER.
- **PL/SQL reuse**: ~70% — report procedures return `SYS_REFCURSOR`, which APEX Classic Reports can consume, but APEX Interactive Reports work better with inline SQL. Most procedures would be converted to SQL queries embedded in APEX report regions. The `eeo_compliance_report` SQL can be copy-pasted directly.
- **APEX constraints**: APEX's built-in charts are adequate for basic bar/pie/line. For the org chart, a third-party APEX plug-in or custom D3 integration is needed. APEX doesn't natively handle the complex org hierarchy visualization as well as a React D3.js component.
- **Duration**: 6–8 weeks.

#### Recommendation

| Approach | Fit (1-5) |
|----------|-----------|
| Strangler Fig | 4 |
| Big-Bang | **5** |
| APEX | 3 |

**Recommended: Big-Bang Rewrite (React dashboard).** Reporting is where a modern React UI with D3.js/Recharts delivers the most visible user-experience improvement. The org chart needs a proper graph visualization (CONNECT BY is a dead end at scale). Interactive dashboards with drill-down, filtering, and export are React's strength. The backend can call `PKG_REPORTING` procedures directly via a thin Spring Boot layer.

**Prerequisites**: (1) Replace `VW_ORG_HIERARCHY` CONNECT BY with a materialized path or closure-table approach for the org chart, (2) Externalize the hard-coded fiscal year start (Oct 1) to `SYSTEM_PARAMETERS`.

**Effort**: **L (8–12 person-weeks)**

---

### 3.7 Integration

**Current State**: `PKG_INTEGRATION` (213 lines) with 3 integration points:
1. **GL Journal Posting**: `generate_gl_journal()` → UTL_FILE → pipe-delimited flat file to `GL_FEED_OUT` directory → consumed by Oracle Financials batch import.
2. **Benefits Feed**: `export_benefits_feed()` → UTL_FILE → ADP-format fixed-width file to `BENEFITS_FEED_OUT` → consumed by ADP.
3. **Time & Attendance Import**: `import_time_attendance()` → UTL_FILE → reads CSV from `TIME_ATTENDANCE_IN` → updates payroll (NOTE: parsing is a TODO stub — `v_imported` counter increments but no actual database update occurs).

Also: `sync_org_structure()` is a placeholder for LDAP/AD sync. No retry logic on any integration. No API-based integration.

#### Strangler Fig

- **Coexistence**: Replace flat-file integrations one at a time with API-based integrations. New services write to the same output directories initially (backward compatible), then switch downstream consumers to APIs.
- **Adapters**: For GL: expose a REST endpoint that returns JSON-formatted journal entries; run a cron job to also write the pipe-delimited file until Oracle Financials is configured for API consumption. For ADP: use ADP's REST API (ADP Workforce Now APIs) instead of fixed-width files.
- **Sequencing**: Integration can be strangled **independently** and in any order. GL journal is highest priority due to financial compliance requirements. Time & attendance import is a stub — implement it properly in the new system.
- **Duration**: 8–12 weeks.

#### Big-Bang Rewrite (Spring Boot + React)

- **Scope**: `IntegrationService` with Spring Integration or Apache Camel for message routing. Replace all UTL_FILE flat-file I/O with:
  - GL: REST API or SFTP with structured JSON/XML
  - Benefits: ADP REST API (https://developers.adp.com)
  - Time & Attendance: REST API endpoint for time system to push data
  - Org Sync: LDAP/SCIM integration via Spring LDAP
- **Architecture**: Event-driven — payroll completion publishes a `PayrollApproved` event, which triggers GL journal generation and benefits feed export asynchronously.
- **Testing**: Generate flat files with both old and new systems for the same payroll period; diff output files field-by-field.
- **Risk**: MEDIUM — downstream consumers (Oracle Financials, ADP) must be coordinated. ADP format change requires ADP vendor coordination.
- **Duration**: 10–14 weeks.

#### Re-Platform (Oracle APEX)

- **APEX mapping**: APEX doesn't directly improve the integration layer — integrations are backend batch processes, not UI-driven. APEX can provide an "Integration Dashboard" page showing `get_integration_status()` results, last-run timestamps, and error logs. But the core UTL_FILE-based architecture remains.
- **PL/SQL reuse**: ~30% — `generate_gl_journal()` and `export_benefits_feed()` structure is salvageable, but UTL_FILE should be replaced with `APEX_WEB_SERVICE.MAKE_REST_REQUEST` for API-based integrations or `DBMS_CLOUD` for cloud storage. The ADP fixed-width format logic is reusable regardless.
- **APEX constraints**: APEX is a UI framework; it doesn't solve the fundamental integration architecture problem. `UTL_FILE` will still be the mechanism unless refactored to use `UTL_HTTP`/`APEX_WEB_SERVICE` for REST calls.
- **Duration**: 8–10 weeks (mostly backend refactoring; APEX UI is minimal).

#### Recommendation

| Approach | Fit (1-5) |
|----------|-----------|
| Strangler Fig | **5** |
| Big-Bang | 4 |
| APEX | 2 |

**Recommended: Strangler Fig.** Integrations are ideal for incremental replacement: each integration point (GL, Benefits, Time) is independent and can be replaced one at a time. The flat-file outputs can be maintained as a backward-compatible fallback while API-based integrations are built. The time & attendance import is a stub anyway and needs to be built from scratch.

**Prerequisites**: (1) Coordinate with Oracle Financials team for GL API or structured-file format, (2) Obtain ADP API credentials and review ADP Workforce Now API documentation, (3) Identify time & attendance system and its available APIs, (4) Set up a message broker (RabbitMQ/Kafka) or use Spring Integration channels for event-driven orchestration.

**Effort**: **L (10–14 person-weeks)**

---

### 3.8 Navigation Shell

**Current State**: `HRMS_MENU.xml` is the MDI (Multiple Document Interface) parent form with `MAIN_MENUBAR` (7 menus: File, Edit, Query, Navigate, Modules, Admin, Help). The Modules menu launches child forms via `OPEN_FORM('HRMS_EMPLOYEE')`, etc. Menu items are enabled/disabled based on `PKG_SECURITY.has_permission()` checks in `WHEN-NEW-FORM-INSTANCE`. `HRMS_MENU.mmb` is the compiled menu module. The MDI pattern is inherently desktop-like and does not map to modern web navigation.

#### Strangler Fig

- **Coexistence**: Build a new web navigation shell (sidebar + header) that embeds both new components and links to legacy Forms modules. Legacy modules open in an embedded Forms applet or a separate browser tab. This is the **first visible artifact** of the migration — users see the new shell immediately.
- **Adapters**: The new shell needs to read permissions from `PKG_SECURITY.has_permission()` (via REST API) to conditionally show/hide navigation items. A thin `/api/permissions/{empId}` endpoint is needed.
- **Sequencing**: The navigation shell must be built **first or in parallel with auth** as it provides the container for all migrated modules.
- **Duration**: 3–4 weeks.

#### Big-Bang Rewrite (Spring Boot + React)

- **Scope**: React SPA shell with `react-router-dom` routing. Sidebar navigation with module icons. Permission-gated routes. Responsive layout replacing the fixed MDI.
  ```
  /login → HRMS_LOGIN replacement
  /employees → HRMS_EMPLOYEE replacement
  /leave → HRMS_LEAVE replacement
  /payroll → HRMS_PAYROLL replacement
  /performance → HRMS_PERFORMANCE replacement
  /reports → HRMS_REPORTS replacement
  /admin → System Admin
  ```
- **Architecture**: `AppLayout` component with `Sidebar` (permission-filtered links), `Header` (user info, logout), `MainContent` (routed pages). Global state stores current user and permissions.
- **Testing**: Verify all 6 module links render, permission filtering matches legacy behavior (grade ≥ 8 → all visible, grade < 5 → only own profile + leave visible).
- **Risk**: LOW — the navigation shell is the simplest component. No business logic.
- **Duration**: 2–3 weeks.

#### Re-Platform (Oracle APEX)

- **APEX mapping**: APEX applications have a built-in navigation bar (top) and sidebar (Tree or List). The `MAIN_MENUBAR` menus map directly to APEX Navigation Menu entries. Permission checks map to APEX Authorization Schemes (`grade_ge_8`, `grade_ge_5`, etc.). APEX provides a responsive Universal Theme with built-in hamburger menu for mobile.
- **PL/SQL reuse**: 100% — `PKG_SECURITY.has_permission()` is called within APEX Authorization Schemes.
- **APEX constraints**: APEX's navigation model is simpler than the MDI pattern but more appropriate for web. The "File → Save" and "Query → Enter Query" menus are Oracle Forms-specific interactions that don't apply in APEX (APEX has its own Save button and search mechanisms).
- **Duration**: 1–2 weeks (largely automatic with APEX application creation).

#### Recommendation

| Approach | Fit (1-5) |
|----------|-----------|
| Strangler Fig | 3 |
| Big-Bang | 4 |
| APEX | **5** |

**Recommended: APEX Re-Platform.** The navigation shell is essentially free with APEX — creating an APEX application automatically creates a navigation menu. The `MAIN_MENUBAR` structure maps to APEX navigation entries, and `PKG_SECURITY.has_permission()` maps to Authorization Schemes. No custom code needed.

**Prerequisites**: (1) Define APEX Authorization Schemes mirroring the grade-based permission model, (2) Decide on APEX Universal Theme template (Side Navigation vs. Top Navigation).

**Effort**: **S (1–2 person-weeks)**

---

## 4. Summary Recommendation Matrix

Fit rating: 1 = poor fit, 5 = excellent fit.

| Functional Area | Strangler Fig | Big-Bang Rewrite | APEX Re-Platform | **Recommended** | **Effort** |
|----------------|:---:|:---:|:---:|----------------|-----------|
| 3.1 Login / Authentication | 4 | 3 | **5** | APEX | M (3–4 pw) |
| 3.2 Employee Management | 3 | 3 | **5** | APEX | L (8–10 pw) |
| 3.3 Leave Management | 3 | 3 | **5** | APEX | M (5–7 pw) |
| 3.4 Payroll Processing | 2 | **4** | 3 | Big-Bang | XL (16–20 pw) |
| 3.5 Performance Reviews | 3 | 3 | **5** | APEX | M (4–6 pw) |
| 3.6 Reporting | 4 | **5** | 3 | Big-Bang | L (8–12 pw) |
| 3.7 Integration | **5** | 4 | 2 | Strangler Fig | L (10–14 pw) |
| 3.8 Navigation Shell | 3 | 4 | **5** | APEX | S (1–2 pw) |

---

## 5. Recommended Hybrid Approach

The analysis shows no single strategy is optimal across all 8 areas. The recommended hybrid approach assigns each area the best-fit strategy:

### Phase 1: Foundation (Weeks 1–6)
**Strategy: APEX Re-Platform**

| Component | Action | Weeks |
|-----------|--------|-------|
| Navigation Shell | Create APEX application with Universal Theme, define navigation menu + Authorization Schemes from `PKG_SECURITY.has_permission()` | 1–2 |
| Login / Authentication | APEX Custom Authentication calling refactored `PKG_SECURITY.authenticate_v2()` (bcrypt). Migrate `USER_CREDENTIALS` to new hash format. Enable APEX session management, CSRF protection. | 3–4 |
| DB Fixes | Fix RACE-01 (`generate_emp_number` → use `SEQ_EMP_NUMBER`). Consolidate `HRMS_VALIDATION_LIB.pll` logic into `PKG_VALIDATION`. | 5–6 |

**Exit criteria**: Users can log in via APEX, see permission-gated navigation, session management is secure.

### Phase 2: Core CRUD Modules (Weeks 7–22)
**Strategy: APEX Re-Platform**

| Component | Action | Weeks |
|-----------|--------|-------|
| Employee Management | APEX Interactive Grid (master) + tabbed detail regions for Salary, Dependents, Emergency Contacts, History. 8 LOVs as APEX LOV components. Call `PKG_EMPLOYEE` directly. | 7–14 |
| Leave Management | APEX Interactive Report for leave requests, Calendar region for team calendar, modal form for new requests. Call `PKG_LEAVE` directly. Fix `calculate_business_days`. | 15–19 |
| Performance Reviews | APEX form with conditional display by status, Rich Text Editor for CLOBs, Interactive Grid for goals. Call `PKG_PERFORMANCE` directly. | 20–22 |

**Exit criteria**: All CRUD operations work in APEX. Legacy Forms can be decommissioned for these modules.

### Phase 3: Payroll Modernization (Weeks 15–34)
**Strategy: Big-Bang Rewrite (Spring Boot)**

> Runs in parallel with Phase 2, starting at week 15 once Employee Management APEX is stable.

| Component | Action | Weeks |
|-----------|--------|-------|
| Payroll Service | Spring Boot service with Spring Batch for payroll calculation. Data-driven tax brackets from `TAX_BRACKETS` table. Proper transaction management (no partial commits). | 15–26 |
| Payroll UI | APEX pages calling the new `PayrollService` via REST Data Source (APEX can consume REST APIs) OR a React micro-frontend for the payroll module. | 27–30 |
| Shadow Payroll | Parallel-run: calculate payroll with both old and new systems for 3 pay periods. Compare every `PAYROLL_DETAILS.AMOUNT` row. | 31–34 |

**Exit criteria**: Shadow payroll shows 100% parity. Cutover to new payroll engine.

### Phase 4: Reporting Dashboard (Weeks 23–34)
**Strategy: Big-Bang Rewrite (React)**

> Runs in parallel with Phase 3 tail end.

| Component | Action | Weeks |
|-----------|--------|-------|
| Report API | Spring Boot `ReportingController` wrapping `PKG_REPORTING` procedures + new org chart CTE. | 23–26 |
| React Dashboard | Headcount/turnover/compensation charts (Recharts), org chart (D3.js tree), leave utilization, payroll summary. PDF/Excel export. | 27–32 |
| Integration | Embed React dashboard in APEX via iframe or APEX Static File reference. Single sign-on via shared JWT. | 33–34 |

**Exit criteria**: All 7 reports available in the new dashboard. Oracle Reports `.rdf` files can be retired.

### Phase 5: Integration Modernization (Weeks 20–34)
**Strategy: Strangler Fig**

> Runs in parallel with Phases 3–4.

| Component | Action | Weeks |
|-----------|--------|-------|
| GL Journal API | REST endpoint replacing `generate_gl_journal()` UTL_FILE output. Maintain backward-compatible flat file for transition. | 20–24 |
| ADP Benefits API | Integrate with ADP Workforce Now REST API replacing `export_benefits_feed()` fixed-width file. | 25–28 |
| Time & Attendance | Implement the stubbed `import_time_attendance()` as a REST endpoint for time systems to push CSV/JSON. | 29–31 |
| Org Sync | Replace placeholder `sync_org_structure()` with LDAP/SCIM integration via Spring LDAP. | 32–34 |

**Exit criteria**: All integrations API-based. UTL_FILE flat-file flows decommissioned. `import_time_attendance` actually implemented (currently a stub).

### Phase 6: Hardening & Cutover (Weeks 35–38)
- Decommission Oracle Forms and WebLogic
- Remove `HRMS_VALIDATION_LIB.pll` and `HRMS_COMMON_LIB.pll` (logic consolidated server-side)
- Performance testing with 200 concurrent users
- Data migration verification (all `AUDIT_LOG` entries preserved)
- User training on APEX + React dashboard
- DNS cutover from Forms endpoint to APEX + API gateway

---

## 6. Total Effort Estimate

### By Phase

| Phase | Strategy | Duration (weeks) | Effort (person-weeks) |
|-------|----------|:-:|:-:|
| 1. Foundation | APEX | 6 | 6–8 |
| 2. Core CRUD | APEX | 16 | 17–23 |
| 3. Payroll | Big-Bang | 20 | 16–20 |
| 4. Reporting | Big-Bang | 12 | 8–12 |
| 5. Integration | Strangler Fig | 15 | 10–14 |
| 6. Hardening | — | 4 | 5–7 |
| **Total** | **Hybrid** | **38 calendar** | **62–84** |

> **Note**: Phases 3, 4, and 5 run in parallel with Phase 2. Calendar duration with a 5-person team: **~38 weeks (9 months)**. Add 20% contingency for a realistic estimate of **46 weeks (11 months)**.

### By Functional Area

| Area | Effort (person-weeks) |
|------|:---:|
| Login / Authentication | 3–4 |
| Employee Management | 8–10 |
| Leave Management | 5–7 |
| Payroll Processing | 16–20 |
| Performance Reviews | 4–6 |
| Reporting | 8–12 |
| Integration | 10–14 |
| Navigation Shell | 1–2 |
| Hardening / Cutover | 5–7 |
| **Sum (including contingency)** | **76–106** |

### Team Composition (Recommended)

| Role | Count | Focus |
|------|:---:|-------|
| Oracle APEX Developer | 2 | Phases 1–2 (Auth, Employee, Leave, Performance, Nav Shell) |
| Spring Boot Developer | 1 | Phases 3, 5 (Payroll Service, Integration APIs) |
| React/Frontend Developer | 1 | Phase 4 (Reporting Dashboard, Org Chart) |
| QA / Test Engineer | 1 | Shadow payroll, report parity testing, UAT |

---

## 7. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|:---:|:---:|------------|
| Payroll calculation discrepancies during parallel-run | HIGH | CRITICAL | 3-period shadow payroll with zero-tolerance comparison. Automated diff of every `PAYROLL_DETAILS.AMOUNT` row. |
| Data corruption from dual-write during Forms/APEX coexistence | MEDIUM | HIGH | Single database remains source of truth. APEX and Forms both invoke the same `PKG_*` procedures. No dual-write scenario. |
| APEX performance under 200 concurrent users | LOW | MEDIUM | APEX scales well on Oracle 19c. Connection pooling via ORDS. Load test before cutover. |
| ADP API integration delays (vendor coordination) | MEDIUM | MEDIUM | Maintain backward-compatible flat-file export during API development. Coordinate with ADP 3 months before Phase 5. |
| Tax bracket changes during migration (e.g., new tax year) | HIGH | MEDIUM | Move to data-driven `TAX_BRACKETS` table in Phase 3. Add admin UI for annual bracket updates. |
| Loss of Oracle Forms institutional knowledge | MEDIUM | LOW | Document all Forms-specific behaviors (e.g., `MESSAGE` called twice, `TRG_EMP_INSTEAD_OF_DELETE` workaround) before Forms decommission. |
| User resistance to APEX UI (different look and feel) | MEDIUM | MEDIUM | Pilot with HR power users in Phase 2. Universal Theme provides a modern but familiar enterprise look. |

---

## 8. Migration Sequencing Roadmap

```
Week:  1    5    10   15   20   25   30   35   38
       │    │     │    │    │    │    │    │    │
Phase 1 ████▓                                       Foundation (APEX)
Phase 2      ██████████████████▓                     Core CRUD (APEX)
Phase 3                ██████████████████████▓       Payroll (Spring Boot)
Phase 4                          ████████████▓       Reporting (React)
Phase 5                     █████████████████▓       Integration (Strangler)
Phase 6                                    ████▓     Hardening
       │    │     │    │    │    │    │    │    │
       Auth  Emp   Leave  Perf  GL   ADP  T&A  Go-Live
       +Nav  Mgmt  Mgmt   Rev   API  API  API
```

**Key milestones**:
- **Week 6**: APEX login + navigation live → users can see the new system
- **Week 14**: Employee Management in APEX → first module fully migrated
- **Week 22**: Leave + Performance in APEX → majority of daily workflows migrated
- **Week 34**: Payroll shadow-run validated → payroll cutover decision
- **Week 38**: All modules live → Oracle Forms decommissioned
