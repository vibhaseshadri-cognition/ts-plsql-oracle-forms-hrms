# Module Ordering — Safe Migration Sequence

> **Version:** 1.0  
> **Last Updated:** 2026-06-11  
> **Purpose:** Define a safe migration order that respects package dependencies, schema FK constraints, and forms coupling.

---

## 1. Dependency Graph

```
                        ┌──────────────────────────────────────────────────┐
                        │              HRMS_LOGIN (form)                   │
                        │  PKG_SECURITY.authenticate()                    │
                        └──────────────┬───────────────────────────────────┘
                                       │
                        ┌──────────────▼───────────────────────────────────┐
                        │            HRMS_MENU (form)                      │
                        │  PKG_SECURITY.has_permission()                   │
                        │  OPEN_FORM → all child forms                    │
                        └──┬─────────┬──────────┬──────────┬──────────────┘
                           │         │          │          │
              ┌────────────▼──┐  ┌───▼───────┐  │  ┌───────▼────────────┐
              │ HRMS_EMPLOYEE │  │ HRMS_LEAVE│  │  │ HRMS_PERFORMANCE   │
              │ PKG_EMPLOYEE  │  │ PKG_LEAVE │  │  │ PKG_PERFORMANCE    │
              │ VALIDATION_LIB│  └───────────┘  │  └────────────────────┘
              └──────┬────────┘                 │
                     │                ┌─────────▼─────────┐
                     │ CIRCULAR       │  HRMS_PAYROLL     │
                     │◄──────────────►│  PKG_PAYROLL      │
                     │                └─────────┬─────────┘
                     │                          │
              ┌──────▼──────────────────────────▼──────────┐
              │           PKG_REPORTING                     │
              │           PKG_INTEGRATION                   │
              └────────────────────┬───────────────────────┘
                                   │
        ┌──────────────────────────▼────────────────────────────┐
        │                 SHARED SERVICES                        │
        │  PKG_SECURITY    PKG_NOTIFICATION    PKG_VALIDATION   │
        └──────────────────────────┬────────────────────────────┘
                                   │
        ┌──────────────────────────▼────────────────────────────┐
        │                BASE PACKAGES                           │
        │           PKG_COMMON       PKG_AUDIT                  │
        └───────────────────────────────────────────────────────┘
```

### Verified Cross-Package Call Sites

| Caller | Callee | Call Site | Function Called |
|--------|--------|-----------|----------------|
| PKG_EMPLOYEE | PKG_PAYROLL | `PKG_EMPLOYEE.pkb` (create_employee, promote_employee) | `PKG_PAYROLL.create_salary_record()` |
| PKG_EMPLOYEE | PKG_COMMON | `PKG_EMPLOYEE.pkb` (multiple) | `PKG_COMMON.log_error()` |
| PKG_EMPLOYEE | PKG_AUDIT | `PKG_EMPLOYEE.pkb` (multiple) | `PKG_AUDIT.log_action()` |
| PKG_EMPLOYEE | PKG_NOTIFICATION | `PKG_EMPLOYEE.pkb` (terminate, transfer) | `PKG_NOTIFICATION.send_notification()` |
| PKG_SECURITY | PKG_EMPLOYEE | `PKG_SECURITY.pkb:75` | `PKG_EMPLOYEE.set_session_context()` |
| PKG_SECURITY | PKG_COMMON | `PKG_SECURITY.pkb` | (logging) |
| PKG_SECURITY | PKG_AUDIT | `PKG_SECURITY.pkb:77` | `PKG_AUDIT.log_action()` |
| PKG_LEAVE | PKG_EMPLOYEE | `PKG_LEAVE.pkb:86-93` | `EMPLOYEES` table (direct SQL, not package call) |
| PKG_LEAVE | PKG_COMMON | `PKG_LEAVE.pkb` | `PKG_COMMON.log_error()` |
| PKG_LEAVE | PKG_AUDIT | `PKG_LEAVE.pkb` | `PKG_AUDIT.log_action()` |
| PKG_LEAVE | PKG_NOTIFICATION | `PKG_LEAVE.pkb` | `PKG_NOTIFICATION.send_notification()` |
| PKG_PAYROLL | PKG_AUDIT | `PKG_PAYROLL.pkb:57` | `PKG_AUDIT.log_action()` |
| PKG_PAYROLL | PKG_COMMON | `PKG_PAYROLL.pkb` | (logging, params) |
| PKG_PERFORMANCE | PKG_EMPLOYEE | `PKG_PERFORMANCE.pks:6` | declared dep (direct SQL to EMPLOYEES) |
| PKG_REPORTING | PKG_EMPLOYEE | `PKG_REPORTING.pks:7` | declared dep |
| PKG_REPORTING | PKG_PAYROLL | `PKG_REPORTING.pks:7` | declared dep |
| PKG_INTEGRATION | PKG_PAYROLL | `PKG_INTEGRATION.pks:6` | declared dep |
| PKG_INTEGRATION | PKG_EMPLOYEE | `PKG_INTEGRATION.pks:6` | declared dep |
| HRMS_COMMON_LIB | PKG_COMMON | `HRMS_COMMON_LIB.pll.sql:25` | `PKG_COMMON.log_error()` |
| HRMS_COMMON_LIB | PKG_SECURITY | `HRMS_COMMON_LIB.pll.sql:134` | `PKG_SECURITY.is_session_valid()` |

---

## 2. Circular Dependency Resolution

### The Cycle

```
PKG_EMPLOYEE ──calls──► PKG_PAYROLL.create_salary_record()
                             │
PKG_SECURITY ──calls──► PKG_EMPLOYEE.set_session_context()
```

**Note:** Despite the source header claiming `PKG_PAYROLL → PKG_EMPLOYEE`, the actual `PKG_PAYROLL.pkb` body queries the `EMPLOYEES` table directly via SQL rather than calling `PKG_EMPLOYEE` functions. The real dependency is one-directional: `PKG_EMPLOYEE → PKG_PAYROLL`.

### Resolution Options

| Option | Description | Effort | Recommendation |
|--------|-------------|--------|----------------|
| **A: Extract Salary Service** | Move `create_salary_record` and salary queries into a new `SalaryService`, eliminating direct coupling | 2 weeks | ✅ **Recommended** |
| **B: Merge packages** | Combine PKG_EMPLOYEE + PKG_PAYROLL into a monolith | 1 week | ❌ Creates maintenance burden |
| **C: Event-driven** | PKG_EMPLOYEE emits "salary needed" event, PKG_PAYROLL subscribes | 3 weeks | Overkill for this coupling |

**Recommended approach (Option A):**

```
BEFORE:                          AFTER:
PKG_EMPLOYEE ──► PKG_PAYROLL     PKG_EMPLOYEE ──► SalaryService
                                 PKG_PAYROLL  ──► SalaryService
                                 (no circular dependency)
```

Extract `create_salary_record`, `get_current_salary`, `get_salary_as_of` into a standalone `SalaryService` (or `PKG_SALARY`). Both `PKG_EMPLOYEE` and `PKG_PAYROLL` depend on it, but not on each other.

---

## 3. Schema Migration Order

Tables must be created in FK-dependency order:

```
Phase 1 (no FK deps):
  ├── LOCATIONS
  ├── JOB_GRADES
  ├── PAY_ELEMENTS
  ├── PAY_PERIODS
  ├── LEAVE_TYPES
  ├── REVIEW_CYCLES
  ├── AUDIT_LOG
  ├── SYSTEM_PARAMETERS
  ├── HOLIDAYS
  └── LOOKUP_VALUES

Phase 2 (deps on Phase 1):
  ├── DEPARTMENTS          → LOCATIONS (optional FK via MANAGER_EMP_ID deferred)
  ├── JOB_TITLES           → JOB_GRADES
  └── NOTIFICATION_QUEUE   → (standalone)

Phase 3 (deps on Phase 2):
  ├── EMPLOYEES            → DEPARTMENTS, JOB_TITLES, LOCATIONS, EMPLOYEES (self-ref)
  └── USER_SESSIONS        → EMPLOYEES

Phase 4 (deps on Phase 3):
  ├── EMPLOYEE_HISTORY     → EMPLOYEES
  ├── EMPLOYEE_DEPENDENTS  → EMPLOYEES
  ├── EMERGENCY_CONTACTS   → EMPLOYEES
  ├── SALARY_RECORDS       → EMPLOYEES
  ├── EMPLOYEE_PAY_ELEMENTS → EMPLOYEES, PAY_ELEMENTS
  ├── LEAVE_BALANCES       → EMPLOYEES, LEAVE_TYPES
  ├── LEAVE_REQUESTS       → EMPLOYEES, LEAVE_TYPES
  ├── LEAVE_ACCRUAL_LOG    → EMPLOYEES, LEAVE_TYPES
  ├── PAYROLL_RUNS         → PAY_PERIODS
  ├── PERFORMANCE_REVIEWS  → REVIEW_CYCLES, EMPLOYEES
  └── TAX_BRACKETS         → (standalone or Phase 1)

Phase 5 (deps on Phase 4):
  ├── PAYROLL_DETAILS      → PAYROLL_RUNS, EMPLOYEES, PAY_ELEMENTS
  └── PERFORMANCE_GOALS    → PERFORMANCE_REVIEWS, EMPLOYEES

Sequences: All 25 sequences can be created in Phase 0 (no dependencies).

Views (after all tables):
  ├── VW_ACTIVE_EMPLOYEES
  ├── VW_ORG_HIERARCHY
  ├── VW_EMPLOYEE_COMPENSATION
  ├── VW_LEAVE_SUMMARY
  └── VW_PAYROLL_LATEST
```

---

## 4. Migration Wave Plan

### Wave 0: Foundation (Weeks 1–3)

**Scope:** Infrastructure, schema, shared utilities

| Component | Type | Action |
|-----------|------|--------|
| Database schema (all phases) | Tables, sequences, views | Migrate to target DB (PostgreSQL/Oracle) |
| Seed data (01_reference_data, 02_employee_data) | Data | ETL scripts |
| PKG_COMMON | PL/SQL → Java | `CommonService.java` — logging, config, date utils, formatting |
| PKG_AUDIT | PL/SQL → Java | `AuditService.java` — audit trail, change history |

**Prerequisites:** Target infrastructure provisioned (DB, app server, CI/CD)  
**Effort:** 3 person-weeks  
**Validation:** All tables created, seed data loaded, `CommonService` and `AuditService` unit tests pass  
**Coexistence:** No impact — foundation only, no Forms changes yet  

---

### Wave 1: Security & Authentication (Weeks 3–5)

**Scope:** Replace login flow, session management, RBAC

| Component | Type | Action |
|-----------|------|--------|
| PKG_SECURITY | PL/SQL → Java | `SecurityService.java` — JWT auth replacing DB sessions |
| PKG_VALIDATION | PL/SQL → Java | `ValidationService.java` — centralized validation |
| HRMS_LOGIN form | Oracle Form → React | Login page with proper password hashing (bcrypt) |
| HRMS_VALIDATION_LIB | PLL → TypeScript | `validation.ts` — client-side validation utils |
| USER_SESSIONS table | Table | Replace with JWT token store / Redis |

**Prerequisites:** Wave 0 complete  
**Effort:** 3 person-weeks  
**Validation:** Login flow works end-to-end; JWT tokens issued; session expiry tested; RBAC checks pass  
**Coexistence:** New login page → issues JWT → legacy forms accept JWT via adapter  

---

### Wave 2: Notifications & Core Employee (Weeks 5–10)

**Scope:** Employee CRUD — the largest and most interconnected module

| Component | Type | Action |
|-----------|------|--------|
| PKG_NOTIFICATION | PL/SQL → Java | `NotificationService.java` — email/SMS via modern provider |
| SalaryService (new) | Extract from PKG_PAYROLL | Break circular dep; `SalaryService.java` |
| PKG_EMPLOYEE | PL/SQL → Java | `EmployeeService.java` — CRUD, lifecycle, org chart |
| HRMS_EMPLOYEE form | Oracle Form → React | Employee maintenance SPA (4 tabs, master-detail) |
| HRMS_COMMON_LIB | PLL → React hooks | `useToolbar()`, `useErrorHandler()`, `useSession()` |
| HRMS_MENU form | Oracle Form → React | App shell / navigation (sidebar + routes) |
| trg_employees triggers | DB trigger → service logic | Move to `EmployeeService` pre/post hooks |

**Prerequisites:** Wave 1 complete (auth, validation)  
**Effort:** 6 person-weeks  
**Validation:** Full employee CRUD; org chart renders; master-detail for dependents, emergency contacts, salary history; audit trail populated  
**Coexistence:** Strangler pattern — new React Employee module coexists with remaining legacy forms via shared DB  

---

### Wave 3: Leave Management (Weeks 10–14)

| Component | Type | Action |
|-----------|------|--------|
| PKG_LEAVE | PL/SQL → Java | `LeaveService.java` — requests, approvals, accruals, balances |
| HRMS_LEAVE form | Oracle Form → React | Leave management SPA (4 tabs) |
| trg_leave_request_audit | DB trigger → service | Move audit to `LeaveService` |

**Prerequisites:** Wave 2 complete (employee service needed for manager lookups, notifications)  
**Effort:** 4 person-weeks  
**Validation:** Submit/approve/reject/cancel leave; balance tracking; accrual batch job; team calendar  
**Coexistence:** New leave module; legacy payroll still reads LEAVE_REQUESTS table directly  

---

### Wave 4: Payroll Processing (Weeks 14–20)

| Component | Type | Action |
|-----------|------|--------|
| PKG_PAYROLL (remainder) | PL/SQL → Java | `PayrollService.java` — runs, calculations, tax |
| HRMS_PAYROLL form | Oracle Form → React | Payroll processing SPA (3 tabs) |
| trg_salary_audit | DB trigger → service | Move to `SalaryService` |

**Prerequisites:** Wave 2 (SalaryService), Wave 3 (leave data for PTO deductions)  
**Effort:** 6 person-weeks  
**Validation:** Create/calculate/approve payroll run; federal + state tax correct; FICA/Medicare; YTD accumulation  
**Coexistence:** Critical — payroll must not have downtime; run parallel payrolls for 2 cycles before cutover  

---

### Wave 5: Performance Management (Weeks 18–22)

| Component | Type | Action |
|-----------|------|--------|
| PKG_PERFORMANCE | PL/SQL → Java | `PerformanceService.java` — reviews, goals, calibration |
| HRMS_PERFORMANCE form | Oracle Form → React | Performance management SPA (3 tabs) |

**Prerequisites:** Wave 2 (employee service for reviewer lookups)  
**Effort:** 4 person-weeks  
**Validation:** Create cycle, generate reviews, self-assessment, manager review, goal tracking, rating distribution  
**Coexistence:** Can run independently — no tight coupling to payroll cycle  

**Note:** Waves 4 and 5 can run in parallel (different teams).

---

### Wave 6: Reporting & Integration (Weeks 20–26)

| Component | Type | Action |
|-----------|------|--------|
| PKG_REPORTING | PL/SQL → Java | `ReportingService.java` — all 7 report types |
| Oracle Reports (.rdf) | RDF → Modern BI | Replace with embedded analytics (Metabase/Superset) or PDF generation |
| PKG_INTEGRATION | PL/SQL → Java | `IntegrationService.java` — GL, benefits, T&A |
| HRMS_MENU.mmb | Menu module | Decommission (replaced by React shell in Wave 2) |
| VW_* views | DB views | Materialize or replace with API aggregations |

**Prerequisites:** Waves 2–5 complete (all source data services available)  
**Effort:** 6 person-weeks  
**Validation:** All 7 reports produce matching output; GL journal file format matches; benefits feed accepted by ADP; T&A import succeeds  
**Coexistence:** Reports can run against both old and new systems during transition  

---

### Wave 7: Decommission Legacy (Weeks 26–28)

| Task | Description |
|------|-------------|
| Disable Oracle Forms runtime | Stop WebLogic Forms servlet |
| Archive .fmb/.fmx/.pll/.mmb binaries | Move to cold storage |
| Remove dual-write adapters | Point all reads to new system |
| Drop legacy triggers | trg_employees, trg_audit triggers |
| Final data reconciliation | Row-count and checksum comparison |
| Security audit | Penetration test on new system |

**Effort:** 2 person-weeks  
**Validation:** Zero traffic to legacy; all users on new system; no data discrepancies  

---

## 5. Risk Points Between Waves

| Transition | Risk | Mitigation |
|------------|------|------------|
| Wave 0 → 1 | Schema drift during migration | Use Flyway/Liquibase from day 1 |
| Wave 1 → 2 | JWT ↔ legacy session adapter failure | Maintain DB session fallback for 2 sprints |
| Wave 2 → 3 | Employee data referenced by leave module — stale cache | Shared DB ensures consistency; no cache in Wave 3 |
| Wave 3 → 4 | Leave balance data needed by payroll deduction calc | API contract between LeaveService and PayrollService; integration test |
| Wave 4 → 5 | None (independent modules) | N/A |
| Wave 5 → 6 | All services must be stable for reporting queries | Run reporting in read-only mode against replica |
| Wave 6 → 7 | Data reconciliation failures | Automated reconciliation job running daily in Wave 6 |

### Rollback Strategy Per Wave

Each wave uses **feature flags** to enable/disable new modules. If a wave fails:
1. Disable feature flag for new module
2. Re-enable legacy form in HRMS_MENU
3. Investigate and fix in the new system
4. Re-enable after validation

---

## 6. Critical Path Analysis

```
Week:  1   3   5       10      14      20   22      26  28
       │   │   │       │       │       │    │       │   │
W0 ════╡   │   │       │       │       │    │       │   │
       W1 ═╡   │       │       │       │    │       │   │
            W2 ═════════╡       │       │    │       │   │
                        W3 ═════╡       │    │       │   │
                                W4 ═════╡    │       │   │
                        W5 (parallel) ══╡    │       │   │
                                        W6 ══════════╡   │
                                                     W7 ═╡

Critical path: W0 → W1 → W2 → W3 → W4 → W6 → W7 = 28 weeks
                                    └─► W5 (parallel, off critical path)
```

The **critical path** is **28 weeks (~7 months)** with a team of 4–5 developers:

```
W0 (3w) → W1 (2w) → W2 (5w) → W3 (4w) → W4 (6w) → W6 (6w) → W7 (2w) = 28 weeks
                                  └─ W5 (4w, parallel) ─┘
```

**Parallelization opportunity:** Waves 4 and 5 can execute simultaneously, saving 4 weeks if staffed with two sub-teams.

---

## 7. Summary Table

| Wave | Modules | Key Dependencies | Effort | Duration | Risk Level |
|------|---------|-----------------|--------|----------|------------|
| **W0** | Schema, PKG_COMMON, PKG_AUDIT | None | 3 pw | 3 weeks | 🟢 Low |
| **W1** | PKG_SECURITY, PKG_VALIDATION, HRMS_LOGIN, VALIDATION_LIB | W0 | 3 pw | 2 weeks | 🟡 Medium |
| **W2** | PKG_EMPLOYEE, PKG_NOTIFICATION, SalaryService, HRMS_EMPLOYEE, HRMS_MENU, COMMON_LIB | W1 | 6 pw | 5 weeks | 🔴 High |
| **W3** | PKG_LEAVE, HRMS_LEAVE | W2 | 4 pw | 4 weeks | 🟡 Medium |
| **W4** | PKG_PAYROLL, HRMS_PAYROLL | W2, W3 | 6 pw | 6 weeks | 🔴 High |
| **W5** | PKG_PERFORMANCE, HRMS_PERFORMANCE | W2 | 4 pw | 4 weeks | 🟢 Low |
| **W6** | PKG_REPORTING, PKG_INTEGRATION, Oracle Reports | W2–W5 | 6 pw | 6 weeks | 🟡 Medium |
| **W7** | Legacy decommission | W6 | 2 pw | 2 weeks | 🟡 Medium |
| **Total** | | | **34 pw** | **28 weeks** | |
