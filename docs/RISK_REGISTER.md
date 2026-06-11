# Risk Register — Oracle Forms HRMS Migration

> **Version:** 1.0  
> **Last Updated:** 2026-06-11  
> **Owner:** Migration Lead  
> **Review Schedule:** Bi-weekly during active migration; monthly during planning  

---

## Risk Heat Map

```
              │  Low Impact    │  Medium Impact  │  High Impact
 ─────────────┼────────────────┼─────────────────┼──────────────────
  High        │                │  RISK-004       │  RISK-001
  Likelihood  │                │  RISK-006       │  RISK-002
              │                │                 │  RISK-005
 ─────────────┼────────────────┼─────────────────┼──────────────────
  Medium      │  RISK-010      │  RISK-008       │  RISK-003
  Likelihood  │                │  RISK-009       │  RISK-007
 ─────────────┼────────────────┼─────────────────┼──────────────────
  Low         │                │                 │
  Likelihood  │                │                 │
 ─────────────┼────────────────┼─────────────────┼──────────────────
```

---

## Top 10 Forms-Specific Migration Risks

---

### RISK-001: Loss of COMMIT_FORM Transactional Semantics

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-001 |
| **Title** | Loss of COMMIT_FORM implicit transaction management |
| **Category** | Data Integrity |
| **Description** | Oracle Forms' `COMMIT_FORM` built-in provides an implicit transaction boundary that commits ALL pending DML across ALL data blocks in a single database transaction. In `HRMS_EMPLOYEE.xml`, a single user action (clicking Save via `toolbar_save` → `COMMIT_FORM` in `HRMS_COMMON_LIB.pll.sql:46`) atomically commits changes to EMPLOYEES, SALARY_RECORDS, EMPLOYEE_DEPENDENTS, and EMERGENCY_CONTACTS in one round-trip. In a REST/SPA architecture, these become 4 separate API calls (POST/PUT to `/employees`, `/salaries`, `/dependents`, `/contacts`), each with its own transaction. Partial failures leave the database in an inconsistent state. |
| **Likelihood** | **High** — Every form uses `COMMIT_FORM`; the Employee form has 5 data blocks. `HRMS_COMMON_LIB.pll.sql:46` (`toolbar_save`) is called from every form's toolbar. |
| **Impact** | **High** — Partial saves corrupt master-detail relationships. An employee record saved without its salary record breaks payroll; dependents without an employee record orphan benefits enrollment. |
| **Risk Score** | **Critical (H×H)** |
| **Affected Components** | `HRMS_EMPLOYEE.xml` (5 blocks), `HRMS_LEAVE.xml` (NEW_REQUEST block), `HRMS_PAYROLL.xml` (BTN_CREATE_RUN), `HRMS_COMMON_LIB.pll.sql:44-47` |
| **Root Cause** | Oracle Forms runs client-side PL/SQL inside a single DB session; all DML shares one implicit transaction. REST APIs use separate HTTP requests with independent transactions. |
| **Mitigation Strategy** | 1) Implement a **Unit of Work** pattern in the backend: batch related mutations into a single API call (e.g., `POST /employees` accepts employee + salary + dependents as a composite payload). 2) Use database transactions (`@Transactional` in Spring) spanning the entire composite operation. 3) For the React frontend, use optimistic UI with rollback on failure. |
| **Contingency Plan** | Implement a **saga pattern** with compensating transactions; add a reconciliation job that detects orphaned child records nightly. |
| **Owner** | Backend Lead |
| **Status** | Open |

---

### RISK-002: Global Variable Session State Has No Web Equivalent

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-002 |
| **Title** | :GLOBAL.* variables used for cross-form session state |
| **Category** | Functionality |
| **Description** | The application stores session state in Oracle Forms global variables: `:GLOBAL.session_id`, `:GLOBAL.current_user`, `:GLOBAL.current_emp_id`. These are set in `HRMS_LOGIN.xml:82-90` and read by every other form (e.g., `HRMS_EMPLOYEE.xml:34-35`, `HRMS_LEAVE.xml:36`, `HRMS_PAYROLL.xml:27-34`, `HRMS_MENU.xml:22-36`). Globals persist across the Forms session's lifetime and are shared by all open forms via `OPEN_FORM(..., SESSION)`. In a web app, there is no equivalent of a persistent server-side session spanning multiple browser tabs with shared mutable state. |
| **Likelihood** | **High** — Every form references `:GLOBAL.*` variables. 15+ references across 6 forms. The `OPEN_FORM('HRMS_EMPLOYEE', ACTIVATE, SESSION)` pattern in `HRMS_MENU.xml:63,79,91,103,119` explicitly shares the session. |
| **Impact** | **High** — If session context is lost or inconsistent between pages, permission checks fail (user sees "Access denied"), audit trails attribute changes to wrong users, and leave/payroll operations run against wrong employee IDs. |
| **Risk Score** | **Critical (H×H)** |
| **Affected Components** | All 6 forms; `HRMS_COMMON_LIB.pll.sql:114-138` (session helpers); `PKG_SECURITY.pkb:75-77` (session context) |
| **Root Cause** | Oracle Forms' `OPEN_FORM` with `SESSION` parameter shares the database session and all `:GLOBAL.*` variables. Web SPAs are stateless by default; each API call is independent. |
| **Mitigation Strategy** | 1) Replace `:GLOBAL.*` with **JWT claims** (`emp_id`, `username`, `roles`). 2) Store session state in React Context/Redux at the SPA level. 3) Pass user identity via Authorization header on every API call. 4) Use `SecurityContextHolder` (Spring Security) server-side to avoid passing emp_id as a parameter. |
| **Contingency Plan** | Implement a server-side session store (Redis) mirroring Forms globals as a temporary bridge during incremental migration. |
| **Owner** | Full-Stack Lead |
| **Status** | Open |

---

### RISK-003: Master-Detail Auto-Query Synchronization Divergence

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-003 |
| **Title** | Master-detail block synchronization behavior differences |
| **Category** | Functionality |
| **Description** | Oracle Forms' `<Relation>` elements with `AutoQuery="Yes"` automatically re-query detail blocks when the master record changes. In `HRMS_PAYROLL.xml:150-152`, `PERIOD_RUN_REL` syncs `PAYROLL_RUN` to the selected `PAY_PERIOD`. In `HRMS_PERFORMANCE.xml:90-92`, `CYCLE_REVIEW_REL` syncs reviews to cycles, and `:116-118` syncs goals to reviews (3-level cascade). `HRMS_EMPLOYEE.xml` has implicit master-detail for SALARY, DEPENDENTS, EMERGENCY_CONTACTS, and EMP_HISTORY against the EMPLOYEE master. This "automatic coordination" must be explicitly re-implemented in React as cascading API calls triggered by parent selection changes. |
| **Likelihood** | **Medium** — Well-understood pattern, but the 3-level nesting in Performance (Cycle → Review → Goal) and 5-block structure in Employee are complex. |
| **Impact** | **High** — If detail data doesn't refresh when the master changes, users see stale data. In payroll, this means viewing payroll details for the wrong pay period — a financial data integrity issue. |
| **Risk Score** | **High (M×H)** |
| **Affected Components** | `HRMS_PAYROLL.xml:150-152` (PERIOD_RUN_REL), `HRMS_PERFORMANCE.xml:90-92` (CYCLE_REVIEW_REL), `HRMS_PERFORMANCE.xml:116-118` (REVIEW_GOAL_REL), `HRMS_EMPLOYEE.xml` (implicit via block DEFAULT_WHERE) |
| **Root Cause** | Forms' data block coordination is declarative and automatic. React/REST requires explicit imperative code: `useEffect(() => fetchDetails(masterId), [masterId])`. |
| **Mitigation Strategy** | 1) Create a `useMasterDetail` custom React hook that mirrors Forms' relation behavior. 2) Define a `RelationConfig` mapping master→detail blocks with join conditions. 3) Include detail data in master API responses where practical (avoid N+1 queries). 4) Test with automated Playwright scripts comparing old and new behavior. |
| **Contingency Plan** | Implement a "refresh all" button on each page as a manual fallback while auto-sync is being refined. |
| **Owner** | Frontend Lead |
| **Status** | Open |

---

### RISK-004: LOV/Record Group Patterns Don't Map to REST

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-004 |
| **Title** | LOV modal selection pattern has no direct REST equivalent |
| **Category** | User Experience |
| **Description** | Oracle Forms LOVs (List of Values) are modal dialogs populated by Record Group SQL queries. `HRMS_EMPLOYEE.xml` has 8 LOVs (Department, Job Title, Manager, Location, Status, Gender, Marital, Country) populated via `POPULATE_GROUP` at form init (`HRMS_EMPLOYEE.xml:56-58`). `HRMS_LEAVE.xml:193-199` defines `LOV_LEAVE_TYPES` with column mappings that auto-fill multiple form items from a single selection. This "select from modal and populate multiple fields" pattern requires careful recreation — a simple `<select>` dropdown doesn't support multi-column return values or filtering within the LOV. |
| **Likelihood** | **High** — 14 LOVs across all forms. They are a primary data-entry mechanism; users rely on them heavily. |
| **Impact** | **Medium** — Poor LOV replacement degrades UX and slows data entry. Incorrect field mappings from LOV selections corrupt data. |
| **Risk Score** | **High (H×M)** |
| **Affected Components** | `HRMS_EMPLOYEE.xml:56-58` (8 LOVs), `HRMS_LEAVE.xml:193-199` (LOV_LEAVE_TYPES with ColumnMapping), `HRMS_PAYROLL.xml` (3 LOVs) |
| **Root Cause** | Forms LOVs are tightly integrated with Record Groups and item references. They filter, display multi-column results, and populate multiple target items atomically. Web dropdowns/autocompletes are typically single-value. |
| **Mitigation Strategy** | 1) Create a reusable `<SearchableSelect>` React component supporting multi-column display and multi-field return mapping. 2) Implement `/api/lookups/{type}` endpoints returning structured objects (not just id+label). 3) Pre-fetch frequently used LOVs and cache in React Query. 4) For LOVs with 100+ options (like Employee), use server-side search with debounced input. |
| **Contingency Plan** | Fall back to simple dropdowns for small LOVs (<50 items) and modal search dialogs for large ones; refine UX in a later sprint. |
| **Owner** | Frontend Lead |
| **Status** | Open |

---

### RISK-005: Client-Side PL/SQL Trigger Logic Decomposition

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-005 |
| **Title** | PL/SQL form triggers must be split between frontend and backend |
| **Category** | Functionality |
| **Description** | Oracle Forms triggers execute PL/SQL directly on the client (via the Forms runtime). This code runs in the same database session and can freely mix UI operations (`MESSAGE`, `SET_ITEM_PROPERTY`, `GO_ITEM`) with database operations (`SELECT INTO`, `INSERT`, `UPDATE`). Examples: `HRMS_LEAVE.xml:77-89` (cancel button: checks status → calls `PKG_LEAVE.cancel_leave_request` → shows message → re-queries); `HRMS_EMPLOYEE.xml:28-63` (form init: validates session → sets permissions → populates LOVs → executes query). In a web architecture, this logic must be decomposed: UI operations go to React event handlers, DB operations go to REST endpoints, and the coordination between them must be rebuilt. `HRMS_VALIDATION_LIB.pll.sql` has 5 validation functions that are called from WHEN-VALIDATE-ITEM triggers — these must exist in BOTH frontend (for instant feedback) and backend (for security). |
| **Likelihood** | **High** — 30+ triggers across 6 forms. Every button, field validation, and form lifecycle event has a trigger with mixed UI+DB logic. |
| **Impact** | **High** — Incorrect decomposition causes: validation bypasses (security), missing UI feedback (UX), or race conditions between frontend and backend state. |
| **Risk Score** | **Critical (H×H)** |
| **Affected Components** | All form XML files (every `<Trigger>` element); `HRMS_VALIDATION_LIB.pll.sql` (5 validation functions); `HRMS_COMMON_LIB.pll.sql` (toolbar handlers) |
| **Root Cause** | Forms triggers run in a hybrid client-server model where the "client" has direct DB access. Web architecture strictly separates frontend (browser) from backend (API server). |
| **Mitigation Strategy** | 1) Catalog every trigger and classify as: UI-only, DB-only, or mixed. 2) For mixed triggers, extract the DB portion into a service method and the UI portion into a React handler. 3) Use a **trigger mapping spreadsheet** tracking source trigger → target component(s). 4) For validation: implement shared schemas (Zod/Yup) that run in both browser and Node.js backend, or use JSON Schema for cross-platform validation. 5) Prioritize `WHEN-BUTTON-PRESSED` triggers (highest complexity). |
| **Contingency Plan** | During transition, wrap legacy PL/SQL triggers as REST endpoints (thin adapter) to preserve behavior while the decomposition is refined. |
| **Owner** | Full-Stack Lead |
| **Status** | Open |

---

### RISK-006: Forms MDI Window Model vs SPA Routing

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-006 |
| **Title** | MDI multi-window navigation model breaks in SPA architecture |
| **Category** | User Experience |
| **Description** | The HRMS uses Oracle Forms' MDI (Multiple Document Interface) where the menu form (`HRMS_MENU.xml`) is the parent and child forms open inside it via `OPEN_FORM('HRMS_EMPLOYEE', ACTIVATE, SESSION)` (`HRMS_MENU.xml:63`). Users can have multiple modules open simultaneously (e.g., Employee and Payroll forms open side-by-side within the MDI container). `SET_WINDOW_PROPERTY(FORMS_MDI_WINDOW, TITLE, ...)` is used by every form (`HRMS_EMPLOYEE.xml:41-42`, `HRMS_PAYROLL.xml:39-40`) to set the MDI title bar. The `KEY-EXIT` trigger in `HRMS_EMPLOYEE.xml:90-105` handles unsaved-changes prompts per window. SPAs use URL routing — only one "page" is active at a time. |
| **Likelihood** | **High** — Core navigation pattern used by all 6 forms. Users are trained on the MDI model. |
| **Impact** | **Medium** — Users lose multi-form concurrent view. Workflow disruption during transition. No data loss, but significant productivity impact for power users who compare data across modules. |
| **Risk Score** | **High (H×M)** |
| **Affected Components** | `HRMS_MENU.xml:57-136` (6 module launch buttons), `HRMS_MENU.mmb.sql` (menu structure), all forms' `WHEN-NEW-FORM-INSTANCE` triggers |
| **Root Cause** | MDI is a desktop paradigm with no web equivalent. SPA routing replaces windows with URL paths; only one is active. |
| **Mitigation Strategy** | 1) Implement a **tabbed interface** in React (browser tabs or in-app tabs) to approximate MDI behavior. 2) Use React Router with persistent tab state so switching tabs doesn't lose unsaved data. 3) Add an "open in new tab" option for power users who need side-by-side views. 4) Conduct UX workshops with current Forms users to understand their multi-window workflows. |
| **Contingency Plan** | Allow browser multi-tab usage (each module opens in a new browser tab, sharing auth via cookies/localStorage). |
| **Owner** | UX Lead |
| **Status** | Open |

---

### RISK-007: Direct DML in Form Triggers Creates Hidden Data Coupling

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-007 |
| **Title** | SQL DML embedded in form triggers bypasses service layer |
| **Category** | Data Integrity |
| **Description** | Several form triggers contain direct SQL queries that bypass the PL/SQL package API layer. `HRMS_LOGIN.xml:86-90`: `SELECT EMP_ID INTO :GLOBAL.current_emp_id FROM EMPLOYEES` — bypasses `PKG_EMPLOYEE.get_employee()`. `HRMS_LEAVE.xml:97-100`: POST-QUERY joins LEAVE_TYPES and LEAVE_REQUESTS directly. `HRMS_PERFORMANCE.xml:82-83`: POST-QUERY selects from EMPLOYEES. `HRMS_EMPLOYEE.xml:52-53`: `SET_BLOCK_PROPERTY('EMPLOYEE', DEFAULT_WHERE, ...)` embeds SQL WHERE clauses. The `trg_employees.sql:78-97` trigger directly inserts into EMPLOYEE_HISTORY (with wrong column names — `HISTORY_ID`, `CHANGE_DATE`, `OLD_VALUE`, `NEW_VALUE` vs the actual table columns `HIST_ID`, `EFFECTIVE_DATE`, etc.). These hidden data access paths must be discovered and routed through the service layer during migration. |
| **Likelihood** | **Medium** — Discoverable via code search, but easy to miss during migration since they don't appear in package dependency analysis. |
| **Impact** | **High** — Missed direct-DML paths cause data access failures (queries that worked in Forms fail when tables are refactored), or business rules are bypassed (e.g., soft-delete enforcement in triggers not replicated in services). |
| **Risk Score** | **High (M×H)** |
| **Affected Components** | `HRMS_LOGIN.xml:86-90`, `HRMS_LEAVE.xml:94-106`, `HRMS_PERFORMANCE.xml:79-87`, `HRMS_EMPLOYEE.xml:52-53`, `trg_employees.sql:78-97` |
| **Root Cause** | Oracle Forms developers commonly embed SQL in triggers for convenience, creating data access paths invisible to dependency analysis tools. |
| **Mitigation Strategy** | 1) **Audit all form XMLs** for `SELECT`, `INSERT`, `UPDATE`, `DELETE` statements in triggers (regex: `INTO\s+:` for form-level SELECTs). 2) Route every data access through the corresponding service. 3) Fix the `trg_employees.sql:78-97` column name mismatch before migration. 4) Add API-level integration tests that verify all data access goes through services. |
| **Contingency Plan** | Create a database access audit view that logs all direct table access not going through package APIs; run during parallel testing. |
| **Owner** | Backend Lead |
| **Status** | Open |

---

### RISK-008: WHEN-VALIDATE-ITEM Real-Time Validation vs Async API

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-008 |
| **Title** | Synchronous field-level validation replaced by asynchronous API calls |
| **Category** | User Experience |
| **Description** | Oracle Forms' `WHEN-VALIDATE-ITEM` triggers fire synchronously when a user tabs out of a field, providing instant validation feedback. `HRMS_VALIDATION_LIB.pll.sql` implements `validate_email()` (:21-41), `validate_phone()` (:47-63), `validate_ssn()` (:69-90), `validate_salary_range()` (:108-135) — all execute in <1ms since they run in the Forms runtime or via direct DB query. In a web app, field validation either runs in the browser (no server roundtrip) or requires an async API call. The `validate_salary_range()` function queries `JOB_GRADES` — this cannot run purely in the browser. Known validation drift already exists: `HRMS_VALIDATION_LIB.pll.sql:17-19` documents that client-side email validation rejects valid subdomain emails while `PKG_VALIDATION` uses a more permissive regex. |
| **Likelihood** | **Medium** — Standard web validation patterns exist, but replicating the exact UX of instant tabbing validation across 50+ form fields is tedious. |
| **Impact** | **Medium** — Sluggish validation degrades UX (users trained on instant feedback). Validation drift (already present) worsens if client/server rules diverge further. |
| **Risk Score** | **Medium (M×M)** |
| **Affected Components** | `HRMS_VALIDATION_LIB.pll.sql` (5 functions), `PKG_VALIDATION.pks` (8 functions), `HRMS_EMPLOYEE.xml` (field-level triggers) |
| **Root Cause** | Forms validation is synchronous and co-located with the database. Web validation is split: format checks in browser, business rule checks via API. |
| **Mitigation Strategy** | 1) Implement **dual validation**: browser-side (Zod/Yup schemas) for format + range checks; API-side for uniqueness and cross-entity rules. 2) Use `onBlur` handlers (React) to mimic tab-out behavior. 3) Pre-fetch reference data (JOB_GRADES) for salary range validation to avoid API roundtrip. 4) Consolidate all validation rules in one place (eliminate the existing drift) — this is a migration benefit. |
| **Contingency Plan** | Accept slightly delayed validation (200ms API calls) during initial release; optimize with caching in sprint 2. |
| **Owner** | Frontend Lead |
| **Status** | Open |

---

### RISK-009: Forms Error Handling Model Has No Web Equivalent

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-009 |
| **Title** | ON-ERROR trigger and Forms error codes not portable |
| **Category** | Functionality |
| **Description** | Oracle Forms has a unique error handling model: the `ON-ERROR` trigger intercepts all runtime errors with `ERROR_CODE`, `ERROR_TYPE`, and `ERROR_TEXT` built-ins. `HRMS_EMPLOYEE.xml:66-88` suppresses error 40202 ("field protected"), converts 40401 ("no changes") to a friendly message, and converts 40501 ("record locked") to a retry prompt. `HRMS_COMMON_LIB.pll.sql:16-38` (`handle_error`) catches `SQLCODE`/`SQLERRM`, logs to DB via `PKG_COMMON.log_error()`, displays via `MESSAGE()` (called twice per Forms convention, line 33-34), then raises `FORM_TRIGGER_FAILURE`. Additionally, `RAISE FORM_TRIGGER_FAILURE` (used 10+ times across forms) is a Forms-specific mechanism to abort the current operation without an error dialog — it has no equivalent in web frameworks. |
| **Likelihood** | **Medium** — Error handling is well-understood conceptually, but the specific Forms error codes (40202, 40401, 40501) and their behavioral implications need careful mapping. |
| **Impact** | **Medium** — Poor error handling causes: cryptic error messages shown to users, lost error context for debugging, or silent failures that corrupt data. |
| **Risk Score** | **Medium (M×M)** |
| **Affected Components** | `HRMS_EMPLOYEE.xml:66-88` (ON-ERROR), `HRMS_COMMON_LIB.pll.sql:16-38` (handle_error), all forms (FORM_TRIGGER_FAILURE) |
| **Root Cause** | Forms runtime manages a curated set of ~500 internal error codes with defined semantics. Web APIs use HTTP status codes (much coarser) plus application-specific error bodies. |
| **Mitigation Strategy** | 1) Create an **error code mapping table**: Forms error → HTTP status + JSON error body. 2) Implement a centralized `ErrorBoundary` in React and a `@ControllerAdvice` in Spring for consistent error handling. 3) Map `FORM_TRIGGER_FAILURE` to "abort current operation" — in React, this is `throw` in an event handler + state rollback. 4) Replicate the "record locked" retry logic with optimistic locking (ETags/version columns) instead of pessimistic `SELECT FOR UPDATE`. |
| **Contingency Plan** | Log all unmapped Forms errors during parallel testing; create a catch-all error handler that presents a generic message while logging the full context. |
| **Owner** | Full-Stack Lead |
| **Status** | Open |

---

### RISK-010: Oracle Reports (.rdf) Migration Path Uncertainty

| Field | Detail |
|-------|--------|
| **Risk ID** | RISK-010 |
| **Title** | Oracle Reports binary format requires complete rewrite |
| **Category** | Functionality |
| **Description** | The HRMS menu references a Reports module (`HRMS_MENU.mmb.sql:46` "Reports & Analytics", `HRMS_MENU.xml:109-122` BTN_REPORTS). `PKG_REPORTING.pks` defines 7 report types (headcount, compensation, turnover, new hires, leave utilization, payroll summary, EEO compliance). Oracle Reports `.rdf` files are compiled binaries that cannot be directly converted — they must be reverse-engineered from the output format and `PKG_REPORTING` queries. The `VW_*` views (`hrms_views.sql`) serve as data sources for several reports. `PKG_REPORTING.pks:58-60` includes `refresh_reporting_tables` suggesting denormalized reporting tables that are refreshed nightly. |
| **Likelihood** | **Medium** — Reports are well-defined by their output format, but the exact layout, grouping, subtotals, and conditional formatting in `.rdf` files cannot be extracted programmatically. |
| **Impact** | **Low-Medium** — Reports are read-only outputs; they don't affect data integrity. But compliance reports (EEO, payroll summary) have regulatory format requirements that must be exactly preserved. |
| **Risk Score** | **Medium (M×L)** |
| **Affected Components** | `PKG_REPORTING.pks` (7 report procedures), `hrms_views.sql` (5 views), `HRMS_MENU.xml:109-122` (Reports button), referenced `.rdf` files (not in repo) |
| **Root Cause** | Oracle Reports is a proprietary binary format with no open-source converter. The `.rdf` files are not in the repo (only referenced). |
| **Mitigation Strategy** | 1) Inventory all report outputs by running each report in the current system and capturing PDF/HTML samples. 2) Choose a modern reporting tool (JasperReports, Apache POI for Excel, or a BI tool like Metabase/Superset). 3) Rewrite reports using the existing `VW_*` views as data sources. 4) For compliance reports (EEO, payroll), validate output format against regulatory requirements. 5) Reuse `PKG_REPORTING` ref cursor queries as the SQL foundation. |
| **Contingency Plan** | Run Oracle Reports in parallel (keep WebLogic Reports Server running) while new reports are validated. Replace one report at a time. |
| **Owner** | Backend Lead + Compliance Officer |
| **Status** | Open |

---

## Risk Dependencies

```
RISK-001 (COMMIT_FORM) ──────► RISK-007 (Direct DML)
    │                              Partial saves compound with hidden DML paths
    │
    └──► RISK-005 (Trigger Decomposition)
             Mixed UI+DB triggers need correct transaction boundaries

RISK-002 (:GLOBAL.*) ──────► RISK-006 (MDI Navigation)
    │                           Session state shared via MDI window model
    │
    └──► RISK-005 (Trigger Decomposition)
             Triggers read :GLOBAL.* for permission and identity checks

RISK-003 (Master-Detail) ──► RISK-004 (LOV Patterns)
    │                           LOVs often populate master record fields
    │                           that trigger detail re-queries
    │
    └──► RISK-008 (Validation)
             Detail block validation depends on master context

RISK-009 (Error Handling) ──► RISK-001, RISK-005
    Error handling wraps all transaction and trigger operations
```

---

## Mitigation Timeline

| Risk | Pre-Migration (Waves 0–1) | Core Migration (Waves 2–4) | Late Migration (Waves 5–7) |
|------|--------------------------|---------------------------|---------------------------|
| RISK-001 | Design Unit of Work pattern | Implement for Employee, Leave, Payroll | Verify all composite operations |
| RISK-002 | Implement JWT + React Context | Migrate all :GLOBAL.* references | Remove legacy session table |
| RISK-003 | Build `useMasterDetail` hook | Apply to Employee (5-block), Payroll | Verify 3-level cascade (Performance) |
| RISK-004 | Build `SearchableSelect` component | Convert 14 LOVs | UX refinement based on user feedback |
| RISK-005 | Classify all 30+ triggers | Decompose Employee + Leave triggers | Decompose Payroll + Performance |
| RISK-006 | Design tabbed navigation | Implement module tabs | User acceptance testing |
| RISK-007 | Audit all direct DML in forms | Route through services | Remove legacy trigger DML |
| RISK-008 | Define shared validation schemas | Implement for Employee fields | Eliminate validation drift |
| RISK-009 | Design error mapping table | Implement ErrorBoundary + ControllerAdvice | Validate all error paths |
| RISK-010 | Inventory all report outputs | Rewrite headcount + payroll reports | Remaining reports + compliance validation |

---

## Risk Scoring Legend

| Score | Likelihood × Impact | Action Required |
|-------|-------------------|-----------------|
| **Critical** | High × High | Immediate mitigation; blocker for migration start |
| **High** | High × Medium or Medium × High | Mitigation must be in place before affected wave |
| **Medium** | Medium × Medium or High × Low | Plan mitigation; monitor during migration |
| **Low** | Low × any or Medium × Low | Accept risk; address opportunistically |
