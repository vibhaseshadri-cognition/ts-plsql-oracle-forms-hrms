# HRMS Component Mapping: Oracle Forms → Java/Spring + React

> **Purpose:** Exhaustive mapping of every Oracle Forms/PL/SQL element to its modern Java/Spring Boot + React/TypeScript equivalent for the HRMS migration.
>
> **Source codebase:** Oracle Forms 12c (12.2.1.4), Oracle Database 19c, PL/SQL packages, shared libraries (.pll), menu module (.mmb).

---

## Table of Contents

1. [Form-Level Mapping](#1-form-level-mapping)
   - [HRMS_LOGIN](#11-hrms_loginxml)
   - [HRMS_MENU](#12-hrms_menuxml)
   - [HRMS_EMPLOYEE](#13-hrms_employeexml)
   - [HRMS_LEAVE](#14-hrms_leavexml)
   - [HRMS_PAYROLL](#15-hrms_payrollxml)
   - [HRMS_PERFORMANCE](#16-hrms_performancexml)
2. [PL/SQL Library Mapping](#2-plsql-library-mapping)
3. [Menu Module Mapping](#3-menu-module-mapping)
4. [PL/SQL Package → Service Layer Mapping](#4-plsql-package--service-layer-mapping)
5. [Trigger → Middleware/Hook Mapping](#5-trigger--middlewarehook-mapping)
6. [Data Block → API Endpoint Mapping](#6-data-block--api-endpoint-mapping)
7. [LOV → Component Mapping](#7-lov--component-mapping)

---

## 1. Form-Level Mapping

### 1.1 HRMS_LOGIN.xml

| Oracle Forms Element | Type | Java/Spring Equivalent | React Equivalent | Notes |
|---|---|---|---|---|
| FormModule `HRMS_LOGIN` | FormModule | — | `LoginPage` (`/login` route) | Entry point; no menu module attached |
| Trigger `WHEN-NEW-FORM-INSTANCE` | Form-level trigger | — | `useEffect` on mount: set document title, focus username input | Sets MDI window title, navigates cursor to `LOGIN.USERNAME` |
| Block `LOGIN` | Control block (QueryDataSourceType=None) | `AuthController.login()` | `LoginForm` component (React Hook Form) | No DB source; InsertAllowed/UpdateAllowed/DeleteAllowed=No |
| Item `COMPANY_LOGO` | Image | — | `<img src="/assets/logo.gif" />` | Static asset, GIF format, 200×60 |
| Item `USERNAME` | Text Field (Char, required, maxlen 100) | `LoginRequest.username` (validated `@NotBlank`) | `<input type="text" name="username" required maxLength={100} />` | Prompt: "Username:" |
| Item `PASSWORD` | Text Field (Char, required, maxlen 100, ConcealData=Yes) | `LoginRequest.password` (validated `@NotBlank`) | `<input type="password" name="password" required maxLength={100} />` | Prompt: "Password:"; ConcealData maps to password input type |
| Item `ERROR_MSG` | Display Item (Char, maxlen 200) | — | `{error && <p className="text-red-500 font-bold">{error}</p>}` | Red, bold error text; populated on auth failure |
| Item `BTN_LOGIN` | Push Button (label "Login") | — | `<button type="submit">Login</button>` | Triggers authentication flow |
| Trigger `WHEN-BUTTON-PRESSED` (BTN_LOGIN) | Button trigger | `AuthController.login()` → `SecurityService.authenticate()` | `onSubmit` handler: calls `POST /api/auth/login`, stores session/JWT in context, redirects to `/dashboard` | Calls `PKG_SECURITY.authenticate`, stores session_id/user/emp_id in globals, opens `HRMS_MENU` |
| Trigger `KEY-NEXT-ITEM` | Block-level trigger | — | `onKeyDown` handler on password field: if Enter, submit form | When cursor on PASSWORD and Tab/Enter pressed, triggers login |
| Canvas `CVS_LOGIN` | Content canvas (700×300, white bg) | — | `LoginPage` container `<div>` with white background, centered layout | Single content canvas |
| Window `WIN_LOGIN` | Dialog window (700×320, non-resizable, non-closeable) | — | Fixed-size centered modal/card, no close button | WindowStyle=Dialog; MoveAllowed=Yes, ResizeAllowed=No |

### 1.2 HRMS_MENU.xml

| Oracle Forms Element | Type | Java/Spring Equivalent | React Equivalent | Notes |
|---|---|---|---|---|
| FormModule `HRMS_MENU` | FormModule (MDI shell) | — | `DashboardLayout` (`/dashboard` route, wraps child routes) | MDI parent; MenuModule=MENU_MAIN; serves as app shell |
| AttachedLibrary `HRMS_COMMON_LIB` | Attached library | Shared utility classes imported | `import { ... } from '@/utils/common'` | Toolbar handlers, error handling, session helpers |
| Trigger `WHEN-NEW-FORM-INSTANCE` | Form-level trigger | Spring Security filter chain (permission checks on init) | `useEffect` on mount: set page title with username/session, conditionally disable nav items based on permissions from `useAuth()` | Sets MDI title, disables menu items based on `PKG_SECURITY.has_permission` |
| Block `MENU_CONTROL` | Control block (QueryDataSourceType=None) | — | Dashboard home component with navigation cards | No DB source; display-only with navigation buttons |
| Item `WELCOME_TEXT` | Display Item (Char, font 14 bold) | — | `<h1>Welcome to the Human Resource Management System</h1>` | DefaultValue static text |
| Item `USER_INFO` | Display Item (Char) | — | `<p>{currentUser.name} - Session active</p>` | Populated at runtime with user info |
| Item `BTN_EMPLOYEES` | Push Button (label "Employee Management", 200×60) | — | `<NavCard to="/employees" icon={UsersIcon}>Employee Management</NavCard>` | `OPEN_FORM('HRMS_EMPLOYEE', ACTIVATE, SESSION)` → React Router navigation |
| Item `BTN_PAYROLL` | Push Button (label "Payroll Processing", 200×60) | — | `<NavCard to="/payroll" icon={DollarIcon} disabled={!can('PAYROLL','VIEW')}>Payroll Processing</NavCard>` | Permission-gated: checks `PKG_SECURITY.has_permission` before opening |
| Item `BTN_LEAVE` | Push Button (label "Leave Management", 200×60) | — | `<NavCard to="/leave" icon={CalendarIcon}>Leave Management</NavCard>` | Opens HRMS_LEAVE |
| Item `BTN_PERFORMANCE` | Push Button (label "Performance Reviews", 200×60) | — | `<NavCard to="/performance" icon={ChartIcon}>Performance Reviews</NavCard>` | Opens HRMS_PERFORMANCE |
| Item `BTN_REPORTS` | Push Button (label "Reports & Analytics", 200×60) | — | `<NavCard to="/reports" icon={BarChartIcon} disabled={!can('REPORTS','VIEW')}>Reports & Analytics</NavCard>` | Permission-gated |
| Item `BTN_LOGOUT` | Push Button (label "Logout", 200×60) | — | `<button onClick={logout}>Logout</button>` | Calls `PKG_SECURITY.logout` then `EXIT_FORM` → `POST /api/auth/logout` then redirect to `/login` |
| Canvas `CVS_MAIN` | Content canvas (740×400) | — | Dashboard page layout container | Single content canvas for dashboard |
| Window `WIN_MAIN` | Document window (760×420) | — | Main application window/viewport | WindowStyle=Document |
| MenuModule `MENU_MAIN` | Inline menu module | — | `<AppMenuBar>` component (see Section 3) | Contains FILE, MODULES, ADMIN, HELP menus |
| Menu `FILE_MENU` | Menu ("File") | — | File dropdown in top navigation | Contains Logout |
| MenuItem `MI_LOGOUT` | MenuItem (PL/SQL) | `POST /api/auth/logout` | `onClick={() => { logout(); navigate('/login'); }}` | `PKG_SECURITY.logout` + `EXIT_FORM` |
| Menu `MODULES_MENU` | Menu ("Modules") | — | Modules dropdown / sidebar nav | Navigation to all sub-modules |
| MenuItem `MI_EMPLOYEES` | MenuItem (PL/SQL) | — | `<Link to="/employees">Employee Management</Link>` | `OPEN_FORM('HRMS_EMPLOYEE')` |
| MenuItem `MI_PAYROLL` | MenuItem (PL/SQL) | — | `<Link to="/payroll">Payroll Processing</Link>` | `OPEN_FORM('HRMS_PAYROLL')` |
| MenuItem `MI_LEAVE` | MenuItem (PL/SQL) | — | `<Link to="/leave">Leave Management</Link>` | `OPEN_FORM('HRMS_LEAVE')` |
| MenuItem `MI_PERFORMANCE` | MenuItem (PL/SQL) | — | `<Link to="/performance">Performance Reviews</Link>` | `OPEN_FORM('HRMS_PERFORMANCE')` |
| MenuItem `MI_REPORTS` | MenuItem (PL/SQL) | — | `<Link to="/reports">Reports</Link>` | `OPEN_FORM('HRMS_REPORTS')` |
| Menu `ADMIN_MENU` | Menu ("Admin") | — | Admin dropdown (permission-gated) | Disabled if user lacks ADMIN permission |
| MenuItem `MI_ADMIN` | MenuItem (PL/SQL) | — | `<Link to="/admin">System Administration</Link>` | `OPEN_FORM('HRMS_ADMIN')` |
| MenuItem `MI_CHANGE_PWD` | MenuItem (PL/SQL) | — | `<button onClick={openChangePasswordModal}>Change Password</button>` | `SHOW_WINDOW('WIN_CHANGE_PWD')` → modal dialog |
| Menu `HELP_MENU` | Menu ("Help") | — | Help dropdown | Contains About |
| MenuItem `MI_ABOUT` | MenuItem (PL/SQL) | — | `<AboutDialog>` showing version string | `MESSAGE('HRMS v4.2 - Build 2024.03.15')` |

### 1.3 HRMS_EMPLOYEE.xml

| Oracle Forms Element | Type | Java/Spring Equivalent | React Equivalent | Notes |
|---|---|---|---|---|
| FormModule `HRMS_EMPLOYEE` | FormModule | — | `EmployeePage` (`/employees` and `/employees/:id` routes) | 5 blocks, 4 tabs, 8 LOVs, 2 alerts; MenuModule=HRMS_MENU |
| AttachedLibrary `HRMS_COMMON_LIB` | Attached library | Shared utility classes | `import { ... } from '@/utils/common'` | Toolbar handlers, error handling |
| AttachedLibrary `HRMS_VALIDATION_LIB` | Attached library | `ValidationService` | `import { validateEmail, validatePhone, validateSSN, ... } from '@/utils/validation'` | Client-side validation functions |
| Trigger `WHEN-NEW-FORM-INSTANCE` | Form-level trigger | Spring Security `@PreAuthorize` | `useEffect` on mount: validate session, set title, check EMPLOYEE EDIT permission, set default query filter, populate LOV data, execute initial query | Session validation via `PKG_SECURITY.is_session_valid`; restricts insert/update/delete based on permission; default WHERE `EMPLOYMENT_STATUS='ACTIVE'` |
| Trigger `ON-ERROR` | Form-level trigger | `@ControllerAdvice` / `GlobalExceptionHandler` | Global error boundary + toast notification system | Suppresses error 40202 (protected field), customizes 40401 (no changes), 40501 (record locked) |
| Trigger `KEY-EXIT` | Form-level trigger | — | `useBeforeUnload` hook + unsaved changes dialog | If form changed: show `ALT_CONFIRM_EXIT` alert (Save/Discard/Cancel) |
| **Block `EMPLOYEE`** | Data block (Table: `HRMS.EMPLOYEES`) | `EmployeeController` + `EmployeeService` | `EmployeeForm` component | QueryDataSourceType=Table; full CRUD; KeyMode=Unique; EnforcePrimaryKey=Yes |
| Item `EMP_ID` | Text Field (Number, PK, hidden) | `Employee.empId` (Long) | Hidden field in form state | PrimaryKey=Yes; InsertAllowed/UpdateAllowed=No; auto-generated via `SEQ_EMPLOYEE.NEXTVAL` |
| Item `EMP_NUMBER` | Text Field (Char, maxlen 20, readonly) | `Employee.empNumber` (String) | `<input readOnly value={empNumber} />` | Generated by `PKG_EMPLOYEE.generate_emp_number`; InsertAllowed/UpdateAllowed=No |
| Item `FIRST_NAME` | Text Field (Char, maxlen 50, required, Upper) | `Employee.firstName` (String, `@NotBlank`, `@Size(max=50)`) | `<input name="firstName" required maxLength={50} style={{textTransform:'uppercase'}} />` | CaseRestriction=Upper |
| Item `LAST_NAME` | Text Field (Char, maxlen 50, required, Upper) | `Employee.lastName` (String, `@NotBlank`, `@Size(max=50)`) | `<input name="lastName" required maxLength={50} style={{textTransform:'uppercase'}} />` | CaseRestriction=Upper |
| Item `DATE_OF_BIRTH` | Text Field (Date, MM/DD/YYYY) | `Employee.dateOfBirth` (LocalDate) | `<DatePicker name="dateOfBirth" format="MM/DD/YYYY" />` | FormatMask=MM/DD/YYYY |
| Item `GENDER` | List Item (Char, Poplist: M/F/O) | `Employee.gender` (String, enum) | `<Select name="gender" options={[{label:'Male',value:'M'},{label:'Female',value:'F'},{label:'Other',value:'O'}]} />` | ListStyle=Poplist |
| Item `MARITAL_STATUS` | List Item (Char, Poplist: SINGLE/MARRIED/DIVORCED/WIDOWED) | `Employee.maritalStatus` (String, enum) | `<Select name="maritalStatus" options={[...]} />` | ListStyle=Poplist |
| Item `EMAIL` | Text Field (Char, maxlen 100, Lower) | `Employee.email` (String, `@Email`, `@Size(max=100)`) | `<input name="email" type="email" maxLength={100} style={{textTransform:'lowercase'}} />` | CaseRestriction=Lower; validated by `PKG_VALIDATION.validate_email_format` in WHEN-VALIDATE-ITEM |
| Item `PHONE_WORK` | Text Field (Char, maxlen 30) | `Employee.phoneWork` (String) | `<input name="phoneWork" maxLength={30} />` | Prompt: "Work Phone:" |
| Item `PHONE_MOBILE` | Text Field (Char, maxlen 30) | `Employee.phoneMobile` (String) | `<input name="phoneMobile" maxLength={30} />` | Prompt: "Mobile:" |
| Item `ADDRESS_LINE1` | Text Field (Char, maxlen 200) | `Employee.addressLine1` (String) | `<input name="addressLine1" maxLength={200} />` | Tab: Personal |
| Item `ADDRESS_LINE2` | Text Field (Char, maxlen 200) | `Employee.addressLine2` (String) | `<input name="addressLine2" maxLength={200} />` | Tab: Personal |
| Item `CITY` | Text Field (Char, maxlen 100) | `Employee.city` (String) | `<input name="city" maxLength={100} />` | Tab: Personal |
| Item `STATE_PROVINCE` | Text Field (Char, maxlen 100) | `Employee.stateProvince` (String) | `<input name="stateProvince" maxLength={100} />` | Tab: Personal |
| Item `POSTAL_CODE` | Text Field (Char, maxlen 20) | `Employee.postalCode` (String) | `<input name="postalCode" maxLength={20} />` | Tab: Personal |
| Item `HIRE_DATE` | Text Field (Date, required, MM/DD/YYYY) | `Employee.hireDate` (LocalDate, `@NotNull`) | `<DatePicker name="hireDate" required format="MM/DD/YYYY" />` | Tab: Job; validated in WHEN-VALIDATE-ITEM (max 90 days future) |
| Item `DEPT_ID` | Text Field (Number, required, LOV) | `Employee.deptId` (Long, `@NotNull`) | `<DepartmentAutocomplete name="deptId" />` | LOV=LOV_DEPARTMENTS; auto-populates DEPT_NAME_DISP |
| Item `DEPT_NAME_DISP` | Display Item (Char, non-DB) | — | Display-only span next to dept selector | Populated via POST-QUERY and WHEN-VALIDATE-ITEM |
| Item `JOB_ID` | Text Field (Number, required, LOV) | `Employee.jobId` (Long, `@NotNull`) | `<JobTitleAutocomplete name="jobId" />` | LOV=LOV_JOB_TITLES; auto-populates JOB_TITLE_DISP |
| Item `JOB_TITLE_DISP` | Display Item (Char, non-DB) | — | Display-only span next to job selector | Populated via POST-QUERY and WHEN-VALIDATE-ITEM |
| Item `MANAGER_EMP_ID` | Text Field (Number, LOV) | `Employee.managerEmpId` (Long) | `<ManagerAutocomplete name="managerEmpId" />` | LOV=LOV_MANAGERS; auto-populates MANAGER_NAME_DISP |
| Item `MANAGER_NAME_DISP` | Display Item (Char, non-DB) | — | Display-only span next to manager selector | Populated via POST-QUERY |
| Item `LOCATION_CODE` | Text Field (Char, maxlen 10, LOV) | `Employee.locationCode` (String) | `<LocationAutocomplete name="locationCode" />` | LOV=LOV_LOCATIONS |
| Item `EMPLOYMENT_TYPE` | List Item (Char, Poplist: FULL_TIME/PART_TIME/CONTRACT/INTERN) | `Employee.employmentType` (String, enum) | `<Select name="employmentType" options={[...]} />` | Tab: Job |
| Item `EMPLOYMENT_STATUS` | List Item (Char, Poplist: ACTIVE/ON_LEAVE/SUSPENDED/TERMINATED, readonly) | `Employee.employmentStatus` (String, enum) | `<Select name="employmentStatus" disabled options={[...]} />` | UpdateAllowed=No; changed only via lifecycle procedures |
| Item `TERMINATION_DATE` | Text Field (Date, readonly) | `Employee.terminationDate` (LocalDate) | `<DatePicker name="terminationDate" disabled />` | UpdateAllowed=No |
| Item `ACTIVE_FLAG` | Text Field (Char, hidden) | `Employee.activeFlag` (String) | Not rendered; maintained server-side | Audit column |
| Item `CREATED_BY` | Text Field (Char, hidden) | `Employee.createdBy` (String) | Not rendered; set server-side | Audit column; InsertAllowed=Yes, UpdateAllowed=No |
| Item `CREATED_DATE` | Text Field (Date, hidden) | `Employee.createdDate` (LocalDateTime) | Not rendered; set server-side | Audit column; InsertAllowed=Yes, UpdateAllowed=No |
| Item `MODIFIED_BY` | Text Field (Char, hidden) | `Employee.modifiedBy` (String) | Not rendered; set server-side | Audit column |
| Item `MODIFIED_DATE` | Text Field (Date, hidden) | `Employee.modifiedDate` (LocalDateTime) | Not rendered; set server-side | Audit column |
| Trigger `PRE-INSERT` (EMPLOYEE) | Block trigger | `@PrePersist` JPA callback / `EmployeeService.create()` | — (server-side) | Sets EMP_ID from sequence, generates EMP_NUMBER, sets ACTIVE_FLAG='Y', STATUS='ACTIVE', audit cols |
| Trigger `PRE-UPDATE` (EMPLOYEE) | Block trigger | `@PreUpdate` JPA callback / `EmployeeService.update()` | — (server-side) | Sets MODIFIED_BY, MODIFIED_DATE |
| Trigger `POST-QUERY` (EMPLOYEE) | Block trigger | JPA `@PostLoad` or DTO projection with joins | `useQuery` populates display fields from joined data | Populates DEPT_NAME_DISP, JOB_TITLE_DISP, MANAGER_NAME_DISP via SELECT lookups |
| Trigger `WHEN-VALIDATE-ITEM` (EMPLOYEE) | Block trigger | `@Valid` Bean Validation + custom validators | `onChange` / `onBlur` validators per field: Zod schema validation | Validates EMAIL format, HIRE_DATE range, auto-populates DEPT_NAME/JOB_TITLE on change |
| **Block `SALARY`** | Data block (Table: `HRMS.SALARY_RECORDS`) | `SalaryController` + `SalaryService` | `SalaryHistoryTable` component (read-only grid) | Detail of EMPLOYEE; RecordsDisplayed=5; InsertAllowed/UpdateAllowed/DeleteAllowed=No |
| Item `SALARY_ID` | Hidden PK | `SalaryRecord.salaryId` (Long) | Hidden | PrimaryKey |
| Item `EMP_ID` | Hidden FK | `SalaryRecord.empId` (Long) | Hidden | FK to EMPLOYEE |
| Item `EFFECTIVE_DATE` | Text Field (Date, MM/DD/YYYY, readonly) | `SalaryRecord.effectiveDate` (LocalDate) | `<td>{formatDate(row.effectiveDate)}</td>` | Read-only column |
| Item `END_DATE` | Text Field (Date, MM/DD/YYYY) | `SalaryRecord.endDate` (LocalDate) | `<td>{formatDate(row.endDate)}</td>` | |
| Item `BASE_SALARY` | Text Field (Number, $999,999,990.00) | `SalaryRecord.baseSalary` (BigDecimal) | `<td>{formatCurrency(row.baseSalary)}</td>` | FormatMask maps to Intl.NumberFormat |
| Item `CHANGE_REASON` | Text Field (Char) | `SalaryRecord.changeReason` (String) | `<td>{row.changeReason}</td>` | |
| Item `CHANGE_PCT` | Text Field (Number, 990.00%) | `SalaryRecord.changePct` (BigDecimal) | `<td>{row.changePct}%</td>` | |
| Relation `EMP_SALARY_REL` | Master-detail relation | `@OneToMany` on Employee entity / `GET /api/employees/{id}/salary-history` | `useQuery(['salary', empId])` triggered on employee selection | JoinCondition: `SALARY.EMP_ID = EMPLOYEE.EMP_ID`; AutoQuery=Yes; DeleteRecordBehavior=Cascading |
| **Block `DEPENDENTS`** | Data block (Table: `HRMS.EMPLOYEE_DEPENDENTS`) | `DependentController` + `DependentService` | `DependentsTable` component (editable grid) | Detail of EMPLOYEE; Tab: Dependents |
| Item `DEPENDENT_ID` | Hidden PK | `Dependent.dependentId` (Long) | Hidden | PrimaryKey; auto-generated via SEQ_DEPENDENT |
| Item `EMP_ID` | Hidden FK | `Dependent.empId` (Long) | Hidden | FK to EMPLOYEE |
| Item `FIRST_NAME` | Text Field (Char, maxlen 50) | `Dependent.firstName` (String) | `<input name="firstName" maxLength={50} />` | |
| Item `LAST_NAME` | Text Field (Char, maxlen 50) | `Dependent.lastName` (String) | `<input name="lastName" maxLength={50} />` | |
| Item `RELATIONSHIP` | List Item (Poplist: SPOUSE/CHILD/PARENT/DOMESTIC_PARTNER/OTHER) | `Dependent.relationship` (String, enum) | `<Select name="relationship" options={[...]} />` | Schema constraint CHK_RELATIONSHIP |
| Item `DATE_OF_BIRTH` | Text Field (Date) | `Dependent.dateOfBirth` (LocalDate) | `<DatePicker name="dateOfBirth" />` | |
| Item `BENEFITS_ENROLLED` | Check Box (Y/N) | `Dependent.benefitsEnrolled` (String) | `<Checkbox name="benefitsEnrolled" />` | Default 'N' |
| **Block `EMERGENCY_CONTACTS`** | Data block (Table: `HRMS.EMERGENCY_CONTACTS`) | `EmergencyContactController` + `EmergencyContactService` | `EmergencyContactsTable` component (editable grid) | Detail of EMPLOYEE; Tab: Personal or Dependents |
| Item `CONTACT_ID` | Hidden PK | `EmergencyContact.contactId` (Long) | Hidden | PrimaryKey; auto-generated via SEQ_EMERGENCY_CONTACT |
| Item `EMP_ID` | Hidden FK | `EmergencyContact.empId` (Long) | Hidden | FK to EMPLOYEE |
| Item `CONTACT_NAME` | Text Field (Char, maxlen 100) | `EmergencyContact.contactName` (String, `@NotBlank`) | `<input name="contactName" required maxLength={100} />` | |
| Item `RELATIONSHIP` | Text Field (Char, maxlen 30) | `EmergencyContact.relationship` (String) | `<input name="relationship" maxLength={30} />` | |
| Item `PHONE_PRIMARY` | Text Field (Char, maxlen 30) | `EmergencyContact.phonePrimary` (String, `@NotBlank`) | `<input name="phonePrimary" required maxLength={30} />` | |
| Item `PHONE_SECONDARY` | Text Field (Char, maxlen 30) | `EmergencyContact.phoneSecondary` (String) | `<input name="phoneSecondary" maxLength={30} />` | |
| Item `EMAIL` | Text Field (Char, maxlen 100) | `EmergencyContact.email` (String) | `<input name="email" type="email" maxLength={100} />` | |
| Item `PRIORITY_ORDER` | Text Field (Number) | `EmergencyContact.priorityOrder` (Integer) | `<input name="priorityOrder" type="number" />` | Default 1 |
| **Block `EMP_HISTORY`** | Data block (Table: `HRMS.EMPLOYEE_HISTORY`) | `EmployeeHistoryController` | `EmploymentHistoryTimeline` component (read-only) | Detail of EMPLOYEE; Tab: History |
| Item `HIST_ID` | Hidden PK | `EmployeeHistory.histId` (Long) | Hidden | PrimaryKey |
| Item `EMP_ID` | Hidden FK | `EmployeeHistory.empId` (Long) | Hidden | FK to EMPLOYEE |
| Item `CHANGE_TYPE` | Display Item (Char) | `EmployeeHistory.changeType` (String) | `<Badge>{row.changeType}</Badge>` | HIRE, TRANSFER, PROMOTION, DEMOTION, SALARY_CHANGE, TERMINATION, REHIRE, etc. |
| Item `EFFECTIVE_DATE` | Display Item (Date) | `EmployeeHistory.effectiveDate` (LocalDate) | `<td>{formatDate(row.effectiveDate)}</td>` | |
| Item `COMMENTS` | Display Item (Char) | `EmployeeHistory.comments` (String) | `<td>{row.comments}</td>` | |
| LOV `LOV_DEPARTMENTS` | LOV (400×300) | `GET /api/lookups/departments` | `<DepartmentAutocomplete>` with async fetch | Query: `SELECT DEPT_ID, DEPT_CODE, DEPT_NAME, COST_CENTER FROM DEPARTMENTS WHERE ACTIVE_FLAG='Y'`; Returns: DEPT_ID→EMPLOYEE.DEPT_ID, DEPT_NAME→EMPLOYEE.DEPT_NAME_DISP |
| LOV `LOV_JOB_TITLES` | LOV (450×300) | `GET /api/lookups/job-titles` | `<JobTitleAutocomplete>` with async fetch | Query: `SELECT JOB_ID, JOB_CODE, JOB_TITLE, GRADE_NAME FROM JOB_TITLES j JOIN JOB_GRADES g ...`; Returns: JOB_ID→EMPLOYEE.JOB_ID, JOB_TITLE→EMPLOYEE.JOB_TITLE_DISP |
| LOV `LOV_MANAGERS` | LOV (400×300) | `GET /api/lookups/managers` | `<ManagerAutocomplete>` with async fetch | Query: `SELECT EMP_ID, EMP_NUMBER, FIRST_NAME||' '||LAST_NAME FROM EMPLOYEES WHERE STATUS='ACTIVE'`; Returns: EMP_ID→EMPLOYEE.MANAGER_EMP_ID, MANAGER_NAME→EMPLOYEE.MANAGER_NAME_DISP |
| LOV `LOV_LOCATIONS` | LOV (400×300) | `GET /api/lookups/locations` | `<LocationAutocomplete>` with async fetch | Query: `SELECT LOCATION_CODE, LOCATION_NAME, CITY, STATE_PROVINCE FROM LOCATIONS WHERE ACTIVE_FLAG='Y'`; Returns: LOCATION_CODE→EMPLOYEE.LOCATION_CODE |
| RecordGroup `RG_DEPARTMENTS` | Record Group | `DepartmentRepository.findByActiveFlagY()` | React Query cache key `['departments']` | Populated at form init via `POPULATE_GROUP` |
| RecordGroup `RG_JOB_TITLES` | Record Group | `JobTitleRepository.findActiveWithGrade()` | React Query cache key `['jobTitles']` | Populated at form init |
| RecordGroup `RG_LOCATIONS` | Record Group | `LocationRepository.findByActiveFlagY()` | React Query cache key `['locations']` | Populated at form init |
| RecordGroup `RG_MANAGERS` | Record Group | `EmployeeRepository.findActiveManagers()` | React Query cache key `['managers']` | Populated dynamically |
| Canvas `CVS_MAIN` | Tab canvas (700×500) | — | `<Tabs>` component wrapping 4 `<TabPanel>` children | CanvasType=Tab |
| TabPage `TP_PERSONAL` | Tab page ("Personal Information") | — | `<TabPanel label="Personal Information">` | Contains personal info fields |
| TabPage `TP_JOB` | Tab page ("Job & Compensation") | — | `<TabPanel label="Job & Compensation">` | Contains job/salary fields |
| TabPage `TP_DEPENDENTS` | Tab page ("Dependents") | — | `<TabPanel label="Dependents">` | Contains DEPENDENTS and EMERGENCY_CONTACTS blocks |
| TabPage `TP_HISTORY` | Tab page ("Employment History") | — | `<TabPanel label="Employment History">` | Contains EMP_HISTORY block |
| Canvas `CVS_TOOLBAR` | Horizontal Toolbar canvas (700×38) | — | `<Toolbar>` component (Save, Clear, Query, Nav buttons) | Toolbar buttons call HRMS_COMMON_LIB procedures |
| Window `WIN_EMPLOYEE` | Document window (720×550) | — | Page container within `DashboardLayout` | WindowStyle=Document |
| Alert `ALT_CONFIRM_EXIT` | Caution alert (Save/Discard/Cancel) | — | `<ConfirmDialog variant="warning" actions={['Save','Discard','Cancel']}>You have unsaved changes...</ConfirmDialog>` | 3 buttons: Save, Discard, Cancel |
| Alert `ALT_CONFIRM_DELETE` | Stop alert (Yes/No) | — | `<ConfirmDialog variant="danger" actions={['Yes','No']}>Are you sure you want to delete this employee record?</ConfirmDialog>` | 2 buttons: Yes, No |

### 1.4 HRMS_LEAVE.xml

| Oracle Forms Element | Type | Java/Spring Equivalent | React Equivalent | Notes |
|---|---|---|---|---|
| FormModule `HRMS_LEAVE` | FormModule | — | `LeavePage` (`/leave` route) | 5 blocks, 4 tabs, 3 LOVs; MenuModule=HRMS_MENU |
| AttachedLibrary `HRMS_COMMON_LIB` | Attached library | Shared utility classes | `import { ... } from '@/utils/common'` | |
| Trigger `WHEN-NEW-FORM-INSTANCE` | Form-level trigger | Spring Security session filter | `useEffect` on mount: validate session, set title, set default filter (current user's requests), populate LOVs, execute queries for requests + balances | Default WHERE: `EMP_ID = current_emp_id ORDER BY CREATED_DATE DESC` |
| **Block `LEAVE_REQUEST`** | Data block (Table: `HRMS.LEAVE_REQUESTS`) | `LeaveController.getMyRequests()` | `MyLeaveRequestsTable` component (read-only grid, 8 rows) | RecordsDisplayed=8; InsertAllowed/UpdateAllowed/DeleteAllowed=No |
| Item `REQUEST_ID` | Hidden PK | `LeaveRequest.requestId` (Long) | Hidden | PrimaryKey |
| Item `EMP_ID` | Hidden FK | `LeaveRequest.empId` (Long) | Hidden | |
| Item `LEAVE_TYPE_NAME_DISP` | Display Item (Char, non-DB) | — | `<td>{row.leaveTypeName}</td>` | Populated via POST-QUERY join to LEAVE_TYPES |
| Item `START_DATE` | Text Field (Date, MM/DD/YYYY) | `LeaveRequest.startDate` (LocalDate) | `<td>{formatDate(row.startDate)}</td>` | |
| Item `END_DATE` | Text Field (Date, MM/DD/YYYY) | `LeaveRequest.endDate` (LocalDate) | `<td>{formatDate(row.endDate)}</td>` | |
| Item `TOTAL_DAYS` | Text Field (Number, 990.0) | `LeaveRequest.totalDays` (BigDecimal) | `<td>{row.totalDays}</td>` | |
| Item `STATUS` | Text Field (Char) | `LeaveRequest.status` (String) | `<StatusBadge status={row.status} />` | PENDING, APPROVED, REJECTED, CANCELLED, TAKEN |
| Item `REASON` | Text Field (Char) | `LeaveRequest.reason` (String) | `<td>{row.reason}</td>` | |
| Item `BTN_CANCEL_REQUEST` | Push Button (label "Cancel Request") | — | `<button onClick={() => cancelRequest(row.requestId)}>Cancel Request</button>` | Only for PENDING/APPROVED; calls `PKG_LEAVE.cancel_leave_request`; shows ALT_CONFIRM_CANCEL first |
| Trigger `POST-QUERY` (LEAVE_REQUEST) | Block trigger | DTO projection with join or `@Formula` | Included in API response via join | Populates LEAVE_TYPE_NAME_DISP from LEAVE_TYPES |
| Trigger `WHEN-BUTTON-PRESSED` (BTN_CANCEL_REQUEST) | Button trigger | `DELETE /api/leave/requests/{id}/cancel` | `useMutation` calling cancel endpoint, with confirmation dialog | Validates status, shows confirm alert, calls PKG_LEAVE, refreshes query |
| **Block `NEW_REQUEST`** | Control block (QueryDataSourceType=None) | `LeaveController.submitRequest()` | `SubmitLeaveRequestForm` component | Control block for new submissions |
| Item `NR_LEAVE_TYPE_ID` | Text Field (Number, LOV) | `SubmitLeaveRequest.leaveTypeId` (Long) | `<LeaveTypeSelect name="leaveTypeId" />` | LOV=LOV_LEAVE_TYPES |
| Item `NR_LEAVE_TYPE_DISP` | Display Item (Char) | — | Display label next to select | Auto-populated from LOV |
| Item `NR_START_DATE` | Text Field (Date, MM/DD/YYYY) | `SubmitLeaveRequest.startDate` (LocalDate) | `<DatePicker name="startDate" />` | |
| Item `NR_END_DATE` | Text Field (Date, MM/DD/YYYY) | `SubmitLeaveRequest.endDate` (LocalDate) | `<DatePicker name="endDate" />` | |
| Item `NR_HALF_DAY` | Check Box (Y/N) | `SubmitLeaveRequest.halfDayFlag` (String) | `<Checkbox name="halfDay" label="Half Day" />` | CheckBoxMapping=Y,N |
| Item `NR_REASON` | Text Field (Char, maxlen 500, MultiLine) | `SubmitLeaveRequest.reason` (String) | `<textarea name="reason" maxLength={500} rows={3} />` | MultiLine=Yes |
| Item `NR_CALC_DAYS` | Display Item (Number) | — | `<span>{calculatedDays}</span>` | Computed from start/end dates |
| Item `NR_BALANCE_DISP` | Display Item (Number) | — | `<span>{availableBalance}</span>` | Shows remaining balance for selected leave type |
| Item `BTN_SUBMIT` | Push Button (label "Submit Request") | — | `<button type="submit">Submit Request</button>` | Validates fields, calls `PKG_LEAVE.submit_leave_request`, clears form, refreshes requests |
| Trigger `WHEN-BUTTON-PRESSED` (BTN_SUBMIT) | Button trigger | `POST /api/leave/requests` | `onSubmit` handler: calls API, shows success toast, reset form, refetch requests | Validates required fields, calls PKG_LEAVE.submit_leave_request |
| **Block `LEAVE_BALANCE`** | Data block (Table: `HRMS.LEAVE_BALANCES`) | `LeaveController.getBalances()` | `LeaveBalanceTable` component (read-only, 6 rows) | RecordsDisplayed=6; read-only |
| Item `LEAVE_TYPE_NAME_DISP` | Display Item | — | `<td>{row.leaveTypeName}</td>` | |
| Item `OPENING_BALANCE` | Display Item (Number, 990.0) | `LeaveBalance.openingBalance` (BigDecimal) | `<td>{row.openingBalance}</td>` | |
| Item `ACCRUED` | Display Item (Number, 990.0) | `LeaveBalance.accrued` (BigDecimal) | `<td>{row.accrued}</td>` | |
| Item `USED` | Display Item (Number, 990.0) | `LeaveBalance.used` (BigDecimal) | `<td>{row.used}</td>` | |
| Item `PENDING` | Display Item (Number, 990.0) | `LeaveBalance.pending` (BigDecimal) | `<td>{row.pending}</td>` | |
| Item `AVAILABLE` | Display Item (Number, 990.0) | `LeaveBalance.available` (BigDecimal) | `<td>{row.available}</td>` | Virtual column in DB: `OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING` |
| **Block `PENDING_APPROVAL`** | Data block (Table/View: pending requests for approver) | `LeaveController.getPendingApprovals()` | `PendingApprovalsTable` component | Tab: Pending Approvals; filtered by current user as approver |
| **Block `TEAM_CAL`** | Data block (query-based) | `LeaveController.getTeamCalendar()` | `TeamCalendar` component (calendar view) | Tab: Team Calendar; shows team's approved leave on a calendar |
| LOV `LOV_LEAVE_TYPES` | LOV (350×250) | `GET /api/lookups/leave-types` | `<LeaveTypeSelect>` with async fetch | Query: `SELECT LEAVE_TYPE_ID, LEAVE_TYPE_CODE, LEAVE_TYPE_NAME FROM LEAVE_TYPES WHERE ACTIVE_FLAG='Y'`; Returns: LEAVE_TYPE_ID→NR_LEAVE_TYPE_ID, LEAVE_TYPE_NAME→NR_LEAVE_TYPE_DISP |
| RecordGroup `RG_LEAVE_TYPES` | Record Group | `LeaveTypeRepository.findByActiveFlagY()` | React Query cache key `['leaveTypes']` | |
| Canvas `CVS_MAIN` | Tab canvas (700×480) | — | `<Tabs>` component | CanvasType=Tab |
| TabPage `TP_MY_REQUESTS` | Tab page ("My Requests") | — | `<TabPanel label="My Requests">` | Contains LEAVE_REQUEST block |
| TabPage `TP_NEW_REQUEST` | Tab page ("Submit Request") | — | `<TabPanel label="Submit Request">` | Contains NEW_REQUEST block |
| TabPage `TP_APPROVALS` | Tab page ("Pending Approvals") | — | `<TabPanel label="Pending Approvals">` | Contains PENDING_APPROVAL block |
| TabPage `TP_CALENDAR` | Tab page ("Team Calendar") | — | `<TabPanel label="Team Calendar">` | Contains TEAM_CAL block |
| Window `WIN_LEAVE` | Document window (720×520) | — | Page container | WindowStyle=Document |
| Alert `ALT_CONFIRM_CANCEL` | Caution alert (Yes/No) | — | `<ConfirmDialog variant="warning" actions={['Yes','No']}>Are you sure you want to cancel this leave request?</ConfirmDialog>` | Shown before cancelling a request |

### 1.5 HRMS_PAYROLL.xml

| Oracle Forms Element | Type | Java/Spring Equivalent | React Equivalent | Notes |
|---|---|---|---|---|
| FormModule `HRMS_PAYROLL` | FormModule | — | `PayrollPage` (`/payroll` route) | 4 blocks, 3 tabs, 3 LOVs; MenuModule=HRMS_MENU; requires PAYROLL permission |
| AttachedLibrary `HRMS_COMMON_LIB` | Attached library | Shared utility classes | `import { ... } from '@/utils/common'` | |
| Trigger `WHEN-NEW-FORM-INSTANCE` | Form-level trigger | Spring Security `@PreAuthorize("hasPermission('PAYROLL','VIEW')")` | `useEffect` on mount: validate session, check PAYROLL VIEW permission (redirect if denied), set title, query open pay periods | Requires `PKG_SECURITY.has_permission('PAYROLL','VIEW')` |
| **Block `PAY_PERIOD`** | Data block (Table: `HRMS.PAY_PERIODS`) | `PayPeriodController` + `PayPeriodService` | `PayPeriodsTable` component (10-row grid, read-only) | RecordsDisplayed=10; all DML disabled; default WHERE: `STATUS='OPEN' ORDER BY PERIOD_START_DATE DESC` |
| Item `PERIOD_ID` | Hidden PK | `PayPeriod.periodId` (Long) | Hidden | PrimaryKey |
| Item `PERIOD_NAME` | Text Field (Char) | `PayPeriod.periodName` (String) | `<td>{row.periodName}</td>` | |
| Item `PERIOD_START_DATE` | Text Field (Date, MM/DD/YYYY) | `PayPeriod.periodStartDate` (LocalDate) | `<td>{formatDate(row.periodStartDate)}</td>` | |
| Item `PERIOD_END_DATE` | Text Field (Date, MM/DD/YYYY) | `PayPeriod.periodEndDate` (LocalDate) | `<td>{formatDate(row.periodEndDate)}</td>` | |
| Item `PAY_DATE` | Text Field (Date, MM/DD/YYYY) | `PayPeriod.payDate` (LocalDate) | `<td>{formatDate(row.payDate)}</td>` | |
| Item `STATUS` | Text Field (Char) | `PayPeriod.status` (String) | `<StatusBadge status={row.status} />` | OPEN, PROCESSING, CLOSED, REVERSED |
| **Block `PAYROLL_RUN`** | Data block (Table: `HRMS.PAYROLL_RUNS`) | `PayrollRunController` + `PayrollRunService` | `PayrollRunsTable` component (5-row grid) | Detail of PAY_PERIOD; RecordsDisplayed=5; read-only |
| Item `RUN_ID` | Hidden PK | `PayrollRun.runId` (Long) | Hidden | PrimaryKey |
| Item `PERIOD_ID` | Hidden FK | `PayrollRun.periodId` (Long) | Hidden | FK to PAY_PERIOD |
| Item `RUN_TYPE` | Text Field (Char) | `PayrollRun.runType` (String) | `<td>{row.runType}</td>` | REGULAR, SUPPLEMENTAL, BONUS, FINAL |
| Item `RUN_DATE` | Text Field (Date, MM/DD/YYYY HH24:MI) | `PayrollRun.runDate` (LocalDateTime) | `<td>{formatDateTime(row.runDate)}</td>` | |
| Item `STATUS` | Text Field (Char) | `PayrollRun.status` (String) | `<StatusBadge status={row.status} />` | PENDING, CALCULATING, CALCULATED, APPROVED, PAID, REVERSED, ERROR |
| Item `EMPLOYEE_COUNT` | Text Field (Number) | `PayrollRun.employeeCount` (Integer) | `<td>{row.employeeCount}</td>` | |
| Item `TOTAL_GROSS` | Text Field (Number, $999,999,990.00) | `PayrollRun.totalGross` (BigDecimal) | `<td>{formatCurrency(row.totalGross)}</td>` | |
| Item `TOTAL_NET` | Text Field (Number, $999,999,990.00) | `PayrollRun.totalNet` (BigDecimal) | `<td>{formatCurrency(row.totalNet)}</td>` | |
| Item `BTN_CREATE_RUN` | Push Button (label "Create Run") | — | `<button onClick={createRun}>Create Run</button>` | Calls `PKG_PAYROLL.create_payroll_run(periodId, 'REGULAR', user)` → `POST /api/payroll/runs` |
| Item `BTN_CALCULATE` | Push Button (label "Calculate") | — | `<button onClick={calculatePayroll}>Calculate</button>` | Only for PENDING status; calls `PKG_PAYROLL.calculate_payroll(runId, user)` → `POST /api/payroll/runs/{id}/calculate` |
| Item `BTN_APPROVE` | Push Button (label "Approve") | — | `<button onClick={approvePayroll} disabled={!can('PAYROLL','APPROVE')}>Approve</button>` | Permission-gated (PAYROLL APPROVE); calls `PKG_PAYROLL.approve_payroll(runId, user)` → `POST /api/payroll/runs/{id}/approve` |
| Trigger `WHEN-BUTTON-PRESSED` (BTN_CREATE_RUN) | Button trigger | `POST /api/payroll/runs` | `useMutation` calling create endpoint, refetch run list | Calls PKG_PAYROLL.create_payroll_run |
| Trigger `WHEN-BUTTON-PRESSED` (BTN_CALCULATE) | Button trigger | `POST /api/payroll/runs/{id}/calculate` | `useMutation` with loading spinner ("Calculating payroll...") | Validates status=PENDING, calls PKG_PAYROLL.calculate_payroll, uses SYNCHRONIZE for UI update |
| Trigger `WHEN-BUTTON-PRESSED` (BTN_APPROVE) | Button trigger | `POST /api/payroll/runs/{id}/approve` | `useMutation` calling approve endpoint | Checks PAYROLL APPROVE permission, calls PKG_PAYROLL.approve_payroll |
| Relation `PERIOD_RUN_REL` | Master-detail relation | `@OneToMany` / `GET /api/payroll/periods/{id}/runs` | `useQuery(['payrollRuns', periodId])` on period row selection | JoinCondition: `PAYROLL_RUN.PERIOD_ID = PAY_PERIOD.PERIOD_ID`; AutoQuery=Yes |
| **Block `PAYROLL_DETAIL`** | Data block (Table: `HRMS.PAYROLL_DETAILS`) | `PayrollDetailController` | `PayrollDetailTable` component | Detail of PAYROLL_RUN; shows per-employee pay elements |
| **Block `PAYSLIP_SUMMARY`** | Data block (query-based) | `PayrollController.getPayslip()` | `PayslipSummaryCard` component | Aggregated view of earnings/deductions/taxes for selected employee |
| Canvas `CVS_MAIN` | Tab canvas (750×520) | — | `<Tabs>` component | CanvasType=Tab |
| TabPage `TP_PERIODS` | Tab page ("Pay Periods") | — | `<TabPanel label="Pay Periods">` | Contains PAY_PERIOD block |
| TabPage `TP_RUNS` | Tab page ("Payroll Runs") | — | `<TabPanel label="Payroll Runs">` | Contains PAYROLL_RUN block with action buttons |
| TabPage `TP_DETAILS` | Tab page ("Pay Details") | — | `<TabPanel label="Pay Details">` | Contains PAYROLL_DETAIL and PAYSLIP_SUMMARY blocks |
| Window `WIN_PAYROLL` | Document window (770×560) | — | Page container | WindowStyle=Document |

### 1.6 HRMS_PERFORMANCE.xml

| Oracle Forms Element | Type | Java/Spring Equivalent | React Equivalent | Notes |
|---|---|---|---|---|
| FormModule `HRMS_PERFORMANCE` | FormModule | — | `PerformancePage` (`/performance` route) | 4 blocks, 3 tabs; MenuModule=HRMS_MENU |
| AttachedLibrary `HRMS_COMMON_LIB` | Attached library | Shared utility classes | `import { ... } from '@/utils/common'` | |
| Trigger `WHEN-NEW-FORM-INSTANCE` | Form-level trigger | Spring Security session filter | `useEffect` on mount: validate session, set title, query open/draft review cycles | Default WHERE: `STATUS IN ('OPEN','DRAFT') ORDER BY CYCLE_YEAR DESC` |
| **Block `REVIEW_CYCLE`** | Data block (Table: `HRMS.REVIEW_CYCLES`) | `ReviewCycleController` + `ReviewCycleService` | `ReviewCyclesTable` component (5-row grid) | RecordsDisplayed=5; read-only |
| Item `CYCLE_ID` | Hidden PK | `ReviewCycle.cycleId` (Long) | Hidden | PrimaryKey |
| Item `CYCLE_NAME` | Text Field (Char) | `ReviewCycle.cycleName` (String) | `<td>{row.cycleName}</td>` | |
| Item `CYCLE_YEAR` | Text Field (Number) | `ReviewCycle.cycleYear` (Integer) | `<td>{row.cycleYear}</td>` | |
| Item `START_DATE` | Text Field (Date, MM/DD/YYYY) | `ReviewCycle.startDate` (LocalDate) | `<td>{formatDate(row.startDate)}</td>` | |
| Item `END_DATE` | Text Field (Date, MM/DD/YYYY) | `ReviewCycle.endDate` (LocalDate) | `<td>{formatDate(row.endDate)}</td>` | |
| Item `STATUS` | Text Field (Char) | `ReviewCycle.status` (String) | `<StatusBadge status={row.status} />` | DRAFT, OPEN, IN_PROGRESS, CALIBRATION, CLOSED |
| **Block `PERFORMANCE_REVIEW`** | Data block (Table: `HRMS.PERFORMANCE_REVIEWS`) | `PerformanceReviewController` + `PerformanceReviewService` | `PerformanceReviewsTable` component (8-row grid, editable) | Detail of REVIEW_CYCLE; RecordsDisplayed=8; UpdateAllowed=Yes |
| Item `REVIEW_ID` | Hidden PK | `PerformanceReview.reviewId` (Long) | Hidden | PrimaryKey |
| Item `CYCLE_ID` | Hidden FK | `PerformanceReview.cycleId` (Long) | Hidden | FK to REVIEW_CYCLE |
| Item `EMP_ID` | Hidden FK | `PerformanceReview.empId` (Long) | Hidden | FK to EMPLOYEES |
| Item `EMP_NAME_DISP` | Display Item (Char, non-DB) | — | `<td>{row.employeeName}</td>` | Populated via POST-QUERY: `SELECT FIRST_NAME||' '||LAST_NAME FROM EMPLOYEES` |
| Item `STATUS` | Text Field (Char, readonly) | `PerformanceReview.status` (String) | `<StatusBadge status={row.status} />` | UpdateAllowed=No; NOT_STARTED, SELF_REVIEW, MANAGER_REVIEW, MEETING_SCHEDULED, COMPLETED, ACKNOWLEDGED |
| Item `OVERALL_RATING` | Text Field (Number, 9.0) | `PerformanceReview.overallRating` (BigDecimal) | `<input name="overallRating" type="number" step="0.1" min="1" max="5" />` | Range 1.0–5.0 |
| Item `RATING_LABEL` | Display Item (Char) | `PerformanceReview.ratingLabel` (String) | `<td>{row.ratingLabel}</td>` | |
| Item `SELF_ASSESSMENT` | Text Field (Char, MultiLine, 300×80) | `PerformanceReview.selfAssessment` (String/CLOB) | `<textarea name="selfAssessment" rows={4} />` | MultiLine=Yes |
| Item `MANAGER_ASSESSMENT` | Text Field (Char, MultiLine, 300×80) | `PerformanceReview.managerAssessment` (String/CLOB) | `<textarea name="managerAssessment" rows={4} />` | MultiLine=Yes |
| Trigger `POST-QUERY` (PERFORMANCE_REVIEW) | Block trigger | DTO join / `@Formula` | Included in API response | Populates EMP_NAME_DISP |
| Relation `CYCLE_REVIEW_REL` | Master-detail relation | `@OneToMany` / `GET /api/performance/cycles/{id}/reviews` | `useQuery(['reviews', cycleId])` on cycle selection | JoinCondition: `PERFORMANCE_REVIEW.CYCLE_ID = REVIEW_CYCLE.CYCLE_ID`; AutoQuery=Yes |
| **Block `PERFORMANCE_GOAL`** | Data block (Table: `HRMS.PERFORMANCE_GOALS`) | `PerformanceGoalController` + `PerformanceGoalService` | `GoalsTable` component (5-row editable grid) | Detail of PERFORMANCE_REVIEW; InsertAllowed=Yes, UpdateAllowed=Yes |
| Item `GOAL_ID` | Hidden PK | `PerformanceGoal.goalId` (Long) | Hidden | PrimaryKey |
| Item `REVIEW_ID` | Hidden FK | `PerformanceGoal.reviewId` (Long) | Hidden | FK to PERFORMANCE_REVIEW |
| Item `GOAL_TITLE` | Text Field (Char, maxlen 250) | `PerformanceGoal.goalTitle` (String, `@NotBlank`) | `<input name="goalTitle" maxLength={250} />` | |
| Item `GOAL_CATEGORY` | List Item (Char, Poplist: BUSINESS/DEVELOPMENT/LEADERSHIP) | `PerformanceGoal.goalCategory` (String, enum) | `<Select name="goalCategory" options={[{label:'Business',value:'BUSINESS'},{label:'Development',value:'DEVELOPMENT'},{label:'Leadership',value:'LEADERSHIP'}]} />` | ListStyle=Poplist; DB allows INNOVATION, COMPLIANCE too |
| Item `WEIGHT_PCT` | Text Field (Number, 990) | `PerformanceGoal.weightPct` (BigDecimal) | `<input name="weightPct" type="number" />` | |
| Item `PROGRESS_PCT` | Text Field (Number, 990) | `PerformanceGoal.progressPct` (BigDecimal) | `<ProgressBar value={row.progressPct} />` or `<input type="number" />` | |
| Item `STATUS` | Text Field (Char) | `PerformanceGoal.status` (String) | `<StatusBadge status={row.status} />` | NOT_STARTED, IN_PROGRESS, COMPLETED, DEFERRED, CANCELLED |
| Relation `REVIEW_GOAL_REL` | Master-detail relation | `@OneToMany` / `GET /api/performance/reviews/{id}/goals` | `useQuery(['goals', reviewId])` on review selection | JoinCondition: `PERFORMANCE_GOAL.REVIEW_ID = PERFORMANCE_REVIEW.REVIEW_ID`; AutoQuery=Yes |
| **Block `REVIEW_DETAIL`** | Control/data block | `PerformanceReviewController.getDetail()` | `ReviewDetailPanel` component | Detailed view of a single review |
| Canvas `CVS_MAIN` | Tab canvas (750×520) | — | `<Tabs>` component | CanvasType=Tab |
| TabPage `TP_CYCLES` | Tab page ("Review Cycles") | — | `<TabPanel label="Review Cycles">` | Contains REVIEW_CYCLE block |
| TabPage `TP_REVIEWS` | Tab page ("My Reviews") | — | `<TabPanel label="My Reviews">` | Contains PERFORMANCE_REVIEW block |
| TabPage `TP_GOALS` | Tab page ("Goals") | — | `<TabPanel label="Goals">` | Contains PERFORMANCE_GOAL block |
| Window `WIN_PERFORMANCE` | Document window (770×560) | — | Page container | WindowStyle=Document |

---

## 2. PL/SQL Library Mapping

### 2.1 HRMS_COMMON_LIB.pll.sql

| PLL Procedure/Function | Purpose | Java Equivalent | React/TS Equivalent |
|---|---|---|---|
| `handle_error(p_module, p_location)` | Global exception handler: logs error to DB via `PKG_COMMON.log_error`, displays formatted message, raises FORM_TRIGGER_FAILURE | `@ControllerAdvice` `GlobalExceptionHandler` with `@ExceptionHandler` methods; logs via SLF4J + writes to `ERROR_LOG` table | Global error boundary (`ErrorBoundary` component) + `toast.error()` notification; errors caught by axios interceptor |
| `toolbar_save` | Commits form (COMMIT_FORM) | `@Transactional` on service methods; explicit `repository.save()` | `useMutation` calling `PUT /api/{resource}/{id}` + success toast |
| `toolbar_clear` | Clears form with ask-commit prompt (CLEAR_FORM(ASK_COMMIT)) | — | `form.reset()` with unsaved-changes confirmation dialog |
| `toolbar_query` | Toggles between ENTER_QUERY and EXECUTE_QUERY mode | `GET /api/{resource}?filters=...` | Search/filter form: toggle between filter-input mode and results mode |
| `toolbar_first` | Navigate to first record (FIRST_RECORD) | — | Pagination: go to page 1 / `setPage(0)` |
| `toolbar_prev` | Navigate to previous record (PREVIOUS_RECORD) | — | Pagination: `setPage(p => Math.max(0, p-1))` |
| `toolbar_next` | Navigate to next record (NEXT_RECORD) | — | Pagination: `setPage(p => p+1)` |
| `toolbar_last` | Navigate to last record (LAST_RECORD) | — | Pagination: go to last page / `setPage(totalPages-1)` |
| `toolbar_insert` | Creates new empty record (CREATE_RECORD) | `POST /api/{resource}` | `navigate('/employees/new')` or open blank form |
| `toolbar_delete` | Deletes current record (DELETE_RECORD) | `DELETE /api/{resource}/{id}` (soft delete) | `useMutation` calling DELETE endpoint with confirmation dialog |
| `toolbar_exit` | Exits form with ask-commit (EXIT_FORM(ASK_COMMIT)) | — | `navigate(-1)` or `navigate('/dashboard')` with unsaved-changes guard |
| `format_date(p_date)` | Formats date as MM/DD/YYYY | `DateTimeFormatter.ofPattern("MM/dd/yyyy")` | `dayjs(date).format('MM/DD/YYYY')` or `Intl.DateTimeFormat` |
| `format_datetime(p_date)` | Formats date as MM/DD/YYYY HH24:MI:SS | `DateTimeFormatter.ofPattern("MM/dd/yyyy HH:mm:ss")` | `dayjs(date).format('MM/DD/YYYY HH:mm:ss')` |
| `get_current_user` | Returns NVL(:GLOBAL.current_user, USER) | `SecurityContextHolder.getContext().getAuthentication().getName()` | `useAuth().currentUser` from auth context |
| `get_session_id` | Returns TO_NUMBER(:GLOBAL.session_id) | Implicit in Spring Security session / JWT claim | `useAuth().sessionId` from auth context |
| `check_session` | Validates session is active via `PKG_SECURITY.is_session_valid` | Spring Security session validation filter / JWT expiry check | Axios interceptor checking 401 responses → redirect to `/login` |
| `refresh_lov(p_lov_name)` | Re-populates a record group by name convention (RG_ prefix) | `GET /api/lookups/{type}` (cache invalidation) | `queryClient.invalidateQueries(['lookupName'])` |

### 2.2 HRMS_VALIDATION_LIB.pll.sql

| PLL Procedure/Function | Purpose | Java Equivalent | React/TS Equivalent |
|---|---|---|---|
| `validate_email(p_email)` | Client-side email validation: checks for `@` and `.` after `@`; returns BOOLEAN | `@Email` Jakarta Bean Validation annotation on DTO field | `z.string().email()` (Zod schema) or custom regex validator; note: PLL version rejects valid subdomains (known bug) |
| `validate_phone(p_phone)` | US phone format validation: strips non-digits, checks 10-11 digit length | Custom `@PhoneNumber` constraint validator | `(value) => { const digits = value.replace(/\D/g,''); return digits.length === 10 \|\| digits.length === 11; }` |
| `validate_ssn(p_ssn)` | SSN format validation: strips non-digits, checks 9 digits, validates no all-zero groups | Custom `@SSN` constraint validator | `(value) => { const d = value.replace(/\D/g,''); return d.length === 9 && d.slice(0,3)!=='000' && d.slice(3,5)!=='00' && d.slice(5)!=='0000'; }` |
| `validate_date_not_future(p_date)` | Ensures date ≤ SYSDATE | `@PastOrPresent` Bean Validation annotation | `z.date().max(new Date())` or `(d) => d <= new Date()` |
| `validate_salary_range(p_salary, p_grade_id)` | Checks salary against JOB_GRADES min/max; returns NULL if valid, error message if invalid | `SalaryValidator` service: queries `JOB_GRADES` by `grade_id`, compares | `useSalaryValidation(gradeId)` hook: fetches grade range from API, returns validation result; `GET /api/lookups/job-grades/{id}` |

---

## 3. Menu Module Mapping

Source: `forms/menus/HRMS_MENU.mmb.sql` and inline `MenuModule MENU_MAIN` in `HRMS_MENU.xml`.

| Menu Item | Oracle Forms Action | Modern UI Equivalent |
|---|---|---|
| **File → Save** | `COMMIT_FORM` | Toolbar "Save" button → `PUT /api/{resource}/{id}` via `useMutation`; keyboard shortcut `Ctrl+S` |
| **File → Save & Exit** | `COMMIT_FORM; EXIT_FORM` | "Save & Close" button → save then `navigate(-1)` |
| **File → Print** | `RUN_PRODUCT` (launches Oracle Reports) | "Print" / "Export PDF" button → `GET /api/reports/{name}?format=pdf` opens in new tab or triggers download |
| **File → Exit** | `EXIT_FORM` | "Close" or browser back; top-level: logout + redirect to `/login` |
| **Edit → Clear Record** | `CLEAR_RECORD` | "Reset" / "Clear" button → `form.reset()` |
| **Edit → Duplicate Record** | `DUPLICATE_RECORD` | "Duplicate" button → `POST /api/{resource}` with copied data (ID omitted) |
| **Edit → Delete Record** | `DELETE_RECORD` | "Delete" button → confirmation dialog → `DELETE /api/{resource}/{id}` |
| **Edit → Insert Record** | `CREATE_RECORD` | "New" / "Add" button → `navigate('/employees/new')` or open blank form row |
| **Query → Enter Query** | `ENTER_QUERY` | Open search/filter panel; switches form fields to filter-input mode |
| **Query → Execute Query** | `EXECUTE_QUERY` | "Search" / "Apply Filters" button → `GET /api/{resource}?filters=...` |
| **Query → Cancel Query** | `EXIT_FORM` (in query mode) | "Clear Filters" / "Cancel" → reset search form |
| **Query → Count Matching** | `COUNT_QUERY` | Display total count in search results header: "Showing X of Y results" |
| **Query → Fetch Next Set** | `SCROLL_DOWN` | Pagination: "Next Page" or infinite scroll `onScrollEnd` trigger |
| **Navigate → First Record** | `FIRST_RECORD` | Pagination: "First" button → `setPage(0)` |
| **Navigate → Previous Record** | `PREVIOUS_RECORD` | Pagination: "Previous" button / `←` arrow key |
| **Navigate → Next Record** | `NEXT_RECORD` | Pagination: "Next" button / `→` arrow key |
| **Navigate → Last Record** | `LAST_RECORD` | Pagination: "Last" button → `setPage(totalPages-1)` |
| **Navigate → Previous Block** | `PREVIOUS_BLOCK` | Tab navigation: focus previous tab panel; or section navigation |
| **Navigate → Next Block** | `NEXT_BLOCK` | Tab navigation: focus next tab panel |
| **Modules → Employee Management** | `OPEN_FORM('HRMS_EMPLOYEE', ACTIVATE, SESSION)` | Sidebar/nav link → `<Link to="/employees">` |
| **Modules → Payroll Processing** | `OPEN_FORM('HRMS_PAYROLL', ACTIVATE, SESSION)` | Sidebar/nav link → `<Link to="/payroll">` (permission-gated) |
| **Modules → Leave Management** | `OPEN_FORM('HRMS_LEAVE', ACTIVATE, SESSION)` | Sidebar/nav link → `<Link to="/leave">` |
| **Modules → Performance Reviews** | `OPEN_FORM('HRMS_PERFORMANCE', ACTIVATE, SESSION)` | Sidebar/nav link → `<Link to="/performance">` |
| **Modules → Reports & Analytics** | `OPEN_FORM('HRMS_REPORTS', ACTIVATE, SESSION)` | Sidebar/nav link → `<Link to="/reports">` (permission-gated) |
| **Modules → System Admin** | `OPEN_FORM('HRMS_ADMIN', ACTIVATE, SESSION)` | Sidebar/nav link → `<Link to="/admin">` (permission-gated) |
| **Admin → Change Password** | `SHOW_WINDOW('WIN_CHANGE_PWD')` | "Change Password" modal dialog → `POST /api/auth/change-password` |
| **Admin → System Parameters** | Requires ADMIN permission | Admin settings page → `GET/PUT /api/admin/parameters` |
| **Admin → User Management** | Requires ADMIN permission | User management page → CRUD on `/api/admin/users` |
| **Help → Contents** | `WEB.SHOW_DOCUMENT` (opens help URL) | Link to documentation site / help center in new tab |
| **Help → About HRMS** | `SHOW_ALERT('ALT_ABOUT')` → "HRMS v4.2 - Build 2024.03.15" | "About" modal showing version, build info |
| **Help → Support** | `WEB.SHOW_DOCUMENT` (opens support URL) | Link to support/ticket portal in new tab |

---

## 4. PL/SQL Package → Service Layer Mapping

### 4.1 PKG_SECURITY

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_SECURITY` | `SecurityService` | `AuthController` | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `authenticate(p_username, p_password, p_ip_address)` → NUMBER | Returns session_id | `POST /api/auth/login` | Request: `{username, password}`; Response: `{token, sessionId, empId, permissions}`; replaces MD5 with bcrypt |
| `logout(p_session_id)` | Void | `POST /api/auth/logout` | Invalidates JWT/session; clears USER_SESSIONS row |
| `is_session_valid(p_session_id)` → BOOLEAN | Returns validity | Spring Security filter (implicit) | JWT expiry check + token blacklist; no explicit endpoint needed |
| `has_permission(p_emp_id, p_module, p_action)` → BOOLEAN | Returns access flag | `GET /api/auth/permissions` or embedded in JWT claims | Used by `@PreAuthorize` annotations on controllers |
| `encrypt_ssn(p_ssn)` → VARCHAR2 | Returns encrypted string | Internal service method (not exposed via REST) | Migrate from hard-coded AES key to externalized secret (e.g., AWS KMS) |
| `decrypt_ssn(p_encrypted)` → VARCHAR2 | Returns plaintext SSN | Internal service method (not exposed via REST) | Only called in employee detail endpoint for authorized users |
| `hash_password(p_password)` → VARCHAR2 | Returns hash | Internal service method | Replace MD5 with `BCryptPasswordEncoder` |
| `change_password(p_emp_id, p_old_password, p_new_password)` | Void | `POST /api/auth/change-password` | Request: `{oldPassword, newPassword}`; validates old password first |

### 4.2 PKG_EMPLOYEE

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_EMPLOYEE` | `EmployeeService` | `EmployeeController` | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `create_employee(p_first_name, p_last_name, p_hire_date, p_dept_id, p_job_id, p_manager_emp_id, p_location_code, p_employment_type, p_base_salary, p_email, p_user)` → NUMBER | Returns emp_id | `POST /api/employees` | Request: `CreateEmployeeRequest` DTO |
| `update_employee(p_emp_id, p_first_name, p_last_name, p_email, p_phone_work, p_phone_mobile, p_address_line1, p_address_line2, p_city, p_state_province, p_postal_code, p_country_code, p_user)` | Void | `PUT /api/employees/{id}` | Request: `UpdateEmployeeRequest` DTO |
| `get_employee(p_emp_id)` → t_emp_rec | Returns record | `GET /api/employees/{id}` | Response: `EmployeeDetailResponse` DTO |
| `get_employee_by_number(p_emp_number)` → t_emp_rec | Returns record | `GET /api/employees?empNumber={number}` | Query parameter search |
| `search_employees(p_cursor OUT, p_last_name, p_first_name, p_dept_id, p_status, p_location_code, p_hire_date_from, p_hire_date_to)` | REF CURSOR | `GET /api/employees?lastName=&firstName=&deptId=&status=&locationCode=&hireDateFrom=&hireDateTo=` | Paginated response with filters |
| `transfer_employee(p_emp_id, p_new_dept_id, p_new_job_id, p_new_manager_id, p_new_location, p_effective_date, p_reason_code, p_comments, p_user)` | Void | `POST /api/employees/{id}/transfer` | Request: `TransferRequest` DTO |
| `promote_employee(p_emp_id, p_new_job_id, p_new_salary, p_effective_date, p_comments, p_user)` | Void | `POST /api/employees/{id}/promote` | Request: `PromotionRequest` DTO |
| `terminate_employee(p_emp_id, p_termination_date, p_reason, p_comments, p_user)` | Void | `POST /api/employees/{id}/terminate` | Request: `TerminationRequest` DTO |
| `rehire_employee(p_emp_id, p_rehire_date, p_dept_id, p_job_id, p_base_salary, p_user)` | Void | `POST /api/employees/{id}/rehire` | Request: `RehireRequest` DTO |
| `get_direct_reports(p_manager_emp_id)` → t_emp_id_table | Returns ID list | `GET /api/employees/{id}/direct-reports` | Response: list of employee summaries |
| `get_org_chart(p_root_emp_id, p_max_depth)` → t_emp_cursor | Returns hierarchy cursor | `GET /api/employees/{id}/org-chart?maxDepth=10` | Response: tree structure; replace `CONNECT BY` with recursive CTE or in-memory tree builder |
| `get_headcount_by_dept(p_dept_id, p_as_of_date)` → NUMBER | Returns count | `GET /api/employees/headcount?deptId=&asOfDate=` | |
| `get_tenure_years(p_emp_id)` → NUMBER | Returns years | Computed field in `EmployeeDetailResponse` | `TRUNC(MONTHS_BETWEEN(SYSDATE, hireDate)/12, 1)` |
| `is_active(p_emp_id)` → BOOLEAN | Returns active flag | Internal service method | Used in cross-package validation |
| `validate_employee(p_emp_id)` → BOOLEAN | Validates record | Internal service method | Called before lifecycle operations |
| `emp_exists(p_emp_id)` → BOOLEAN | Checks existence | Internal service method | |
| `generate_emp_number` → VARCHAR2 | Generates EMP-XXXXXX | Internal service method | Replace MAX()+1 race condition with sequence-backed generation |
| `set_session_context(p_user, p_emp_id)` | Sets package globals | `SecurityContext` in Spring | Replaced by Spring Security context |

### 4.3 PKG_LEAVE

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_LEAVE` | `LeaveService` | `LeaveController` | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `submit_leave_request(p_emp_id, p_leave_type_id, p_start_date, p_end_date, p_half_day_flag, p_half_day_period, p_reason, p_user)` → NUMBER | Returns request_id | `POST /api/leave/requests` | Request: `SubmitLeaveRequest` DTO |
| `approve_leave_request(p_request_id, p_approver_emp_id, p_comments, p_user)` | Void | `POST /api/leave/requests/{id}/approve` | Request: `{comments}` |
| `reject_leave_request(p_request_id, p_approver_emp_id, p_comments, p_user)` | Void | `POST /api/leave/requests/{id}/reject` | Request: `{comments}` (required) |
| `cancel_leave_request(p_request_id, p_reason, p_user)` | Void | `POST /api/leave/requests/{id}/cancel` | Request: `{reason}` |
| `get_leave_balance(p_emp_id, p_leave_type_id, p_year)` → NUMBER | Returns available balance | `GET /api/leave/balances?empId=&leaveTypeId=&year=` | |
| `adjust_leave_balance(p_emp_id, p_leave_type_id, p_adjustment, p_reason, p_user)` | Void | `POST /api/leave/balances/adjust` | Admin-only; Request: `AdjustBalanceRequest` DTO |
| `initialize_balances(p_emp_id, p_year, p_user)` | Void | `POST /api/leave/balances/initialize` | Batch operation for new year |
| `run_monthly_accrual(p_accrual_date, p_user)` | Void | `POST /api/leave/accrual/run` | Scheduled job → `@Scheduled(cron="0 0 1 1 * *")` or Spring Batch |
| `process_carryover(p_year, p_user)` | Void | `POST /api/leave/accrual/carryover` | Year-end batch |
| `expire_carryover(p_user)` | Void | `POST /api/leave/accrual/expire` | Batch job |
| `get_pending_requests(p_cursor OUT, p_approver_id)` | REF CURSOR | `GET /api/leave/requests/pending?approverId=` | Returns pending requests for approver |
| `get_team_calendar(p_cursor OUT, p_manager_id, p_start_date, p_end_date)` | REF CURSOR | `GET /api/leave/team-calendar?managerId=&startDate=&endDate=` | Calendar data for team view |
| `calculate_business_days(p_start_date, p_end_date, p_location_code)` → NUMBER | Returns count | `GET /api/leave/business-days?startDate=&endDate=&locationCode=` | Excludes weekends + holidays |
| `check_leave_overlap(p_emp_id, p_start_date, p_end_date, p_exclude_request_id)` → BOOLEAN | Returns overlap flag | Internal service method | Called during submission validation |

### 4.4 PKG_PAYROLL

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_PAYROLL` | `PayrollService` | `PayrollController` | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `create_salary_record(p_emp_id, p_effective_date, p_base_salary, p_change_reason, p_change_pct, p_currency_code, p_pay_frequency, p_user)` | Void | `POST /api/payroll/salary-records` | Request: `CreateSalaryRecordRequest` DTO |
| `get_current_salary(p_emp_id)` → NUMBER | Returns salary | `GET /api/payroll/salary/{empId}/current` | |
| `get_salary_as_of(p_emp_id, p_as_of)` → NUMBER | Returns salary at date | `GET /api/payroll/salary/{empId}?asOf=` | |
| `create_pay_periods(p_year, p_frequency, p_user)` | Void | `POST /api/payroll/periods/generate` | Request: `{year, frequency}` |
| `close_pay_period(p_period_id, p_user)` | Void | `POST /api/payroll/periods/{id}/close` | |
| `get_current_period` → NUMBER | Returns period_id | `GET /api/payroll/periods/current` | |
| `create_payroll_run(p_period_id, p_run_type, p_user)` → NUMBER | Returns run_id | `POST /api/payroll/runs` | Request: `{periodId, runType}` |
| `calculate_payroll(p_run_id, p_user)` | Void | `POST /api/payroll/runs/{id}/calculate` | Long-running; consider async with status polling |
| `calculate_employee_pay(p_run_id, p_emp_id, p_period_id, p_user)` | Void | Internal service method | Called per-employee during calculate_payroll |
| `approve_payroll(p_run_id, p_user)` | Void | `POST /api/payroll/runs/{id}/approve` | Requires PAYROLL APPROVE permission |
| `reverse_payroll(p_run_id, p_reason, p_user)` | Void | `POST /api/payroll/runs/{id}/reverse` | Request: `{reason}` |
| `calculate_federal_tax(p_taxable_income, p_filing_status, p_allowances, p_additional_wh, p_pay_frequency)` → NUMBER | Returns tax amount | Internal service method (`TaxCalculationService`) | Replace hard-coded brackets with configurable tax tables |
| `calculate_state_tax(p_taxable_income, p_state_code, p_filing_status, p_allowances, p_pay_frequency)` → NUMBER | Returns tax amount | Internal service method (`TaxCalculationService`) | |
| `calculate_fica(p_gross_pay, p_ytd_gross)` → NUMBER | Returns FICA amount | Internal service method (`TaxCalculationService`) | Social Security calculation |
| `calculate_medicare(p_gross_pay, p_ytd_gross)` → NUMBER | Returns Medicare amount | Internal service method (`TaxCalculationService`) | Includes additional Medicare surtax |
| `get_payslip(p_cursor OUT, p_run_id, p_emp_id)` | REF CURSOR | `GET /api/payroll/runs/{runId}/payslips?empId=` | Response: paginated payslip list |
| `get_ytd_earnings(p_emp_id, p_tax_year)` → NUMBER | Returns YTD gross | `GET /api/payroll/ytd/{empId}?taxYear=` | |
| `generate_pay_register(p_run_id, p_user)` | Void | `POST /api/payroll/runs/{id}/register` | Generates summary report |

### 4.5 PKG_PERFORMANCE

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_PERFORMANCE` | `PerformanceService` | `PerformanceController` | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `create_review_cycle(p_cycle_name, p_cycle_year, p_start_date, p_end_date, p_self_review_due, p_manager_review_due, p_user)` → NUMBER | Returns cycle_id | `POST /api/performance/cycles` | Request: `CreateReviewCycleRequest` DTO |
| `open_review_cycle(p_cycle_id, p_user)` | Void | `POST /api/performance/cycles/{id}/open` | |
| `close_review_cycle(p_cycle_id, p_user)` | Void | `POST /api/performance/cycles/{id}/close` | |
| `create_review(p_cycle_id, p_emp_id, p_reviewer_emp_id, p_user)` → NUMBER | Returns review_id | `POST /api/performance/reviews` | Request: `{cycleId, empId, reviewerEmpId}` |
| `submit_self_assessment(p_review_id, p_self_assessment, p_user)` | Void | `PUT /api/performance/reviews/{id}/self-assessment` | Request: `{selfAssessment}` (CLOB) |
| `submit_manager_review(p_review_id, p_overall_rating, p_manager_assessment, p_strengths, p_improvement_areas, p_development_plan, p_user)` | Void | `PUT /api/performance/reviews/{id}/manager-review` | Request: `ManagerReviewRequest` DTO |
| `acknowledge_review(p_review_id, p_emp_comments, p_user)` | Void | `POST /api/performance/reviews/{id}/acknowledge` | Request: `{comments}` |
| `add_goal(p_review_id, p_emp_id, p_goal_title, p_goal_description, p_goal_category, p_weight_pct, p_target_date, p_user)` → NUMBER | Returns goal_id | `POST /api/performance/goals` | Request: `CreateGoalRequest` DTO |
| `update_goal_progress(p_goal_id, p_progress_pct, p_status, p_comments, p_user)` | Void | `PUT /api/performance/goals/{id}/progress` | Request: `{progressPct, status, comments}` |
| `get_team_reviews(p_cursor OUT, p_manager_id, p_cycle_id)` | REF CURSOR | `GET /api/performance/reviews?managerId=&cycleId=` | For manager's team view |
| `get_rating_distribution(p_cycle_id, p_dept_id)` → SYS_REFCURSOR | Returns distribution | `GET /api/performance/cycles/{id}/distribution?deptId=` | For calibration/analytics |
| `generate_reviews_for_cycle(p_cycle_id, p_user)` | Void | `POST /api/performance/cycles/{id}/generate-reviews` | Bulk creates review records for all active employees |

### 4.6 PKG_COMMON

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_COMMON` | `CommonService` / utility classes | `CommonController` (minimal) | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `log_error(p_package, p_procedure, p_message, p_user)` | Void | Internal (SLF4J + `ErrorLogRepository`) | No REST endpoint; logs via structured logging framework |
| `log_info(p_package, p_procedure, p_message, p_user)` | Void | Internal (SLF4J) | |
| `get_param(p_group, p_code)` → VARCHAR2 | Returns config value | `GET /api/admin/parameters/{group}/{code}` | Backed by `SYSTEM_PARAMETERS` table |
| `get_param_number(p_group, p_code)` → NUMBER | Returns numeric config | Same as above, parsed | |
| `get_param_date(p_group, p_code)` → DATE | Returns date config | Same as above, parsed | |
| `set_param(p_group, p_code, p_value, p_user)` | Void | `PUT /api/admin/parameters/{group}/{code}` | Admin-only |
| `business_days_between(p_start_date, p_end_date)` → NUMBER | Returns count | `GET /api/common/business-days?startDate=&endDate=` | Also used internally by LeaveService |
| `add_business_days(p_date, p_days)` → DATE | Returns resulting date | Internal utility method | |
| `get_fiscal_year(p_date)` → NUMBER | Returns fiscal year | Internal utility method | Hard-coded Oct 1 start |
| `get_fiscal_quarter(p_date)` → NUMBER | Returns fiscal quarter | Internal utility method | |
| `format_phone(p_phone)` → VARCHAR2 | Formats as (XXX) XXX-XXXX | `PhoneFormatter` utility class | React: shared formatter function |
| `format_ssn_masked(p_ssn)` → VARCHAR2 | Returns XXX-XX-1234 | `SSNFormatter` utility class | Only shows last 4 digits |
| `format_currency(p_amount, p_currency_code)` → VARCHAR2 | Formats as $X,XXX.XX | `CurrencyFormatter` utility class | React: `Intl.NumberFormat('en-US', {style:'currency', currency})` |
| `format_name(p_first_name, p_last_name, p_format)` → VARCHAR2 | Formats name (FL or LF) | `NameFormatter` utility class | |
| `is_valid_email(p_email)` → BOOLEAN | Email validation | `EmailValidator` (Bean Validation) | |
| `is_valid_phone(p_phone)` → BOOLEAN | Phone validation | `PhoneValidator` | |
| `is_valid_ssn(p_ssn)` → BOOLEAN | SSN validation | `SSNValidator` | |

### 4.7 PKG_AUDIT

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_AUDIT` | `AuditService` | `AuditController` | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `log_action(p_table_name, p_record_id, p_action, p_user, p_old_values, p_new_values)` | Void | Internal: `@EntityListeners(AuditListener.class)` + Hibernate Envers or custom JPA audit | Automatically invoked on entity changes; writes to AUDIT_LOG |
| `purge_old_records(p_days_to_keep, p_user)` | Void | `POST /api/admin/audit/purge` | Admin-only; scheduled job `@Scheduled` |
| `get_change_history(p_table_name, p_record_id, p_from_date, p_to_date)` → SYS_REFCURSOR | Returns history | `GET /api/audit/history?tableName=&recordId=&fromDate=&toDate=` | |

### 4.8 PKG_NOTIFICATION

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_NOTIFICATION` | `NotificationService` | `NotificationController` | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `send_notification(p_recipient_emp_id, p_recipient_email, p_type, p_subject, p_body, p_priority, p_reference_table, p_reference_id, p_user)` | Void | Internal service method; enqueues to `NOTIFICATION_QUEUE` | Replace UTL_MAIL with Spring Mail (`JavaMailSender`) or messaging queue (RabbitMQ/SQS) |
| `process_queue(p_batch_size, p_user)` | Void | `POST /api/admin/notifications/process` | Scheduled job `@Scheduled`; processes pending notifications |
| `retry_failed(p_max_retries, p_user)` | Void | `POST /api/admin/notifications/retry` | Retries failed notifications up to max_retries |
| `cancel_notification(p_notification_id, p_user)` | Void | `DELETE /api/notifications/{id}` | Sets status=CANCELLED |

### 4.9 PKG_INTEGRATION

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_INTEGRATION` | `IntegrationService` | `IntegrationController` | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `generate_gl_journal(p_run_id, p_user)` | Void | `POST /api/integrations/gl/generate` | Replace flat file (UTL_FILE) with REST API to GL system or message queue |
| `export_benefits_feed(p_effective_date, p_user)` | Void | `POST /api/integrations/benefits/export` | Replace ADP flat file format with API integration |
| `import_time_attendance(p_file_name, p_user)` | Void | `POST /api/integrations/time-attendance/import` | Replace file-based import with REST/webhook from T&A system |
| `sync_org_structure(p_user)` | Void | `POST /api/integrations/org-structure/sync` | Syncs org data to external systems |
| `get_integration_status(p_integration_name)` → VARCHAR2 | Returns status | `GET /api/integrations/{name}/status` | Health check for integration endpoints |

### 4.10 PKG_VALIDATION

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_VALIDATION` | `ValidationService` | — (no direct REST; used internally) | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `validate_date_range(p_start_date, p_end_date)` → BOOLEAN | Returns validity | Internal: `@AssertTrue` on DTO or custom `DateRangeValidator` | Ensures end ≥ start |
| `validate_salary_for_grade(p_salary, p_grade_id)` → VARCHAR2 | Returns NULL or error | Internal: `SalaryValidator` service | Checks against JOB_GRADES.MIN_SALARY / MAX_SALARY |
| `validate_email_format(p_email)` → BOOLEAN | Returns validity | Internal: `@Email` Bean Validation | Used by WHEN-VALIDATE-ITEM in EMPLOYEE form |
| `validate_phone_format(p_phone)` → BOOLEAN | Returns validity | Internal: custom `@Phone` constraint | |
| `validate_emp_number_format(p_emp_number)` → BOOLEAN | Returns validity | Internal: regex check | Format: `EMP-XXXXXX` |
| `is_future_date(p_date)` → BOOLEAN | Returns if date > SYSDATE | Internal: `@Future` Bean Validation | |
| `is_business_day(p_date, p_location_code)` → BOOLEAN | Returns if business day | Internal: `BusinessDayService` | Checks weekends + HOLIDAYS table |
| `validate_required_fields(p_table_name, p_record_id)` → VARCHAR2 | Returns NULL or missing fields | Internal: Bean Validation `@NotNull/@NotBlank` | Replaced by Jakarta Bean Validation at DTO level |

### 4.11 PKG_REPORTING

| PL/SQL Package | Java Service Class | REST Controller | Key Endpoints |
|---|---|---|---|
| `PKG_REPORTING` | `ReportingService` | `ReportController` | See below |

| PL/SQL Procedure/Function | Signature | REST Endpoint | Notes |
|---|---|---|---|
| `headcount_report(p_cursor OUT, p_as_of_date, p_dept_id, p_location)` | REF CURSOR | `GET /api/reports/headcount?asOfDate=&deptId=&location=` | |
| `compensation_summary(p_cursor OUT, p_dept_id, p_grade_id)` | REF CURSOR | `GET /api/reports/compensation?deptId=&gradeId=` | Uses VW_EMPLOYEE_COMPENSATION |
| `turnover_report(p_cursor OUT, p_start_date, p_end_date, p_dept_id)` | REF CURSOR | `GET /api/reports/turnover?startDate=&endDate=&deptId=` | |
| `new_hires_report(p_cursor OUT, p_start_date, p_end_date, p_dept_id)` | REF CURSOR | `GET /api/reports/new-hires?startDate=&endDate=&deptId=` | |
| `leave_utilization_report(p_cursor OUT, p_year, p_dept_id)` | REF CURSOR | `GET /api/reports/leave-utilization?year=&deptId=` | Uses VW_LEAVE_SUMMARY |
| `payroll_summary_report(p_cursor OUT, p_period_id)` | REF CURSOR | `GET /api/reports/payroll-summary?periodId=` | |
| `eeo_compliance_report(p_cursor OUT, p_as_of_date)` | REF CURSOR | `GET /api/reports/eeo-compliance?asOfDate=` | |
| `refresh_reporting_tables(p_user)` | Void | `POST /api/admin/reports/refresh` | Scheduled nightly refresh; replace with materialized views or real-time aggregation |

---

## 5. Trigger → Middleware/Hook Mapping

### 5.1 Database Triggers

| Trigger | Type | Source Table | Modern Equivalent |
|---|---|---|---|
| `TRG_EMP_BEFORE_INSERT` | BEFORE INSERT (row) | `EMPLOYEES` | JPA `@PrePersist` callback or `@EntityListeners`: sets `createdBy`, `createdDate`, `activeFlag='Y'`, `employmentStatus='ACTIVE'`; validates hire date not >180 days future; validates email uniqueness (unique constraint + Spring `@Unique` validation) |
| `TRG_EMP_BEFORE_UPDATE` | BEFORE UPDATE (row) | `EMPLOYEES` | JPA `@PreUpdate` callback: sets `modifiedBy`, `modifiedDate`; validates state transitions (no direct TERMINATED→ACTIVE); logs status/dept/job changes to `EMPLOYEE_HISTORY` via `EmployeeHistoryService` |
| `TRG_EMP_INSTEAD_OF_DELETE` | BEFORE DELETE (row) | `EMPLOYEES` | Override `delete()` in `EmployeeRepository` / `EmployeeService` to perform soft delete (`activeFlag='N'`); throw exception on hard delete attempt. Or use `@SQLDelete(sql="UPDATE EMPLOYEES SET ACTIVE_FLAG='N' WHERE EMP_ID=?")` |
| `TRG_SALARY_AUDIT` | AFTER INSERT/UPDATE/DELETE (row) | `SALARY_RECORDS` | Hibernate Envers `@Audited` annotation on `SalaryRecord` entity; or `AuditListener` that calls `AuditService.logAction()` with JSON old/new values |
| `TRG_LEAVE_REQUEST_AUDIT` | AFTER UPDATE OF STATUS (row) | `LEAVE_REQUESTS` | `AuditListener` on `LeaveRequest` entity; specifically tracks status changes; or `@PostUpdate` with dirty-checking on `status` field |
| `TRG_DEPARTMENT_AUDIT` | AFTER INSERT/UPDATE/DELETE (row) | `DEPARTMENTS` | Hibernate Envers `@Audited` on `Department` entity; or generic `AuditListener` |

### 5.2 Form-Level Triggers

| Trigger | Form | Type | Modern Equivalent |
|---|---|---|---|
| `WHEN-NEW-FORM-INSTANCE` | All forms | Form lifecycle | React `useEffect(fn, [])` on mount: session validation, permission checks, set page title, fetch initial data, populate dropdowns |
| `ON-ERROR` | HRMS_EMPLOYEE | Form error handler | `@ControllerAdvice` + React `ErrorBoundary` + axios response interceptor; maps error codes to user-friendly messages |
| `KEY-EXIT` | HRMS_EMPLOYEE | Key trigger | `useBeforeUnload` / React Router `useBlocker` for unsaved changes; shows "Save/Discard/Cancel" dialog |
| `KEY-NEXT-ITEM` | HRMS_LOGIN | Key trigger | `onKeyDown` handler: Enter on password field triggers form submit |
| `PRE-INSERT` (EMPLOYEE block) | HRMS_EMPLOYEE | Block trigger | `@PrePersist` / `EmployeeService.create()`: generate ID from sequence, generate emp number, set defaults |
| `PRE-UPDATE` (EMPLOYEE block) | HRMS_EMPLOYEE | Block trigger | `@PreUpdate` / interceptor: set `modifiedBy`, `modifiedDate` |
| `POST-QUERY` (EMPLOYEE block) | HRMS_EMPLOYEE | Block trigger | DTO projection with JOINs in repository query; or `@PostLoad` to populate transient display fields |
| `POST-QUERY` (LEAVE_REQUEST block) | HRMS_LEAVE | Block trigger | JOIN in repository query: `LEFT JOIN LEAVE_TYPES` to include `leaveTypeName` in response DTO |
| `POST-QUERY` (PERFORMANCE_REVIEW block) | HRMS_PERFORMANCE | Block trigger | JOIN in repository query: `LEFT JOIN EMPLOYEES` to include `employeeName` in response DTO |
| `WHEN-VALIDATE-ITEM` (EMPLOYEE block) | HRMS_EMPLOYEE | Validation trigger | Per-field `onChange`/`onBlur` validation in React form; Zod schema or react-hook-form `validate`; on server side: `@Valid` with custom constraint validators |
| `WHEN-BUTTON-PRESSED` (BTN_LOGIN) | HRMS_LOGIN | Button trigger | `onSubmit` handler calling `POST /api/auth/login` |
| `WHEN-BUTTON-PRESSED` (BTN_LOGOUT) | HRMS_MENU | Button trigger | `onClick` calling `POST /api/auth/logout` + redirect |
| `WHEN-BUTTON-PRESSED` (BTN_EMPLOYEES) | HRMS_MENU | Button trigger | `onClick={() => navigate('/employees')}` |
| `WHEN-BUTTON-PRESSED` (BTN_PAYROLL) | HRMS_MENU | Button trigger | `onClick`: permission check → `navigate('/payroll')` |
| `WHEN-BUTTON-PRESSED` (BTN_LEAVE) | HRMS_MENU | Button trigger | `onClick={() => navigate('/leave')}` |
| `WHEN-BUTTON-PRESSED` (BTN_PERFORMANCE) | HRMS_MENU | Button trigger | `onClick={() => navigate('/performance')}` |
| `WHEN-BUTTON-PRESSED` (BTN_REPORTS) | HRMS_MENU | Button trigger | `onClick`: permission check → `navigate('/reports')` |
| `WHEN-BUTTON-PRESSED` (BTN_CANCEL_REQUEST) | HRMS_LEAVE | Button trigger | `onClick`: validate status, show confirm dialog, call `POST /api/leave/requests/{id}/cancel` |
| `WHEN-BUTTON-PRESSED` (BTN_SUBMIT) | HRMS_LEAVE | Button trigger | `onSubmit` → validate fields → call `POST /api/leave/requests` |
| `WHEN-BUTTON-PRESSED` (BTN_CREATE_RUN) | HRMS_PAYROLL | Button trigger | `onClick` → call `POST /api/payroll/runs` |
| `WHEN-BUTTON-PRESSED` (BTN_CALCULATE) | HRMS_PAYROLL | Button trigger | `onClick` → validate status → call `POST /api/payroll/runs/{id}/calculate` with loading state |
| `WHEN-BUTTON-PRESSED` (BTN_APPROVE) | HRMS_PAYROLL | Button trigger | `onClick` → permission check → call `POST /api/payroll/runs/{id}/approve` |

---

## 6. Data Block → API Endpoint Mapping

| Block Name | Form | Source Table | GET Endpoint | POST Endpoint | PUT Endpoint | DELETE Endpoint |
|---|---|---|---|---|---|---|
| `LOGIN` | HRMS_LOGIN | None (control block) | — | `POST /api/auth/login` | — | — |
| `MENU_CONTROL` | HRMS_MENU | None (control block) | `GET /api/auth/permissions` (for nav gating) | — | — | — |
| `EMPLOYEE` | HRMS_EMPLOYEE | `HRMS.EMPLOYEES` | `GET /api/employees` (list, filtered) / `GET /api/employees/{id}` (detail) | `POST /api/employees` | `PUT /api/employees/{id}` | `DELETE /api/employees/{id}` (soft delete: sets ACTIVE_FLAG='N') |
| `SALARY` | HRMS_EMPLOYEE | `HRMS.SALARY_RECORDS` | `GET /api/employees/{empId}/salary-history` | `POST /api/payroll/salary-records` | — (read-only in form) | — (read-only in form) |
| `DEPENDENTS` | HRMS_EMPLOYEE | `HRMS.EMPLOYEE_DEPENDENTS` | `GET /api/employees/{empId}/dependents` | `POST /api/employees/{empId}/dependents` | `PUT /api/employees/{empId}/dependents/{id}` | `DELETE /api/employees/{empId}/dependents/{id}` |
| `EMERGENCY_CONTACTS` | HRMS_EMPLOYEE | `HRMS.EMERGENCY_CONTACTS` | `GET /api/employees/{empId}/emergency-contacts` | `POST /api/employees/{empId}/emergency-contacts` | `PUT /api/employees/{empId}/emergency-contacts/{id}` | `DELETE /api/employees/{empId}/emergency-contacts/{id}` |
| `EMP_HISTORY` | HRMS_EMPLOYEE | `HRMS.EMPLOYEE_HISTORY` | `GET /api/employees/{empId}/history` | — (read-only; auto-generated) | — | — |
| `LEAVE_REQUEST` | HRMS_LEAVE | `HRMS.LEAVE_REQUESTS` | `GET /api/leave/requests?empId={currentEmpId}` | — (read-only in this block) | — | — |
| `NEW_REQUEST` | HRMS_LEAVE | None (control block) | — | `POST /api/leave/requests` | — | — |
| `LEAVE_BALANCE` | HRMS_LEAVE | `HRMS.LEAVE_BALANCES` | `GET /api/leave/balances?empId={currentEmpId}&year={currentYear}` | — (read-only) | — | — |
| `PENDING_APPROVAL` | HRMS_LEAVE | `HRMS.LEAVE_REQUESTS` (filtered) | `GET /api/leave/requests/pending?approverId={currentEmpId}` | — | `POST /api/leave/requests/{id}/approve` or `reject` | — |
| `TEAM_CAL` | HRMS_LEAVE | Query-based | `GET /api/leave/team-calendar?managerId={currentEmpId}&startDate=&endDate=` | — | — | — |
| `PAY_PERIOD` | HRMS_PAYROLL | `HRMS.PAY_PERIODS` | `GET /api/payroll/periods?status=OPEN` | `POST /api/payroll/periods/generate` (admin) | — (read-only in form) | — |
| `PAYROLL_RUN` | HRMS_PAYROLL | `HRMS.PAYROLL_RUNS` | `GET /api/payroll/periods/{periodId}/runs` | `POST /api/payroll/runs` | — (read-only; actions via dedicated endpoints) | — |
| `PAYROLL_DETAIL` | HRMS_PAYROLL | `HRMS.PAYROLL_DETAILS` | `GET /api/payroll/runs/{runId}/details?empId=` | — (auto-generated during calculation) | — | — |
| `PAYSLIP_SUMMARY` | HRMS_PAYROLL | Query/view-based | `GET /api/payroll/runs/{runId}/payslips?empId=` | — | — | — |
| `REVIEW_CYCLE` | HRMS_PERFORMANCE | `HRMS.REVIEW_CYCLES` | `GET /api/performance/cycles?status=OPEN,DRAFT` | `POST /api/performance/cycles` (admin) | `PUT /api/performance/cycles/{id}` | — |
| `PERFORMANCE_REVIEW` | HRMS_PERFORMANCE | `HRMS.PERFORMANCE_REVIEWS` | `GET /api/performance/cycles/{cycleId}/reviews` | `POST /api/performance/reviews` | `PUT /api/performance/reviews/{id}` | — |
| `PERFORMANCE_GOAL` | HRMS_PERFORMANCE | `HRMS.PERFORMANCE_GOALS` | `GET /api/performance/reviews/{reviewId}/goals` | `POST /api/performance/goals` | `PUT /api/performance/goals/{id}` | — (DeleteAllowed=No in form) |
| `REVIEW_DETAIL` | HRMS_PERFORMANCE | Query-based | `GET /api/performance/reviews/{id}` (detailed) | — | — | — |

---

## 7. LOV → Component Mapping

| LOV Name | Form | Record Group Query | React Component | API Endpoint |
|---|---|---|---|---|
| `LOV_DEPARTMENTS` | HRMS_EMPLOYEE | `SELECT DEPT_ID, DEPT_CODE, DEPT_NAME, COST_CENTER FROM HRMS.DEPARTMENTS WHERE ACTIVE_FLAG = 'Y' ORDER BY DEPT_NAME` | `<DepartmentAutocomplete>` — searchable select/combobox with columns: Code, Name, Cost Center. Returns `deptId` and `deptName`. | `GET /api/lookups/departments` → `[{deptId, deptCode, deptName, costCenter}]` |
| `LOV_JOB_TITLES` | HRMS_EMPLOYEE | `SELECT j.JOB_ID, j.JOB_CODE, j.JOB_TITLE, g.GRADE_NAME FROM HRMS.JOB_TITLES j JOIN HRMS.JOB_GRADES g ON j.GRADE_ID = g.GRADE_ID WHERE j.ACTIVE_FLAG = 'Y' ORDER BY j.JOB_TITLE` | `<JobTitleAutocomplete>` — searchable select with columns: Code, Title, Grade. Returns `jobId` and `jobTitle`. | `GET /api/lookups/job-titles` → `[{jobId, jobCode, jobTitle, gradeName}]` |
| `LOV_MANAGERS` | HRMS_EMPLOYEE | `SELECT EMP_ID, EMP_NUMBER, FIRST_NAME \|\| ' ' \|\| LAST_NAME AS MANAGER_NAME FROM HRMS.EMPLOYEES WHERE EMPLOYMENT_STATUS = 'ACTIVE' ORDER BY LAST_NAME` | `<ManagerAutocomplete>` — searchable select with columns: Emp#, Name. Returns `managerEmpId` and `managerName`. | `GET /api/lookups/managers` → `[{empId, empNumber, managerName}]` |
| `LOV_LOCATIONS` | HRMS_EMPLOYEE | `SELECT LOCATION_CODE, LOCATION_NAME, CITY, STATE_PROVINCE FROM HRMS.LOCATIONS WHERE ACTIVE_FLAG = 'Y' ORDER BY LOCATION_NAME` | `<LocationAutocomplete>` — searchable select with columns: Code, Name, City, State. Returns `locationCode`. | `GET /api/lookups/locations` → `[{locationCode, locationName, city, stateProvince}]` |
| `LOV_LEAVE_TYPES` | HRMS_LEAVE | `SELECT LEAVE_TYPE_ID, LEAVE_TYPE_CODE, LEAVE_TYPE_NAME FROM HRMS.LEAVE_TYPES WHERE ACTIVE_FLAG = 'Y' ORDER BY LEAVE_TYPE_NAME` | `<LeaveTypeSelect>` — dropdown select. Returns `leaveTypeId` and `leaveTypeName`. | `GET /api/lookups/leave-types` → `[{leaveTypeId, leaveTypeCode, leaveTypeName}]` |
| Gender (inline ListItem) | HRMS_EMPLOYEE | Inline: `M=Male, F=Female, O=Other` | `<Select name="gender">` with static options | No API; static enum `{M:'Male', F:'Female', O:'Other'}` |
| Marital Status (inline ListItem) | HRMS_EMPLOYEE | Inline: `SINGLE, MARRIED, DIVORCED, WIDOWED` | `<Select name="maritalStatus">` with static options | No API; static enum |
| Employment Type (inline ListItem) | HRMS_EMPLOYEE | Inline: `FULL_TIME, PART_TIME, CONTRACT, INTERN` | `<Select name="employmentType">` with static options | No API; static enum |
| Employment Status (inline ListItem) | HRMS_EMPLOYEE | Inline: `ACTIVE, ON_LEAVE, SUSPENDED, TERMINATED` | `<Select name="employmentStatus" disabled>` with static options | No API; static enum |
| Goal Category (inline ListItem) | HRMS_PERFORMANCE | Inline: `BUSINESS, DEVELOPMENT, LEADERSHIP` | `<Select name="goalCategory">` with static options | No API; static enum (DB allows INNOVATION, COMPLIANCE too) |
| Payroll Run Type (implied) | HRMS_PAYROLL | Implied: `REGULAR, SUPPLEMENTAL, BONUS, FINAL` | `<Select name="runType">` with static options | No API; static enum from schema CHECK constraint |
| Pay Period Status (implied) | HRMS_PAYROLL | Implied: `OPEN, PROCESSING, CLOSED, REVERSED` | `<StatusBadge>` display component | No API; static enum |
| Leave Request Status (implied) | HRMS_LEAVE | Implied: `PENDING, APPROVED, REJECTED, CANCELLED, TAKEN` | `<StatusBadge>` display component | No API; static enum |

---

## Appendix A: Schema Tables Summary

| Table | Domain | Primary Key Sequence | Description |
|---|---|---|---|
| `DEPARTMENTS` | Core | `SEQ_DEPARTMENT` | Organization departments and cost centers |
| `LOCATIONS` | Core | `SEQ_LOCATION` | Physical office locations |
| `JOB_GRADES` | Core | `SEQ_JOB_GRADE` | Salary grade bands |
| `JOB_TITLES` | Core | `SEQ_JOB_TITLE` | Job positions linked to grades |
| `EMPLOYEES` | Core | `SEQ_EMPLOYEE` | Master employee records |
| `EMPLOYEE_HISTORY` | Core | `SEQ_EMP_HISTORY` | Employment change log |
| `EMPLOYEE_DEPENDENTS` | Core | `SEQ_DEPENDENT` | Employee dependents |
| `EMERGENCY_CONTACTS` | Core | `SEQ_EMERGENCY_CONTACT` | Emergency contact information |
| `SALARY_RECORDS` | Payroll | `SEQ_SALARY` | Salary history with effective dates |
| `PAY_ELEMENTS` | Payroll | `SEQ_PAY_ELEMENT` | Earning/deduction/tax/benefit types |
| `EMPLOYEE_PAY_ELEMENTS` | Payroll | `SEQ_EMP_PAY_ELEMENT` | Per-employee pay element assignments |
| `PAY_PERIODS` | Payroll | `SEQ_PAY_PERIOD` | Pay period definitions |
| `PAYROLL_RUNS` | Payroll | `SEQ_PAYROLL_RUN` | Payroll run header records |
| `PAYROLL_DETAILS` | Payroll | `SEQ_PAYROLL_DETAIL` | Per-employee per-element pay line items |
| `TAX_BRACKETS` | Payroll | `SEQ_TAX_BRACKET` | Federal/state tax bracket tables |
| `EMPLOYEE_TAX_INFO` | Payroll | (PK: TAX_INFO_ID) | W-4 withholding elections |
| `EMPLOYEE_BANK_ACCOUNTS` | Payroll | (PK: BANK_ACCT_ID) | Direct deposit information |
| `LEAVE_TYPES` | Leave | `SEQ_LEAVE_TYPE` | Leave type definitions with accrual rules |
| `LEAVE_BALANCES` | Leave | `SEQ_LEAVE_BALANCE` | Per-employee per-type annual leave balances |
| `LEAVE_REQUESTS` | Leave | `SEQ_LEAVE_REQUEST` | Leave request records with approval workflow |
| `LEAVE_ACCRUAL_LOG` | Leave | `SEQ_LEAVE_ACCRUAL` | Monthly accrual transaction log |
| `HOLIDAYS` | Leave | `SEQ_HOLIDAY` | Company holidays by location |
| `REVIEW_CYCLES` | Performance | `SEQ_REVIEW_CYCLE` | Annual review cycle definitions |
| `PERFORMANCE_REVIEWS` | Performance | `SEQ_PERF_REVIEW` | Individual performance review records |
| `PERFORMANCE_GOALS` | Performance | `SEQ_PERF_GOAL` | Performance goals linked to reviews |
| `AUDIT_LOG` | System | `SEQ_AUDIT` | Cross-cutting audit trail |
| `SYSTEM_PARAMETERS` | System | `SEQ_SYSTEM_PARAM` | Application configuration key-value store |
| `NOTIFICATION_QUEUE` | System | `SEQ_NOTIFICATION` | Email/SMS/in-app notification queue |
| `USER_SESSIONS` | System | `SEQ_USER_SESSION` | Active session tracking |
| `LOOKUP_VALUES` | System | `SEQ_LOOKUP` | Generic lookup/reference data |

## Appendix B: Views Summary

| View | Source Tables | Purpose | Modern Equivalent |
|---|---|---|---|
| `VW_ACTIVE_EMPLOYEES` | EMPLOYEES, DEPARTMENTS, JOB_TITLES, JOB_GRADES, LOCATIONS, SALARY_RECORDS | Denormalized active employee view with dept, job, manager, salary | JPA `EmployeeDetailProjection` or Spring Data `@Query` with joins |
| `VW_ORG_HIERARCHY` | EMPLOYEES | Hierarchical org chart via CONNECT BY | Recursive CTE or in-memory tree builder; `GET /api/employees/{id}/org-chart` |
| `VW_EMPLOYEE_COMPENSATION` | EMPLOYEES, DEPARTMENTS, JOB_TITLES, JOB_GRADES, SALARY_RECORDS | Compensation details with compa-ratio | `CompensationReportProjection` DTO |
| `VW_LEAVE_SUMMARY` | LEAVE_BALANCES, EMPLOYEES, DEPARTMENTS, LEAVE_TYPES | Current year leave balances with utilization % | `LeaveBalanceSummaryProjection` DTO |
| `VW_PAYROLL_LATEST` | PAYROLL_DETAILS, EMPLOYEES, PAYROLL_RUNS, PAY_PERIODS | Latest approved payroll run per employee | `PayslipSummaryProjection` DTO |
| `VW_PENDING_APPROVALS` | LEAVE_REQUESTS, PERFORMANCE_REVIEWS, EMPLOYEES, LEAVE_TYPES, REVIEW_CYCLES | Unified pending approvals across modules | `PendingApprovalProjection` DTO; `GET /api/approvals/pending` |

## Appendix C: Sequences Summary

| Sequence | Start | Increment | Cache | Used By |
|---|---|---|---|---|
| `SEQ_DEPARTMENT` | 100 | 1 | NOCACHE | DEPARTMENTS.DEPT_ID |
| `SEQ_LOCATION` | 100 | 1 | NOCACHE | LOCATIONS.LOCATION_CODE (if numeric) |
| `SEQ_JOB_GRADE` | 100 | 1 | NOCACHE | JOB_GRADES.GRADE_ID |
| `SEQ_JOB_TITLE` | 100 | 1 | NOCACHE | JOB_TITLES.JOB_ID |
| `SEQ_EMPLOYEE` | 10000 | 1 | NOCACHE | EMPLOYEES.EMP_ID |
| `SEQ_EMP_HISTORY` | 1 | 1 | NOCACHE | EMPLOYEE_HISTORY.HIST_ID |
| `SEQ_DEPENDENT` | 1 | 1 | NOCACHE | EMPLOYEE_DEPENDENTS.DEPENDENT_ID |
| `SEQ_EMERGENCY_CONTACT` | 1 | 1 | NOCACHE | EMERGENCY_CONTACTS.CONTACT_ID |
| `SEQ_EMP_NUMBER` | 1000 | 1 | NOCACHE | EMP_NUMBER generation (race condition: PKG_EMPLOYEE uses MAX()+1 instead) |
| `SEQ_SALARY` | 1 | 1 | NOCACHE | SALARY_RECORDS.SALARY_ID |
| `SEQ_PAY_ELEMENT` | 1 | 1 | NOCACHE | PAY_ELEMENTS.ELEMENT_ID |
| `SEQ_EMP_PAY_ELEMENT` | 1 | 1 | NOCACHE | EMPLOYEE_PAY_ELEMENTS.EMP_ELEMENT_ID |
| `SEQ_PAY_PERIOD` | 1 | 1 | NOCACHE | PAY_PERIODS.PERIOD_ID |
| `SEQ_PAYROLL_RUN` | 1 | 1 | NOCACHE | PAYROLL_RUNS.RUN_ID |
| `SEQ_PAYROLL_DETAIL` | 1 | 1 | NOCACHE | PAYROLL_DETAILS.DETAIL_ID |
| `SEQ_TAX_BRACKET` | 1 | 1 | NOCACHE | TAX_BRACKETS.BRACKET_ID |
| `SEQ_LEAVE_TYPE` | 1 | 1 | NOCACHE | LEAVE_TYPES.LEAVE_TYPE_ID |
| `SEQ_LEAVE_BALANCE` | 1 | 1 | NOCACHE | LEAVE_BALANCES.BALANCE_ID |
| `SEQ_LEAVE_REQUEST` | 1 | 1 | NOCACHE | LEAVE_REQUESTS.REQUEST_ID |
| `SEQ_LEAVE_ACCRUAL` | 1 | 1 | NOCACHE | LEAVE_ACCRUAL_LOG.ACCRUAL_ID |
| `SEQ_HOLIDAY` | 1 | 1 | NOCACHE | HOLIDAYS.HOLIDAY_ID |
| `SEQ_REVIEW_CYCLE` | 1 | 1 | NOCACHE | REVIEW_CYCLES.CYCLE_ID |
| `SEQ_PERF_REVIEW` | 1 | 1 | NOCACHE | PERFORMANCE_REVIEWS.REVIEW_ID |
| `SEQ_PERF_GOAL` | 1 | 1 | NOCACHE | PERFORMANCE_GOALS.GOAL_ID |
| `SEQ_AUDIT` | 1 | 1 | CACHE 100 | AUDIT_LOG.AUDIT_ID |
| `SEQ_NOTIFICATION` | 1 | 1 | NOCACHE | NOTIFICATION_QUEUE.NOTIFICATION_ID |
| `SEQ_USER_SESSION` | 1 | 1 | NOCACHE | USER_SESSIONS.SESSION_ID |
| `SEQ_SYSTEM_PARAM` | 1 | 1 | NOCACHE | SYSTEM_PARAMETERS.PARAM_ID |
| `SEQ_LOOKUP` | 1 | 1 | NOCACHE | LOOKUP_VALUES.LOOKUP_ID |
