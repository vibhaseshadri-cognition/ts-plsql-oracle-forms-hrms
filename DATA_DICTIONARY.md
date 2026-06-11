# Data Dictionary — Oracle Forms/PL/SQL HRMS Estate

## Overview

| Domain | Table Count | Description |
|--------|------------|-------------|
| Employee | 8 | Core employee data, org structure, job hierarchy |
| Payroll | 9 | Compensation, pay periods, tax, banking |
| Leave | 5 | Leave types, balances, requests, accruals, holidays |
| Performance | 3 | Review cycles, reviews, goals |
| Security | 1 | User session tracking |
| System | 4 | Audit, configuration, notifications, lookups |
| **Total** | **30** | |

**Schema**: `HRMS` on Oracle Database 19c

**Conventions**:
- All tables use surrogate numeric primary keys from sequences
- Audit columns (`CREATED_BY`, `CREATED_DATE`, `MODIFIED_BY`, `MODIFIED_DATE`) on all mutable tables
- Soft-delete via `ACTIVE_FLAG CHAR(1) DEFAULT 'Y'` where applicable
- Encrypted columns suffixed with `_ENCRYPTED` or `_ENC`

---

## 1. Employee Domain

### 1.1 DEPARTMENTS

Organization departments and cost centers. Supports hierarchy via self-referencing FK.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| DEPT_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| DEPT_CODE | VARCHAR2(20) | UK, NOT NULL | Short department code |
| DEPT_NAME | VARCHAR2(100) | NOT NULL | Full department name |
| PARENT_DEPT_ID | NUMBER(10) | FK → DEPARTMENTS.DEPT_ID | Parent department for hierarchy |
| COST_CENTER | VARCHAR2(20) | | Financial cost center code for GL integration |
| MANAGER_EMP_ID | NUMBER(10) | FK → EMPLOYEES.EMP_ID | Department manager |
| LOCATION_CODE | VARCHAR2(10) | FK → LOCATIONS.LOCATION_CODE | Physical location |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y', CHECK IN ('Y','N') | Soft-delete flag |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit: creating user |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit: creation timestamp |
| MODIFIED_BY | VARCHAR2(30) | | Audit: last modifier |
| MODIFIED_DATE | DATE | | Audit: last modification |

**Relationships**: Self-referencing (PARENT_DEPT_ID), references EMPLOYEES (manager), LOCATIONS.
**Audit Trigger**: TRG_DEPARTMENT_AUDIT logs all changes.

---

### 1.2 LOCATIONS

Physical office locations with address and timezone data.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| LOCATION_CODE | VARCHAR2(10) | PK, NOT NULL | Natural key (e.g., 'HQ', 'CHI', 'SF') |
| LOCATION_NAME | VARCHAR2(100) | NOT NULL | Full location name |
| ADDRESS_LINE1 | VARCHAR2(200) | | Street address |
| ADDRESS_LINE2 | VARCHAR2(200) | | Suite/floor |
| CITY | VARCHAR2(100) | | City |
| STATE_PROVINCE | VARCHAR2(100) | | State or province |
| POSTAL_CODE | VARCHAR2(20) | | ZIP/postal code |
| COUNTRY_CODE | VARCHAR2(3) | | ISO country code |
| PHONE_NUMBER | VARCHAR2(30) | | Office phone |
| TIMEZONE | VARCHAR2(50) | DEFAULT 'America/New_York' | IANA timezone |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete flag |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

### 1.3 JOB_GRADES

Salary grade bands for compensation management.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| GRADE_ID | NUMBER(5) | PK, NOT NULL | Surrogate key |
| GRADE_CODE | VARCHAR2(10) | UK, NOT NULL | Short grade code |
| GRADE_NAME | VARCHAR2(50) | NOT NULL | Grade label (e.g., 'Entry Level', 'Senior') |
| MIN_SALARY | NUMBER(12,2) | NOT NULL | Minimum salary for grade |
| MAX_SALARY | NUMBER(12,2) | NOT NULL, CHECK (MAX >= MIN) | Maximum salary for grade |
| OVERTIME_ELIGIBLE | CHAR(1) | DEFAULT 'N' | FLSA overtime eligibility |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

**Constraint**: CHK_SALARY_RANGE ensures MAX_SALARY >= MIN_SALARY.

---

### 1.4 JOB_TITLES

Job positions linked to salary grades.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| JOB_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| JOB_CODE | VARCHAR2(20) | UK, NOT NULL | Short job code |
| JOB_TITLE | VARCHAR2(100) | NOT NULL | Full title |
| JOB_FAMILY | VARCHAR2(50) | | Job family grouping |
| GRADE_ID | NUMBER(5) | FK → JOB_GRADES.GRADE_ID, NOT NULL | Salary grade |
| EEO_CATEGORY | VARCHAR2(10) | | EEO reporting category |
| FLSA_STATUS | VARCHAR2(10) | DEFAULT 'EXEMPT' | FLSA classification |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

**Relationships**: FK to JOB_GRADES.

---

### 1.5 EMPLOYEES

Master employee records — core entity of the HRMS system.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| EMP_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| EMP_NUMBER | VARCHAR2(20) | UK, NOT NULL | Business key (format: EMP-XXXXXX) |
| FIRST_NAME | VARCHAR2(50) | NOT NULL | First name |
| MIDDLE_NAME | VARCHAR2(50) | | Middle name |
| LAST_NAME | VARCHAR2(50) | NOT NULL | Last name |
| DATE_OF_BIRTH | DATE | | DOB |
| GENDER | CHAR(1) | CHECK IN ('M','F','O') | Gender code |
| MARITAL_STATUS | VARCHAR2(10) | | SINGLE/MARRIED/DIVORCED/WIDOWED |
| NATIONALITY | VARCHAR2(50) | | Nationality |
| SSN_ENCRYPTED | VARCHAR2(200) | | AES-256 encrypted SSN (decrypted only in PKG_SECURITY) |
| EMAIL | VARCHAR2(100) | | Work email address |
| PHONE_WORK | VARCHAR2(30) | | Work phone |
| PHONE_MOBILE | VARCHAR2(30) | | Mobile phone |
| ADDRESS_LINE1 | VARCHAR2(200) | | Street address |
| ADDRESS_LINE2 | VARCHAR2(200) | | Suite/apt |
| CITY | VARCHAR2(100) | | City |
| STATE_PROVINCE | VARCHAR2(100) | | State/province |
| POSTAL_CODE | VARCHAR2(20) | | ZIP code |
| COUNTRY_CODE | VARCHAR2(3) | | ISO country code |
| HIRE_DATE | DATE | NOT NULL | Original hire date |
| TERMINATION_DATE | DATE | | Termination date (NULL if active) |
| TERMINATION_REASON | VARCHAR2(50) | | Reason for termination |
| DEPT_ID | NUMBER(10) | FK → DEPARTMENTS, NOT NULL | Current department |
| JOB_ID | NUMBER(10) | FK → JOB_TITLES, NOT NULL | Current job title |
| MANAGER_EMP_ID | NUMBER(10) | FK → EMPLOYEES (self-ref) | Direct manager |
| LOCATION_CODE | VARCHAR2(10) | FK → LOCATIONS | Work location |
| EMPLOYMENT_TYPE | VARCHAR2(20) | DEFAULT 'FULL_TIME', CHECK | FULL_TIME/PART_TIME/CONTRACT/INTERN |
| EMPLOYMENT_STATUS | VARCHAR2(20) | DEFAULT 'ACTIVE', CHECK | ACTIVE/ON_LEAVE/SUSPENDED/TERMINATED |
| PHOTO_BLOB | BLOB | | Employee photo |
| NOTES | CLOB | | Free-text notes |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

**Relationships**: FK to DEPARTMENTS, JOB_TITLES, LOCATIONS. Self-referencing FK for MANAGER_EMP_ID.
**Triggers**: TRG_EMP_BEFORE_INSERT, TRG_EMP_BEFORE_UPDATE, TRG_EMP_INSTEAD_OF_DELETE.
**Notes**: SSN_ENCRYPTED uses AES-256 via PKG_SECURITY. Physical deletion is blocked by trigger.

---

### 1.6 EMPLOYEE_HISTORY

Change log for employee status, department, job, salary, and location changes.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| HIST_ID | NUMBER(15) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Employee reference |
| CHANGE_TYPE | VARCHAR2(30) | NOT NULL, CHECK | HIRE/TRANSFER/PROMOTION/DEMOTION/SALARY_CHANGE/TERMINATION/REHIRE/LEAVE_START/LEAVE_END/STATUS_CHANGE |
| EFFECTIVE_DATE | DATE | NOT NULL | When change took effect |
| OLD_DEPT_ID | NUMBER(10) | | Previous department |
| NEW_DEPT_ID | NUMBER(10) | | New department |
| OLD_JOB_ID | NUMBER(10) | | Previous job |
| NEW_JOB_ID | NUMBER(10) | | New job |
| OLD_MANAGER_ID | NUMBER(10) | | Previous manager |
| NEW_MANAGER_ID | NUMBER(10) | | New manager |
| OLD_SALARY | NUMBER(12,2) | | Previous salary |
| NEW_SALARY | NUMBER(12,2) | | New salary |
| OLD_LOCATION | VARCHAR2(10) | | Previous location |
| NEW_LOCATION | VARCHAR2(10) | | New location |
| REASON_CODE | VARCHAR2(30) | | Reason code |
| COMMENTS | VARCHAR2(4000) | | Free-text comments |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |

---

### 1.7 EMPLOYEE_DEPENDENTS

Employee dependents for benefits enrollment.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| DEPENDENT_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Parent employee |
| FIRST_NAME | VARCHAR2(50) | NOT NULL | Dependent first name |
| LAST_NAME | VARCHAR2(50) | NOT NULL | Dependent last name |
| RELATIONSHIP | VARCHAR2(20) | NOT NULL, CHECK | SPOUSE/CHILD/PARENT/DOMESTIC_PARTNER/OTHER |
| DATE_OF_BIRTH | DATE | | DOB |
| SSN_ENCRYPTED | VARCHAR2(200) | | Encrypted SSN |
| BENEFITS_ENROLLED | CHAR(1) | DEFAULT 'N' | Enrolled in benefits |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

### 1.8 EMERGENCY_CONTACTS

Employee emergency contact information.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| CONTACT_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Employee reference |
| CONTACT_NAME | VARCHAR2(100) | NOT NULL | Contact full name |
| RELATIONSHIP | VARCHAR2(30) | | Relationship to employee |
| PHONE_PRIMARY | VARCHAR2(30) | NOT NULL | Primary phone |
| PHONE_SECONDARY | VARCHAR2(30) | | Secondary phone |
| EMAIL | VARCHAR2(100) | | Email address |
| PRIORITY_ORDER | NUMBER(2) | DEFAULT 1 | Contact priority ordering |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete flag |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

## 2. Payroll Domain

### 2.1 SALARY_RECORDS

Employee salary history with effective dating. Only one record active (ACTIVE_FLAG='Y') per employee at a time.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| SALARY_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Employee reference |
| EFFECTIVE_DATE | DATE | NOT NULL | Salary effective date |
| END_DATE | DATE | | End date (NULL if current) |
| BASE_SALARY | NUMBER(12,2) | NOT NULL | Annual or hourly salary amount |
| CURRENCY_CODE | VARCHAR2(3) | DEFAULT 'USD' | ISO currency code |
| PAY_FREQUENCY | VARCHAR2(20) | DEFAULT 'MONTHLY', CHECK | WEEKLY/BIWEEKLY/SEMIMONTHLY/MONTHLY |
| SALARY_BASIS | VARCHAR2(20) | DEFAULT 'ANNUAL', CHECK | ANNUAL/HOURLY |
| CHANGE_REASON | VARCHAR2(50) | | Reason for salary change |
| CHANGE_PCT | NUMBER(5,2) | | Percentage change from prior |
| APPROVED_BY | NUMBER(10) | | Approver employee ID |
| APPROVAL_DATE | DATE | | Approval date |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Current active record |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

**Audit Trigger**: TRG_SALARY_AUDIT logs all changes for compliance.

---

### 2.2 PAY_ELEMENTS

Definition of pay element types (earnings, deductions, taxes, benefits, reimbursements).

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| ELEMENT_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| ELEMENT_CODE | VARCHAR2(30) | UK, NOT NULL | Element code |
| ELEMENT_NAME | VARCHAR2(100) | NOT NULL | Display name |
| ELEMENT_TYPE | VARCHAR2(20) | NOT NULL, CHECK | EARNING/DEDUCTION/TAX/BENEFIT/REIMBURSEMENT |
| CALCULATION_TYPE | VARCHAR2(20) | NOT NULL, CHECK | FLAT/PERCENTAGE/HOURS/FORMULA |
| DEFAULT_AMOUNT | NUMBER(12,2) | | Default flat amount |
| DEFAULT_PERCENTAGE | NUMBER(5,2) | | Default percentage |
| TAXABLE_FLAG | CHAR(1) | DEFAULT 'Y' | Subject to tax |
| PRETAX_FLAG | CHAR(1) | DEFAULT 'N' | Pre-tax deduction |
| EMPLOYER_PAID | CHAR(1) | DEFAULT 'N' | Employer-paid benefit |
| GL_ACCOUNT_CODE | VARCHAR2(30) | | General ledger account code |
| PRIORITY_ORDER | NUMBER(5) | DEFAULT 100 | Calculation order |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

### 2.3 EMPLOYEE_PAY_ELEMENTS

Employee-level overrides for pay elements (effective-dated).

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| EMP_ELEMENT_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Employee |
| ELEMENT_ID | NUMBER(10) | FK → PAY_ELEMENTS, NOT NULL | Pay element |
| EFFECTIVE_DATE | DATE | NOT NULL | Effective start |
| END_DATE | DATE | | Effective end |
| AMOUNT | NUMBER(12,2) | | Override amount |
| PERCENTAGE | NUMBER(5,2) | | Override percentage |
| OVERRIDE_AMOUNT | NUMBER(12,2) | | Manual override |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

### 2.4 PAY_PERIODS

Pay period definitions for payroll processing.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| PERIOD_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| PERIOD_NAME | VARCHAR2(50) | NOT NULL | Display name (e.g., '2024-01 (Jan)') |
| PAY_FREQUENCY | VARCHAR2(20) | NOT NULL | WEEKLY/BIWEEKLY/SEMIMONTHLY/MONTHLY |
| PERIOD_START_DATE | DATE | NOT NULL | Period start |
| PERIOD_END_DATE | DATE | NOT NULL | Period end |
| PAY_DATE | DATE | NOT NULL | Check/deposit date |
| STATUS | VARCHAR2(20) | DEFAULT 'OPEN', CHECK | OPEN/PROCESSING/CLOSED/REVERSED |
| CLOSED_BY | VARCHAR2(30) | | User who closed period |
| CLOSED_DATE | DATE | | Close timestamp |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

### 2.5 PAYROLL_RUNS

Individual payroll run execution records within a pay period.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| RUN_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| PERIOD_ID | NUMBER(10) | FK → PAY_PERIODS, NOT NULL | Associated period |
| RUN_TYPE | VARCHAR2(20) | DEFAULT 'REGULAR', CHECK | REGULAR/SUPPLEMENTAL/BONUS/FINAL |
| RUN_DATE | DATE | NOT NULL | Run execution date |
| STATUS | VARCHAR2(20) | DEFAULT 'PENDING', CHECK | PENDING/CALCULATING/CALCULATED/APPROVED/PAID/REVERSED/ERROR |
| TOTAL_GROSS | NUMBER(15,2) | | Sum of gross pay |
| TOTAL_DEDUCTIONS | NUMBER(15,2) | | Sum of deductions |
| TOTAL_NET | NUMBER(15,2) | | Sum of net pay |
| TOTAL_EMPLOYER_COST | NUMBER(15,2) | | Total employer cost |
| EMPLOYEE_COUNT | NUMBER(10) | | Employees in run |
| ERROR_COUNT | NUMBER(10) | DEFAULT 0 | Error count |
| SUBMITTED_BY | VARCHAR2(30) | | Submitter |
| SUBMITTED_DATE | DATE | | Submission time |
| APPROVED_BY | VARCHAR2(30) | | Approver |
| APPROVED_DATE | DATE | | Approval time |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

### 2.6 PAYROLL_DETAILS

Line-item payroll calculations per employee per pay element per run.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| DETAIL_ID | NUMBER(15) | PK, NOT NULL | Surrogate key |
| RUN_ID | NUMBER(10) | FK → PAYROLL_RUNS, NOT NULL | Payroll run |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Employee |
| ELEMENT_ID | NUMBER(10) | FK → PAY_ELEMENTS, NOT NULL | Pay element |
| ELEMENT_TYPE | VARCHAR2(20) | NOT NULL | EARNING/DEDUCTION/TAX/BENEFIT |
| HOURS_WORKED | NUMBER(6,2) | | Hours (for hourly employees) |
| RATE | NUMBER(12,4) | | Rate applied |
| AMOUNT | NUMBER(12,2) | NOT NULL | Calculated amount |
| YTD_AMOUNT | NUMBER(15,2) | | Year-to-date accumulation |
| STATUS | VARCHAR2(20) | DEFAULT 'CALCULATED' | Line status |
| ERROR_MESSAGE | VARCHAR2(4000) | | Error details if failed |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |

---

### 2.7 TAX_BRACKETS

Federal and state tax bracket definitions by year and filing status.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| BRACKET_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| TAX_YEAR | NUMBER(4) | NOT NULL | Tax year |
| FILING_STATUS | VARCHAR2(30) | NOT NULL, CHECK | SINGLE/MARRIED_JOINT/MARRIED_SEPARATE/HEAD_OF_HOUSEHOLD |
| BRACKET_MIN | NUMBER(12,2) | NOT NULL | Bracket lower bound |
| BRACKET_MAX | NUMBER(12,2) | | Bracket upper bound (NULL for highest) |
| TAX_RATE | NUMBER(5,4) | NOT NULL | Marginal tax rate |
| BASE_TAX | NUMBER(12,2) | DEFAULT 0 | Cumulative base tax |
| STATE_CODE | VARCHAR2(3) | | State code (NULL for federal) |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |

---

### 2.8 EMPLOYEE_TAX_INFO

Employee W-4 withholding elections per tax year.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| TAX_INFO_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Employee |
| TAX_YEAR | NUMBER(4) | NOT NULL | Tax year |
| FILING_STATUS | VARCHAR2(30) | NOT NULL | W-4 filing status |
| FEDERAL_ALLOWANCES | NUMBER(3) | DEFAULT 0 | Federal allowances |
| STATE_ALLOWANCES | NUMBER(3) | DEFAULT 0 | State allowances |
| ADDITIONAL_FED_WH | NUMBER(12,2) | DEFAULT 0 | Additional federal withholding |
| ADDITIONAL_STATE_WH | NUMBER(12,2) | DEFAULT 0 | Additional state withholding |
| EXEMPT_FLAG | CHAR(1) | DEFAULT 'N' | Exempt from withholding |
| STATE_CODE | VARCHAR2(3) | | State of residence |
| W4_RECEIVED_DATE | DATE | | Date W-4 received |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

**Unique Constraint**: (EMP_ID, TAX_YEAR)

---

### 2.9 EMPLOYEE_BANK_ACCOUNTS

Direct deposit bank account information. Account numbers are encrypted.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| BANK_ACCT_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Employee |
| BANK_NAME | VARCHAR2(100) | | Bank name |
| ROUTING_NUMBER | VARCHAR2(20) | NOT NULL | ABA routing number |
| ACCOUNT_NUMBER_ENC | VARCHAR2(200) | NOT NULL | Encrypted account number |
| ACCOUNT_TYPE | VARCHAR2(20) | DEFAULT 'CHECKING', CHECK | CHECKING/SAVINGS |
| DEPOSIT_TYPE | VARCHAR2(20) | DEFAULT 'FULL', CHECK | FULL/PARTIAL_AMOUNT/PARTIAL_PERCENT/REMAINDER |
| DEPOSIT_AMOUNT | NUMBER(12,2) | | Fixed deposit amount |
| DEPOSIT_PERCENTAGE | NUMBER(5,2) | | Deposit percentage |
| PRIORITY_ORDER | NUMBER(2) | DEFAULT 1 | Deposit order |
| PRENOTE_SENT | CHAR(1) | DEFAULT 'N' | Pre-notification sent |
| PRENOTE_DATE | DATE | | Pre-notification date |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

**Note**: ACCOUNT_NUMBER_ENC is encrypted at rest.

---

## 3. Leave Domain

### 3.1 LEAVE_TYPES

Leave type definitions with accrual rules.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| LEAVE_TYPE_ID | NUMBER(5) | PK, NOT NULL | Surrogate key |
| LEAVE_TYPE_CODE | VARCHAR2(20) | UK, NOT NULL | Type code (e.g., 'PTO', 'SICK') |
| LEAVE_TYPE_NAME | VARCHAR2(50) | NOT NULL | Display name |
| PAID_FLAG | CHAR(1) | DEFAULT 'Y' | Paid or unpaid leave |
| ACCRUAL_FLAG | CHAR(1) | DEFAULT 'Y' | Subject to accrual |
| ACCRUAL_RATE | NUMBER(6,2) | | Hours/days accrued per period |
| ACCRUAL_FREQUENCY | VARCHAR2(20) | CHECK | MONTHLY/BIWEEKLY/ANNUAL/NULL |
| MAX_BALANCE | NUMBER(6,2) | | Maximum accrual cap |
| CARRYOVER_MAX | NUMBER(6,2) | | Max carryover to next year |
| CARRYOVER_EXPIRY | NUMBER(3) | | Days until carryover expires |
| MIN_TENURE_DAYS | NUMBER(5) | DEFAULT 0 | Minimum tenure to be eligible |
| REQUIRES_APPROVAL | CHAR(1) | DEFAULT 'Y' | Requires manager approval |
| REQUIRES_DOCUMENT | CHAR(1) | DEFAULT 'N' | Requires supporting document |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

### 3.2 LEAVE_BALANCES

Per-employee, per-leave-type, per-year balance tracking. Includes a virtual column for available balance.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| BALANCE_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Employee |
| LEAVE_TYPE_ID | NUMBER(5) | FK → LEAVE_TYPES, NOT NULL | Leave type |
| CALENDAR_YEAR | NUMBER(4) | NOT NULL | Balance year |
| OPENING_BALANCE | NUMBER(6,2) | DEFAULT 0 | Carried-forward balance |
| ACCRUED | NUMBER(6,2) | DEFAULT 0 | Accrued during year |
| USED | NUMBER(6,2) | DEFAULT 0 | Used/taken |
| ADJUSTMENT | NUMBER(6,2) | DEFAULT 0 | Manual adjustments |
| PENDING | NUMBER(6,2) | DEFAULT 0 | Pending approval requests |
| AVAILABLE | NUMBER(6,2) | **VIRTUAL** | `OPENING_BALANCE + ACCRUED - USED + ADJUSTMENT - PENDING` |
| CARRYOVER_FROM_PREV | NUMBER(6,2) | DEFAULT 0 | Carryover from previous year |
| CARRYOVER_EXPIRY_DT | DATE | | Carryover expiry date |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

**Unique Constraint**: (EMP_ID, LEAVE_TYPE_ID, CALENDAR_YEAR)
**Note**: AVAILABLE is a `GENERATED ALWAYS AS ... VIRTUAL` column — not stored, computed on read.

---

### 3.3 LEAVE_REQUESTS

Individual leave request records with approval workflow.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| REQUEST_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Requestor |
| LEAVE_TYPE_ID | NUMBER(5) | FK → LEAVE_TYPES, NOT NULL | Leave type |
| START_DATE | DATE | NOT NULL | Leave start |
| END_DATE | DATE | NOT NULL, CHECK (END >= START) | Leave end |
| TOTAL_DAYS | NUMBER(5,1) | NOT NULL | Total leave days |
| HALF_DAY_FLAG | CHAR(1) | DEFAULT 'N' | Half-day request |
| HALF_DAY_PERIOD | VARCHAR2(10) | CHECK IN ('AM','PM',NULL) | AM or PM half-day |
| STATUS | VARCHAR2(20) | DEFAULT 'PENDING', CHECK | PENDING/APPROVED/REJECTED/CANCELLED/TAKEN |
| REASON | VARCHAR2(4000) | | Leave reason |
| SUPPORTING_DOC_PATH | VARCHAR2(500) | | Document path |
| APPROVER_EMP_ID | NUMBER(10) | FK → EMPLOYEES | Approver |
| APPROVAL_DATE | DATE | | Approval/rejection date |
| APPROVAL_COMMENTS | VARCHAR2(4000) | | Approver comments |
| CANCEL_REASON | VARCHAR2(4000) | | Cancellation reason |
| CANCELLED_DATE | DATE | | Cancellation date |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

**Audit Trigger**: TRG_LEAVE_REQUEST_AUDIT logs status changes.

---

### 3.4 LEAVE_ACCRUAL_LOG

Audit trail for leave accrual calculations.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| ACCRUAL_ID | NUMBER(15) | PK, NOT NULL | Surrogate key |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Employee |
| LEAVE_TYPE_ID | NUMBER(5) | FK → LEAVE_TYPES, NOT NULL | Leave type |
| ACCRUAL_DATE | DATE | NOT NULL | Date of accrual |
| ACCRUAL_AMOUNT | NUMBER(6,2) | NOT NULL | Amount accrued |
| BALANCE_AFTER | NUMBER(6,2) | | Balance post-accrual |
| RUN_ID | NUMBER(10) | | Batch run ID |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |

---

### 3.5 HOLIDAYS

Company holidays, optionally location-specific.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| HOLIDAY_ID | NUMBER(5) | PK, NOT NULL | Surrogate key |
| HOLIDAY_DATE | DATE | NOT NULL | Holiday date |
| HOLIDAY_NAME | VARCHAR2(100) | NOT NULL | Holiday name |
| LOCATION_CODE | VARCHAR2(10) | | NULL = company-wide; value = location-specific |
| FLOATING_FLAG | CHAR(1) | DEFAULT 'N' | Floating holiday |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |

---

## 4. Performance Domain

### 4.1 REVIEW_CYCLES

Performance review cycle definitions.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| CYCLE_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| CYCLE_NAME | VARCHAR2(100) | NOT NULL | Cycle name (e.g., 'FY2024 Annual Review') |
| CYCLE_YEAR | NUMBER(4) | NOT NULL | Review year |
| START_DATE | DATE | NOT NULL | Cycle start |
| END_DATE | DATE | NOT NULL | Cycle end |
| SELF_REVIEW_DUE | DATE | | Self-review deadline |
| MANAGER_REVIEW_DUE | DATE | | Manager review deadline |
| CALIBRATION_DUE | DATE | | Calibration deadline |
| STATUS | VARCHAR2(20) | DEFAULT 'DRAFT', CHECK | DRAFT/OPEN/IN_PROGRESS/CALIBRATION/CLOSED |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

### 4.2 PERFORMANCE_REVIEWS

Individual employee performance review records.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| REVIEW_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| CYCLE_ID | NUMBER(10) | FK → REVIEW_CYCLES, NOT NULL | Review cycle |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Reviewee |
| REVIEWER_EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Reviewer (manager) |
| REVIEW_TYPE | VARCHAR2(20) | DEFAULT 'ANNUAL' | ANNUAL review type |
| STATUS | VARCHAR2(20) | DEFAULT 'NOT_STARTED', CHECK | NOT_STARTED/SELF_REVIEW/MANAGER_REVIEW/MEETING_SCHEDULED/COMPLETED/ACKNOWLEDGED |
| OVERALL_RATING | NUMBER(2,1) | CHECK BETWEEN 1.0 AND 5.0 | Final rating |
| RATING_LABEL | VARCHAR2(50) | | Derived label (Exceptional/Exceeds/Meets/Needs Improvement/Unsatisfactory) |
| SELF_ASSESSMENT | CLOB | | Employee self-assessment |
| MANAGER_ASSESSMENT | CLOB | | Manager assessment |
| STRENGTHS | CLOB | | Documented strengths |
| AREAS_FOR_IMPROVEMENT | CLOB | | Areas for improvement |
| DEVELOPMENT_PLAN | CLOB | | Development plan |
| EMPLOYEE_COMMENTS | CLOB | | Employee acknowledgment comments |
| EMPLOYEE_ACK_DATE | DATE | | Acknowledgment date |
| CALIBRATED_RATING | NUMBER(2,1) | | Post-calibration adjusted rating |
| CALIBRATION_NOTES | VARCHAR2(4000) | | Calibration justification |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

### 4.3 PERFORMANCE_GOALS

Individual goals tied to performance reviews.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| GOAL_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| REVIEW_ID | NUMBER(10) | FK → PERFORMANCE_REVIEWS, NOT NULL | Parent review |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Goal owner |
| GOAL_TITLE | VARCHAR2(200) | NOT NULL | Goal title |
| GOAL_DESCRIPTION | CLOB | | Detailed description |
| GOAL_CATEGORY | VARCHAR2(30) | CHECK | BUSINESS/DEVELOPMENT/LEADERSHIP/INNOVATION/COMPLIANCE |
| WEIGHT_PCT | NUMBER(5,2) | DEFAULT 0 | Goal weight percentage |
| TARGET_DATE | DATE | | Target completion date |
| STATUS | VARCHAR2(20) | DEFAULT 'NOT_STARTED', CHECK | NOT_STARTED/IN_PROGRESS/COMPLETED/DEFERRED/CANCELLED |
| PROGRESS_PCT | NUMBER(5,2) | DEFAULT 0 | Progress percentage |
| SELF_RATING | NUMBER(2,1) | | Employee self-rating |
| MANAGER_RATING | NUMBER(2,1) | | Manager rating |
| COMMENTS | CLOB | | Progress comments |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

---

## 5. Security Domain

### 5.1 USER_SESSIONS

Forms-specific session tracking for authentication.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| SESSION_ID | NUMBER(15) | PK, NOT NULL | Surrogate key (also used as session token) |
| EMP_ID | NUMBER(10) | FK → EMPLOYEES, NOT NULL | Authenticated employee |
| USERNAME | VARCHAR2(30) | NOT NULL | Login username |
| LOGIN_TIME | DATE | NOT NULL | Session start |
| LOGOUT_TIME | DATE | | Session end (NULL if active) |
| IP_ADDRESS | VARCHAR2(50) | | Client IP address |
| FORMS_MODULE | VARCHAR2(100) | | Current forms module name |
| SESSION_STATUS | VARCHAR2(20) | DEFAULT 'ACTIVE' | ACTIVE/EXPIRED/TERMINATED |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |

---

## 6. System Domain

### 6.1 AUDIT_LOG

Centralized audit trail for all DML operations across the system.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| AUDIT_ID | NUMBER(15) | PK, NOT NULL | Surrogate key (SEQ_AUDIT with CACHE 100) |
| TABLE_NAME | VARCHAR2(60) | NOT NULL | Affected table |
| RECORD_ID | NUMBER(15) | NOT NULL | Affected record PK |
| ACTION_TYPE | VARCHAR2(10) | NOT NULL, CHECK | INSERT/UPDATE/DELETE |
| OLD_VALUES | CLOB | | JSON of previous values |
| NEW_VALUES | CLOB | | JSON of new values |
| CHANGED_BY | VARCHAR2(30) | NOT NULL | User who made the change |
| CHANGED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Change timestamp |
| IP_ADDRESS | VARCHAR2(50) | | Client IP from SYS_CONTEXT |
| SESSION_ID | VARCHAR2(100) | | Oracle session ID from SYS_CONTEXT |

---

### 6.2 SYSTEM_PARAMETERS

Application configuration key-value store, grouped by category.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| PARAM_ID | NUMBER(5) | PK, NOT NULL | Surrogate key |
| PARAM_GROUP | VARCHAR2(50) | NOT NULL | Parameter group |
| PARAM_CODE | VARCHAR2(50) | NOT NULL | Parameter code |
| PARAM_VALUE | VARCHAR2(4000) | NOT NULL | Parameter value |
| PARAM_DESCRIPTION | VARCHAR2(200) | | Human-readable description |
| DATA_TYPE | VARCHAR2(20) | DEFAULT 'VARCHAR2' | Expected data type |
| EDITABLE_FLAG | CHAR(1) | DEFAULT 'Y' | User-editable flag |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |
| MODIFIED_BY | VARCHAR2(30) | | Audit |
| MODIFIED_DATE | DATE | | Audit |

**Unique Constraint**: (PARAM_GROUP, PARAM_CODE)

---

### 6.3 NOTIFICATION_QUEUE

Asynchronous notification queue for email, SMS, and in-app messages.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| NOTIFICATION_ID | NUMBER(15) | PK, NOT NULL | Surrogate key |
| RECIPIENT_EMP_ID | NUMBER(10) | | Recipient employee |
| RECIPIENT_EMAIL | VARCHAR2(100) | | Resolved email address |
| NOTIFICATION_TYPE | VARCHAR2(30) | NOT NULL, CHECK | EMAIL/IN_APP/SMS |
| SUBJECT | VARCHAR2(200) | NOT NULL | Message subject |
| BODY | CLOB | NOT NULL | Message body |
| STATUS | VARCHAR2(20) | DEFAULT 'PENDING', CHECK | PENDING/SENT/FAILED/CANCELLED |
| PRIORITY | NUMBER(2) | DEFAULT 5 | Priority (1=highest) |
| SENT_DATE | DATE | | Sent timestamp |
| ERROR_MESSAGE | VARCHAR2(4000) | | Error details on failure |
| RETRY_COUNT | NUMBER(3) | DEFAULT 0 | Retry attempts |
| REFERENCE_TABLE | VARCHAR2(60) | | Source table for context |
| REFERENCE_ID | NUMBER(15) | | Source record ID |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |

---

### 6.4 LOOKUP_VALUES

Generic lookup table for dropdown lists and coded values.

| Column | Data Type | Constraints | Description |
|--------|-----------|-------------|-------------|
| LOOKUP_ID | NUMBER(10) | PK, NOT NULL | Surrogate key |
| LOOKUP_TYPE | VARCHAR2(50) | NOT NULL | Lookup category |
| LOOKUP_CODE | VARCHAR2(50) | NOT NULL | Code value |
| LOOKUP_VALUE | VARCHAR2(200) | NOT NULL | Display value |
| DISPLAY_ORDER | NUMBER(5) | DEFAULT 0 | Sort order |
| PARENT_LOOKUP_ID | NUMBER(10) | | Cascading lookup parent |
| ACTIVE_FLAG | CHAR(1) | NOT NULL, DEFAULT 'Y' | Soft-delete |
| CREATED_BY | VARCHAR2(30) | NOT NULL | Audit |
| CREATED_DATE | DATE | NOT NULL, DEFAULT SYSDATE | Audit |

**Unique Constraint**: (LOOKUP_TYPE, LOOKUP_CODE)

---

## 7. Sequences

All sequences use `INCREMENT BY 1` and `NOCACHE` unless noted.

| Sequence | Used By | Start | Notes |
|----------|---------|-------|-------|
| SEQ_AUDIT | AUDIT_LOG | 1 | **CACHE 100** (high-volume) |
| SEQ_EMP_NUMBER | Intended for employee numbers | 1000 | **Unused** — PKG_EMPLOYEE uses MAX()+1 instead (race condition) |
| All others | Respective tables | 1 or 100 | NOCACHE — performance consideration |

---

## 8. Views

| View | Purpose | Key Joins |
|------|---------|-----------|
| VW_ACTIVE_EMPLOYEES | Active employees with dept, job, manager, location, salary | EMPLOYEES → DEPARTMENTS → JOB_TITLES → JOB_GRADES → LOCATIONS → SALARY_RECORDS |
| VW_ORG_HIERARCHY | Hierarchical org chart via CONNECT BY | EMPLOYEES (self-join) |
| VW_EMPLOYEE_COMPENSATION | Compensation with compa-ratio | EMPLOYEES → DEPARTMENTS → JOB_TITLES → JOB_GRADES → SALARY_RECORDS |
| VW_LEAVE_SUMMARY | Current-year leave balances | LEAVE_BALANCES → EMPLOYEES → DEPARTMENTS → LEAVE_TYPES |
| VW_PAYROLL_LATEST | Latest payroll details | PAYROLL_DETAILS → EMPLOYEES → PAYROLL_RUNS → PAY_PERIODS |
| VW_PENDING_APPROVALS | Unified pending approvals (leave + performance) | LEAVE_REQUESTS ∪ PERFORMANCE_REVIEWS |
