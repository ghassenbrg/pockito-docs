# Pockito — Cursor Agent Step-by-Step Prompts (v3, Full Detail)

> **Usage**: Paste **one step at a time** into Cursor Agent. Each step must:
> 1) Load `/pockito-docs/Pockito_Master_Context.md` and follow it strictly.
> 2) Make **atomic** changes.
> 3) Return a **unified diff**, a **Conventional Commit** message, and **validation results** (pass/fail).  
> 4) If checks fail, fix within the same step.

**Validation commands** (run every step unless stated):  
- Backend: `mvn -q -DskipITs clean verify`  
- Frontend: `npm ci && npm run lint && npm test -- --watch=false`

---

## Phase A — Bootstrap & Infra

**A0 — Add Master Context (v3)**
> Create `/pockito-docs/Pockito_Master_Context.md` with the exact content provided. Update root `README.md` to link it. Output unified diff. Commit `docs: add master context v3`.

**A1 — Monorepo Init**
> Create `/pockito-core`, `/pockito-ui`, `/pockito-infra`, `/pockito-docs`. Add root `.gitignore` (Java, Node, IDE). Add `README.md` that links to the Master Context and describes stack & dev commands. Provide tree + diff. Commit `chore: init monorepo structure`.

**A2 — Docker Compose & Env**
> Add `/pockito-infra/docker-compose.yml` and `/pockito-infra/.env.example` exactly as in Master Context §7. Startability and healthchecks required. Commit `chore(infra): add postgres and keycloak compose`.

**A3 — Keycloak Realm Placeholder**
> Add `/pockito-infra/keycloak/realm-pockito.json` (from MC §7.3). Update README with import steps. Commit `docs(infra): add keycloak realm placeholder`.

**A4 — Backend Scaffold**
> Scaffold Spring Boot 3.3 (Java 21) in `/pockito-core`. Add `pom.xml` from MC §4.2. Add `application.yaml` from §4.3. Ensure app builds. Commit `feat(backend): scaffold spring app with core deps`.

**A5 — Flyway Migration V1**
> Add `/pockito-core/src/main/resources/db/migration/V1__init.sql` using **full DDL** from MC §3.2. Confirm migration applies on clean DB. Commit `feat(db): add initial schema with flyway V1`.

**A6 — Security & Auditing**
> Implement `SecurityConfig`, `KeycloakRealmRoleConverter`, `AuditingConfig` from MC §4.4. Permit `/actuator/health` & Swagger; lock `/api/**`. Commit `feat(security): configure oauth2 resource server and auditing`.

**A7 — Global Exception Handler**
> Add `GlobalExceptionHandler` from MC §4.5, mapping validation & business errors to Problem JSON. Commit `feat(web): global exception handler`.

**A8 — OpenAPI**
> Enable springdoc OpenAPI (MC §4.3). Add a sample controller to verify docs load at `/swagger-ui`. Commit `chore(api): enable openapi and sample endpoint`.

**A9 — Seed (Dev)**
> Add a `CommandLineRunner` (dev profile) to seed currencies (USD/EUR/JPY) and a sample user. Commit `chore(dev): add basic seeds`.

---

## Phase B — Backend Features

**B1 — Wallets**
> Implement entity, repo, DTOs, service, controller as in MC §4.6. Enforce unique active name; idempotent `setDefault`; archive reassigns default. Add unit tests for service and MockMvc tests for controller. Commit `feat(wallets): CRUD with default management and soft-delete`.

**B2 — Categories**
> CRUD with EXPENSE/INCOME; partial unique index (user+type+lower(name)); soft-delete; list filter by `?type=`. Tests. Commit `feat(categories): CRUD with type filter and soft-delete`.

**B3 — Transactions (Expense/Income)**
> Implement create/update/list & archive/activate; enforce category type match; required fields; date-desc listing; paging optional. Tests. Commit `feat(txns): expense/income with validation and listing`.

**B4 — Transfers & FX**
> Implement TRANSFER with internal/to external/from external; store `fromAmount`, `toAmount`, `fromCurrencyCode`, `toCurrencyCode`, `exchangeRate`, `externalWalletName?`. Integrity checks to avoid mixed shapes. Tests. Commit `feat(txns): transfer with multi-currency and fx snapshot`.

**B5 — Subscriptions + Pay-Now**
> CRUD; deterministic next-due per MC; `POST /api/subscriptions/{id}/pay-now` creates linked `txn` + `subscription_payment` and advances date. Tests. Commit `feat(subscriptions): schedule math and pay-now`.

**B6 — Budgets**
> CRUD; `budget_category` links; compute spent vs limit using stored FX; warning/breach flags. Tests. Commit `feat(budgets): CRUD and consumption metrics`.

**B7 — Agreements**
> CRUD; repayments create linked txns; outstanding computed. Tests. Commit `feat(agreements): CRUD and repayments`.

**B8 — Dashboard KPIs**
> Aggregate KPIs for range filters per MC. Tests. Commit `feat(dashboard): KPI aggregation with date filters`.

**B9 — Activity Log Hooks**
> Hook services to append `activity_log` entries on key actions. Commit `feat(audit): activity log hooks`.

---

## Phase C — Frontend Foundations

**C1 — Angular + Tailwind**
> Scaffold Angular 17 standalone app; add Tailwind config, PostCSS, and base styles from MC §6.2. Commit `feat(frontend): scaffold angular with tailwind`.

**C2 — Auth Integration**
> Add `keycloak.service.ts`, `auth.guard.ts`, `token.interceptor.ts` from MC §6.3. Wire guard & interceptor globally. Commit `feat(auth): keycloak integration`.

**C3 — Error Handling**
> Add `error.interceptor.ts` and NgRx `error` slice. Show `<pockito-error-banner>` at page headers. Commit `feat(core): centralized http error handling`.

**C4 — Routing & Shell**
> Define routes for Dashboard, Wallets, Transactions, Subscriptions, Budgets, Agreements, Settings. App shell with topbar, bottom nav (mobile), FAB opens `txn-modal`. Commit `feat(routes): app shell and feature routes`.

**C5 — Modal System**
> Implement `ModalService` + `ModalHostComponent` per MC §6.4. Accessible focus trap. Commit `feat(ui): unified modal system`.

**C6 — Icon Picker**
> Build shared `<icon-picker>` with emoji/URL and optional `/api/icons` suggestions. Commit `feat(ui): icon picker`.

---

## Phase D — Frontend Features

**D1 — Wallets UI**
> NgRx slice + ApiService + list page + detail stub + create/edit modal; set default & archive actions. Commit `feat(wallets): ngrx, api, pages, modal`.

**D2 — Categories UI**
> CRUD UI with type filter; integrate icon picker. Commit `feat(categories): ui and state`.

**D3 — Transactions UI (Expense/Income)**
> Unified `txn-modal` for expense/income; default wallet preselected; category filtering; list page with filters + “Last 5” card. Commit `feat(txns): expense/income ui and list`.

**D4 — Transfers & FX UI**
> Extend `txn-modal` to transfer mode; from/to wallets; `fromAmount`/`toAmount`; `exchangeRate`; **Swap** button. Persist FX snapshot. Commit `feat(txns): transfer ui with fx snapshot`.

**D5 — Subscriptions UI**
> CRUD + payment history; `Pay now`; next due display; dashboard “Upcoming 7 days”. Commit `feat(subscriptions): ui with pay-now flow`.

**D6 — Budgets UI**
> CRUD + category assignment; show spend vs limit with warning/breach. Commit `feat(budgets): ui and metrics`.

**D7 — Agreements UI**
> CRUD + repayments modal; outstanding + snapshot chips (“You owe” / “Owed to you”). Commit `feat(agreements): ui and state`.

**D8 — Dashboard UI**
> KPI widgets + date-range filter. Commit `feat(dashboard): kpi widgets and filters`.

---

## Phase E — QA, Docs, CI

**E1 — Accessibility & Responsiveness**
> Add aria labels, focus outlines, keyboard nav; verify on small screens. Commit `chore(a11y): improve accessibility and responsiveness`.

**E2 — Coverage**
> Raise tests to meet targets (backend ≥80%). Commit `test: raise coverage thresholds`.

**E3 — Seeds & Demo Data**
> Seed scripts to create demo user/data; README instructions. Commit `chore: add demo seeds and docs`.

**E4 — Docs & OpenAPI**
> Update READMEs; ensure Swagger/OpenAPI present and accurate. Commit `docs: usage and api docs`.

**E5 — CI**
> Add GitHub Actions workflows (backend & frontend). Commit `ci: add build and test workflows`.

---

## Response Format Required (each step)
- **Unified diff** of changed files.
- **Conventional Commit** message.
- **Validation results**: show command(s) run and brief PASS/FAIL summary.
- Brief **notes/decisions** if anything required interpretation (must align with Master Context).

**End of Cursor Steps v3. Paste steps sequentially.**
