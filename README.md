# CuraNet

A modular healthcare platform. This repository currently contains a TypeScript/Express-based backend (Auth service + FHIR-lite Health Records) and a placeholder `frontend/` directory.

This README documents everything that’s implemented so far, with detailed setup, environment, endpoints, and testing instructions.

- Repo structure
- Prerequisites
- Local setup (Windows PowerShell)
- Environment variables
- Database (PostgreSQL via Prisma)
- Auth service
  - POST-only API design
  - Registration, Email verification, Login, Refresh, Logout, Profile, Sessions
  - Security details (JWT, Argon2 + pepper, cookies, rate limiting, lockouts)
  - Dev conveniences (verification token exposure)
- Admin service
  - Provider approval flow
  - Dev-only admin bootstrap
- Health Records (FHIR-lite)
  - Models (Consent, Encounter, Observation)
  - Provenance + Audit
  - Consent rules
  - Endpoints (create/read/list)
- Postman testing guide
- Operational endpoints (health)
- Error handling & logs
- Roadmap / Next steps

---

## Repo structure

```
CuraNet/
├─ LICENSE
├─ backend/
│  ├─ package.json
│  ├─ tsconfig.json
│  ├─ .env (local only)
│  ├─ prisma/
│  │  ├─ schema.prisma
│  │  └─ migrations/
│  └─ src/
│     ├─ index.ts
│     ├─ controllers/
│     │  ├─ auth.controller.ts
│     │  ├─ records.controller.ts
│     │  └─ admin.controller.ts
│     ├─ routes/
│     │  ├─ auth.routes.ts
│     │  ├─ records.routes.ts
│     │  └─ admin.routes.ts
│     ├─ middlewares/
│     │  └─ authMiddleware.ts
│     ├─ services/
│     │  ├─ consent.service.ts
│     │  └─ audit.service.ts
│     └─ types/
│        └─ ...
└─ frontend/
```

---

## Prerequisites

- Node.js 18+ (recommended LTS) or 20+
- npm 8+
- PostgreSQL database (we use Neon in dev via `DATABASE_URL`)
- PowerShell (the commands here use Windows PowerShell)

---

## Local setup (Windows PowerShell)

1) Install dependencies

```powershell
cd d:\Projects\CuraNet\backend
npm install
```

2) Configure environment

Create `backend/.env` with the following (sample dev values shown; change for your setup):

```env
DATABASE_URL="postgresql://<user>:<password>@<host>/<db>?sslmode=require"

# Auth service secrets (dev values; change in production)
PASSWORD_PEPPER="dev-pepper-please-change-0a1b2c3d4e5f6g7h8i9j"
JWT_SECRET="dev-jwt-secret-7b3b0b83e58a4a8c9a6b8d2f50f6c8c1"
JWT_REFRESH_SECRET="dev-jwt-refresh-secret-63a1f0dbe9bb4ab884f0e9d5a5c7d3e2"

# Optional
# PORT=3000
# CORS_ORIGIN=http://localhost:5173

# Dev-only admin bootstrap token
ADMIN_BOOTSTRAP_TOKEN="dev-bootstrap-admin-please-change"
```

3) Create/update DB schema

```powershell
# From the backend folder
npx prisma migrate dev --name init-records
npx prisma generate
```

If you see EPERM file-lock errors on Windows during `prisma generate`, stop Node processes and retry:

```powershell
Get-Process node | Stop-Process -Force
npx prisma generate
```

4) Run the server in dev mode

```powershell
npm run dev
```

- Server listens on `http://localhost:3000`
- Health: `POST /healthz` → `{ status: "ok" }`

---

## Environment variables (backend/.env)

- `DATABASE_URL`: PostgreSQL connection string.
- `PASSWORD_PEPPER`: Secret pepper appended to password prior to hashing.
- `JWT_SECRET`: Secret for access token JWT signing.
- `JWT_REFRESH_SECRET`: Secret for refresh token rotation & cookie-setting.
- `PORT` (optional): Defaults to 3000.
- `CORS_ORIGIN` (optional): Comma-separated origins for CORS (e.g., `http://localhost:5173`).
- `ADMIN_BOOTSTRAP_TOKEN` (dev-only): Token to protect the admin bootstrap route.

---

## Database (Prisma)

Schema defined in `backend/prisma/schema.prisma`.

Core models:
- `User` (with `role` { patient | doctor | pharmacy | admin } and `status` { pending_verification | active | suspended | pending_approval })
- `RefreshToken` (rotated on refresh; hashed; cookie-based transport)
- `EmailVerification` (hashed, expiring email verification token)
- `PasswordResetToken` (hashed, expiring reset token)

FHIR-lite additions:
- `Consent` (patientId, providerId, status, expiresAt)
- `Encounter` (type, reason, time bounds, notes + provenance fields)
- `Observation` (code, JSON `value`, unit, recordedAt + provenance fields)

Run migrations:

```powershell
npx prisma migrate dev --name <your-name>
```

Generate Prisma Client:

```powershell
npx prisma generate
```

---

## Auth service

Implemented in `src/controllers/auth.controller.ts` with routes in `src/routes/auth.routes.ts`.

### POST-only API design

All auth endpoints are POST-only (even health). Paths are mounted under `/api/auth`.

### Endpoints

- `POST /api/auth/register`
  - Body: `{ email, password, role, phone?, name? }`
  - Creates a user. Patients => `pending_verification`; providers => `pending_approval`.
  - Generates an email verification token (hashed in DB). In dev, the raw token is returned as `devVerificationToken` and logged for convenience.

- `POST /api/auth/verify-email`
  - Body: `{ token }`
  - Marks patient as `active` (providers remain `pending_approval` until admin approval).

- `POST /api/auth/login`
  - Body: `{ email, password, deviceFingerprint? }`
  - Validates user (must be `active`).
  - Returns `accessToken` (JWT HS256, 15m) and sets `refreshToken` as HttpOnly cookie.

- `POST /api/auth/refresh`
  - Cookie: `refreshToken`
  - Rotates refresh token and returns a new `accessToken`.

- `POST /api/auth/logout`
  - Revokes current refresh token and clears cookie.

- `POST /api/auth/profile`
  - Requires `Authorization: Bearer <accessToken>`.
  - Returns current user’s profile fields.

- Sessions management (POST-only)
  - `POST /api/auth/revoke-all-sessions` → Revokes all refresh tokens for the current user.
  - `POST /api/auth/sessions` → Returns active sessions for current user.
  - `POST /api/auth/sessions/:sessionId` → Revokes a specific session by ID.

- Health
  - `POST /api/auth/health` → Basic service+DB check

### Security highlights

- Argon2id password hashing with memory/time cost and a global `PASSWORD_PEPPER`.
- JWT access tokens (HS256) with `sub`, `email`, `role`, `status`, and `jti`.
- HttpOnly, SameSite=strict refresh token cookies.
- Middleware `authenticateToken` validates and attaches `req.user`.
- Role helpers: `requirePatient`, `requireDoctor`, `requirePharmacy`, `requireAdmin`.
- Rate limiting by IP on sensitive endpoints.
- Basic account lockout tracking helpers (failed login attempts).

### Dev conveniences

- On `register`, returns `devVerificationToken` (non-production) and logs the token to console.
- `POST /healthz` endpoint exists at application root for quick checks.

---

## Admin service

Routes in `src/routes/admin.routes.ts`, controller in `src/controllers/admin.controller.ts`.

- `POST /api/admin/providers/pending` (admin-only)
  - Lists providers (`doctor`/`pharmacy`) in `pending_approval`.

- `POST /api/admin/providers/approve/:id` (admin-only)
  - Approves a provider user by ID, updating status to `active`.

- `POST /api/admin/bootstrap` (dev-only)
  - Securely create or promote an admin using `ADMIN_BOOTSTRAP_TOKEN`.
  - Input (promote existing): `{ "email": "user@example.com" }` (+ optional `password` to reset).
  - Input (create new): `{ "email": ..., "password": ..., "name"?: ..., "phone"?: ... }`.
  - Blocked when `NODE_ENV=production`.

---

## Health Records (FHIR-lite)

Implemented in `src/controllers/records.controller.ts`, mounted at `/api/records` with POST-only endpoints. All routes require a valid access token via `authenticateToken`.

### Data model

- `Consent`: Grants a provider (doctor/pharmacy) access to a patient’s records. Must be `active`. Optional `expiresAt`.
- `Encounter`: Clinical encounter with patient; contains provenance fields (`createdById`, `createdByRole`, `createdAt`, `updatedAt`).
- `Observation`: A clinical measurement or note (`code`, JSON `value`, optional `unit`), also with provenance.

### Consent rules

- Patients can read their own records without consent.
- Providers must have an `active` Consent to create or read patient records.

### Audit

- Every read (`record.read`) and write (`record.write`) emits an event via `emitAudit` (currently logs to console; replace with HTTP/message bus in prod).

### Endpoints

Encounters:
- `POST /api/records/encounters/create` (doctor only; consent required)
  - Body: `{ patientId, type, reason?, startTime, endTime?, notes? }`
- `POST /api/records/encounters/get/:id`
- `POST /api/records/encounters/list`
  - Body (doctor): `{ patientId, limit?, cursor? }`
  - Body (patient): `{ limit?, cursor? }` (patientId inferred from token)

Observations:
- `POST /api/records/observations/create` (doctor only; consent required)
  - Body: `{ patientId, encounterId?, code, value, unit? }` (`value` is JSON)
- `POST /api/records/observations/get/:id`
- `POST /api/records/observations/list`
  - Body (doctor): `{ patientId, limit?, cursor? }`
  - Body (patient): `{ limit?, cursor? }`

---

## Postman testing guide

1) Health checks
- `POST http://localhost:3000/healthz` → 200 `{ status: "ok" }`
- `POST http://localhost:3000/api/auth/health` → 200

2) Register (patient)
- `POST /api/auth/register`
  - Body: `{ "email": "...", "password": "Passw0rd!23", "role": "patient", "phone": "+1555...", "name": "..." }`
  - Copy `devVerificationToken` from response (dev only)

3) Verify email
- `POST /api/auth/verify-email`
  - Body: `{ "token": "<devVerificationToken>" }`

4) Login
- `POST /api/auth/login` → Returns `accessToken` (Authorization Bearer) and sets `refreshToken` cookie.

5) Profile
- `POST /api/auth/profile` with `Authorization: Bearer <accessToken>`

6) Admin bootstrap (dev only)
- `POST /api/admin/bootstrap` with header `x-bootstrap-token: <ADMIN_BOOTSTRAP_TOKEN>`
  - Promote existing or create new admin.

7) Approve provider
- As admin: `POST /api/admin/providers/approve/:id`

8) Consent (manual for now)
- Insert a `Consent` row (via Prisma Studio or SQL) to grant doctor access to a patient.

9) Records
- Create Encounter (doctor): `POST /api/records/encounters/create`
- Create Observation (doctor): `POST /api/records/observations/create`
- List/Get as patient or provider per rules above.

---

## Operational endpoints

- App health: `POST /healthz` (root) → `{ status: "ok" }`
- Auth health: `POST /api/auth/health` (DB ping)

---

## Error handling & logs

- Centralized error handler in `src/index.ts` logs server errors and returns `{ message: ... }` with appropriate status codes.
- Auth middleware returns 401/403 as needed.
- Rate limiting returns 429 with `retryAfter` seconds.
- Audit logs are emitted via `console.info('[AUDIT]', ...)` (replace with real transport in production).

---

## Roadmap / Next steps

- Add consent management endpoints (grant/revoke) to avoid manual inserts during testing.
- Replace audit logger with real HTTP or message bus integration.
- Add request validation (e.g., Zod) and OpenAPI (Swagger) documentation.
- Email/SMS delivery service integration for verification and password reset.
- Robust session/device management UI and geo/IP intel.
- E2E tests and CI workflow.
- Implement frontend app and integrate with Auth and Records.

---

## Notes

- All APIs in this backend are designed as POST-only for uniform client behavior and to simplify certain constrained client environments.
- Keep secrets secure and rotate for production.
- Treat `ADMIN_BOOTSTRAP_TOKEN` as a development convenience only; disable in prod.
