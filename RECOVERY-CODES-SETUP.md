# Recovery Codes System

## What changed
- `db/schema.sql`: adds `recovery_codes`.
- `api/app.ts`: generate, status, revoke and public recovery-login endpoints.
- `frontend/src/main.tsx`: adds a Recovery Code login option on the sign-in screen.

## API
Authenticated:
- POST `/api/recovery-codes/generate` -> creates 10 new codes and revokes old unused ones.
- GET `/api/recovery-codes/status` -> remaining unused count.
- POST `/api/recovery-codes/revoke` -> revoke unused codes.

Public:
- POST `/api/auth/recovery` body `{ "code": "XXXX-XXXX-XXXX" }`.

## Database deployment
Run the updated `db/schema.sql` in Neon/PostgreSQL before deploying the API.

## Security
Plain recovery codes are returned only when generated. The database stores SHA-256 hashes. Every code is single-use and is consumed atomically during login.
