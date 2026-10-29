# Saned Assistant License Server (SaaS)

License management server for Saned Assistant with a **Master panel** and **Reseller panels**, backed by **Turso (libSQL)** and deployable on Render.

## Features
- **Master panel** — full control: generate, revoke and delete any token; create/disable/delete resellers; set per-duration quotas; reset usage; reset passwords.
- **Reseller panel** — generate tokens within master-assigned quotas, view only their own tokens, revoke their own tokens, change their own password.
- **No reseller deletes** — token deletion is server-enforced for the master account only.
- **Per-duration quotas** — 1, 3, 7, 30, 60, 90 and 365 days. `0` means that period is blocked. Quotas never reset automatically; master resets usage manually.
- **Device-bound licenses** — every token is pre-set for a specific device ID (unchanged client API).
- **Session auth** — HttpOnly cookie sessions, scrypt password hashing, login rate limiting.
- **Zero extra dependencies** — native Node.js `http`/`crypto` plus `@libsql/client`.

## Environment variables
| Variable | Required | Description |
|---|---|---|
| `TURSO_DATABASE_URL` | Production | Turso database URL (`libsql://...`). Falls back to `file:./local.db` for local dev. |
| `TURSO_AUTH_TOKEN` | Production | Turso auth token. |
| `MASTER_USERNAME` | Optional | Master username created on first run (default `master`). |
| `MASTER_PASSWORD` | Optional | Master password on first run. If omitted, a random password is generated and printed once in the logs. |
| `PORT` | Optional | HTTP port (Render sets this automatically). |
| `RENDER_EXTERNAL_URL` | Optional | Used by the keep-alive ping. |

> Never commit Turso credentials. Rotate any token that was previously committed to git.

## Run locally
```bash
node server.js
```
or double-click `start_server.bat`. Without env vars it uses `file:./local.db`.

First run creates the schema, seeds the master account and prints the master credentials if `MASTER_PASSWORD` was not set.

## Panels
- `/login` — sign in
- `/master` — master panel
- `/reseller` — reseller panel
- `/` — redirects by role

## API
Public (used by the desktop/mobile client):
- `GET /api/health`
- `POST /api/verify` — `{ token, device_id }`
- `POST /api/activate` — `{ token, device_id }`

Auth:
- `POST /api/auth/login` — `{ username, password }`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/auth/change-password` — `{ current_password, new_password }`

Tokens:
- `GET /api/tokens` — master sees all (optional `?reseller_id=` / `?status=`), reseller sees own
- `POST /api/tokens/generate` — `{ device_id, period_days, note?, reseller_id? }` (master only for `reseller_id`)
- `POST /api/tokens/revoke` — `{ token }`
- `POST /api/tokens/delete` — `{ token }` (master only)

Reseller:
- `GET /api/me/quotas`

Master:
- `GET /api/admin/stats`
- `GET /api/admin/resellers`
- `POST /api/admin/resellers` — `{ username, password }`
- `POST /api/admin/resellers/update` — `{ user_id, username?, password?, status? }`
- `POST /api/admin/resellers/delete` — `{ user_id }` (their tokens transfer to master)
- `POST /api/admin/resellers/quotas` — `{ user_id, quotas: { "30": 10, ... } }`
- `POST /api/admin/resellers/reset-usage` — `{ user_id, period_days? }`

## Database migration
On startup the server creates `users`, `sessions` and `reseller_quotas`, and adds `tokens.reseller_id` if missing. Existing tokens have `reseller_id = NULL`, which means they are owned by master and remain valid.

## Manual Turso setup (optional)
The server migrates automatically, but you can also prepare the database yourself:

```bash
node scripts/generate-setup-sql.js --username master --password "YourStrongPassword"
```

This writes `turso-setup.sql` (gitignored) containing the full schema, indexes, the hashed master password and default reseller quotas. Run it with:

```bash
turso db shell <your-database-name> < turso-setup.sql
```

If `tokens.reseller_id` already exists, skip the `ALTER TABLE` line. The master upsert resets the master password and clears its sessions, so re-running the file is safe apart from that one `ALTER` statement.

## Deploy on Render
1. Set `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `MASTER_USERNAME`, `MASTER_PASSWORD` in the Render dashboard.
2. Deploy. The schema migration runs automatically on boot.
3. Open `/login` and sign in as master.
