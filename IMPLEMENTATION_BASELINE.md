# Implementation Baseline Report: Saned License Server & AWS Legacy Adapter

## Target Environment
- **Server Codebase**: `C:\Users\Tovfikur Rahman\Desktop\asistant-new\server`
- **Primary Server File**: `server.js` (951 lines)
- **Database Module**: `lib/db.js`
- **Database Engine**: Turso libSQL (`@libsql/client`) with SQLite fallback
- **Production URL**: `https://saned-license-server.onrender.com`

---

## 1. Current State Inventory

### 1.1 Existing Database Schema (`lib/db.js`)
Currently, `initDB()` executes:
```sql
CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    period_days INTEGER,
    created_at INTEGER,
    activated_at INTEGER,
    expires_at INTEGER,
    device_id TEXT NOT NULL,
    note TEXT,
    status TEXT
);
```
- **Constraint Issue**: `device_id TEXT NOT NULL` is in the table definition. In SQLite, inserting `''` (empty string) succeeds, but `NULL` fails unless the column is nullable.
- **Current Behavior**: `server.js#L437` actively rejects empty `device_id` with:
  `Target Device ID is required. Every token must be pre-set for a device.`
- **Existing Columns via Migration**: `reseller_id TEXT`.

### 1.2 Existing Endpoint Behavior

| Route | Method | Current Target Audience | Current Implementation & Device-Binding Behavior |
|---|---|---|---|
| `/api/activate` | `POST` | Mobile / Desktop Client | `server.js#L227-295`. Requires `token` and `device_id`. Checks `preSetDevice !== deviceId`. If mismatch, returns HTTP 403. Does **not** support unassigned tokens. |
| `/api/verify` | `POST` | Mobile / Desktop Client | `server.js#L144-225`. Checks `preSetDevice !== deviceId`. If mismatch, returns HTTP 403. |
| `/api/tokens/generate`| `POST` | Master & Reseller Panel | `server.js#L422-537`. Rejects request if `device_id` is blank. Deducts quota for resellers. |
| `/api/auth/login` | `POST` | Master & Reseller Panel | `server.js#L298-380`. Web-panel authentication using session cookies (`auth_session`). **Must remain isolated from legacy client login**. |

---

## 2. Identified Changes Required

1. **Database Schema & Migrations (`lib/db.js`)**:
   - Ensure `tokens` table accommodates unassigned tokens (`device_id` being `NULL` or empty string `''`).
   - Add new table `legacy_sessions` to store genuine, cryptographically secure access and refresh tokens for AWS V6.2.0:
     ```sql
     CREATE TABLE IF NOT EXISTS legacy_sessions (
         id TEXT PRIMARY KEY,
         token_hash TEXT NOT NULL,
         refresh_token_hash TEXT NOT NULL,
         license_token TEXT NOT NULL,
         device_id TEXT NOT NULL,
         expires_at INTEGER NOT NULL,
         created_at INTEGER NOT NULL
     );
     CREATE INDEX IF NOT EXISTS idx_legacy_refresh ON legacy_sessions (refresh_token_hash);
     CREATE INDEX IF NOT EXISTS idx_legacy_license ON legacy_sessions (license_token);
     ```

2. **Core Licensing Service (`server.js`)**:
   - Refactor activation into a shared, atomic core function: `processActivation({ token, deviceId })`.
   - Implement dynamic first-activation claiming using an atomic conditional update:
     ```sql
     UPDATE tokens 
     SET device_id = ?, activated_at = ?, expires_at = ?, status = 'active'
     WHERE LOWER(token) = LOWER(?)
       AND (device_id IS NULL OR TRIM(device_id) = '')
       AND activated_at IS NULL
       AND status != 'revoked';
     ```
   - If rows affected is `0`, reload record to differentiate between "claimed by this device concurrently", "claimed by another device", "expired", or "revoked".
   - Support repeat activation by the same device without extending `expires_at`.

3. **Admin & Reseller UI (`master.html`, `reseller.html`, `server.js`)**:
   - Remove mandatory check on `device_id` in `/api/tokens/generate`.
   - Update form UI: `Target Device ID (Optional)` with descriptive helper text.
   - Update token tables: Display `<span class="badge badge-unassigned">Unassigned</span>` when `device_id` is empty.

4. **Isolated Legacy Adapter Routes**:
   - Expose `/api/legacy/auth/login` and `/api/legacy/auth/refresh`.
   - Support hostname-aware routing: if request `Host` header equals `drivers-dashboard.com`, route `/api/auth/login` and `/api/auth/refresh` to the legacy adapter without interfering with the web panel login.
   - Translate legacy body (`loginKey`) and header (`x-device-id`) into the shared activation service.
   - Issue genuine session credentials into `legacy_sessions`.

5. **Backward Compatibility & Regression Risks**:
   - Pre-assigned tokens in the database continue to require their specific device ID.
   - Reseller quota deduction logic remains untouched.
   - Master and Reseller session cookies remain isolated.
