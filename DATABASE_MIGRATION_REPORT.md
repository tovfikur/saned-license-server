# Database Migration Report: Turso libSQL & Schema Integrity

## 1. Migration Summary
- **Module**: `lib/db.js`
- **Engine**: Turso libSQL (`@libsql/client`) / SQLite
- **Migration Strategy**: 100% Additive & Non-Destructive

---

## 2. Executed Schema Migrations

### 2.1 Nullable Device ID Constraint
In `lib/db.js`, the table definition for `tokens` was updated to make `device_id` nullable:
```sql
CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    period_days INTEGER,
    created_at INTEGER,
    activated_at INTEGER,
    expires_at INTEGER,
    device_id TEXT,
    note TEXT,
    status TEXT
);
```
- **Existing Records**: All existing records with preassigned device IDs remain unchanged.
- **SQLite Compatibility**: In existing SQLite/libSQL databases, SQLite permits empty string `''` or `NULL` insertion into existing columns. The code supports both `NULL` and empty string representations interchangeably via `(device_id IS NULL OR TRIM(device_id) = '')`.

### 2.2 Dedicated Legacy Sessions Table
To support genuine, cryptographically secure session and refresh tokens for AWS V6.2.0, a dedicated table was added:
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

---

## 3. Data Integrity & Verification

1. **Pre-existing Token Records**: Verified during automated test suite (Test 16). Pre-existing tokens remain intact and queryable.
2. **Quota Tracking**: The `reseller_quotas` table and quota deduction logic remain completely untouched.
3. **Admin User Records**: The `users` and `sessions` tables for web panel administration continue operating without interruption.
