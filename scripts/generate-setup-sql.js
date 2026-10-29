#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { hashPassword } = require('../lib/security');

function getArg(name) {
    const index = process.argv.indexOf(name);
    if (index === -1) return null;
    return process.argv[index + 1] || null;
}

function sqlString(value) {
    return "'" + String(value).replace(/'/g, "''") + "'";
}

const username = (getArg('--username') || 'master').trim();
const password = getArg('--password') || crypto.randomBytes(16).toString('base64url');
const userId = crypto.randomBytes(16).toString('hex');
const passwordHash = hashPassword(password);
const now = Date.now();

const sql = `-- Saned License SaaS - Turso setup
-- Generated: ${new Date(now).toISOString()}
--
-- How to run:
--   turso db shell <your-database-name> < turso-setup.sql
--   (or paste this file into the Turso web console)
--
-- IMPORTANT:
--   1. The ALTER TABLE line below fails with "duplicate column name" if
--      tokens.reseller_id already exists. That is safe; skip that line.
--   2. Change the master password after first login.
--   3. This file contains a password hash. Do not commit it to git.

-- ------------------------------------------------------------------ Tokens
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

-- Existing databases need this column. Skip if it already exists.
ALTER TABLE tokens ADD COLUMN reseller_id TEXT;

-- ------------------------------------------------------------------- Users
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL
);

-- ---------------------------------------------------------------- Sessions
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- --------------------------------------------------------- Reseller quotas
CREATE TABLE IF NOT EXISTS reseller_quotas (
    user_id TEXT NOT NULL,
    period_days INTEGER NOT NULL,
    max_tokens INTEGER NOT NULL DEFAULT 0,
    used_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, period_days)
);

CREATE INDEX IF NOT EXISTS idx_tokens_reseller ON tokens (reseller_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

-- ------------------------------------------------------------------ Master
-- Upsert: creates the master on a fresh database and resets its password
-- on an existing database. Existing master id is preserved.
INSERT INTO users (id, username, password_hash, role, status, created_at)
VALUES (
    ${sqlString(userId)},
    ${sqlString(username)},
    ${sqlString(passwordHash)},
    'master',
    'active',
    ${now}
)
ON CONFLICT (username COLLATE NOCASE) DO UPDATE SET
    password_hash = excluded.password_hash,
    role = 'master',
    status = 'active';

-- Force re-login after a password reset.
DELETE FROM sessions
WHERE user_id = (SELECT id FROM users WHERE username = ${sqlString(username)} COLLATE NOCASE);

-- ---------------------------------------------- Default quotas for resellers
-- Every reseller gets a 0 quota for each supported period (0 = blocked).
INSERT OR IGNORE INTO reseller_quotas (user_id, period_days, max_tokens, used_count)
SELECT u.id, p.period_days, 0, 0
FROM users u
CROSS JOIN (
    SELECT 1 AS period_days
    UNION ALL SELECT 3
    UNION ALL SELECT 7
    UNION ALL SELECT 30
    UNION ALL SELECT 60
    UNION ALL SELECT 90
    UNION ALL SELECT 365
) p
WHERE u.role = 'reseller';

-- ------------------------------------------------------------------- Done
`;

const outputPath = path.join(__dirname, '..', 'turso-setup.sql');
fs.writeFileSync(outputPath, sql, 'utf8');

console.log('Wrote: ' + outputPath);
console.log('Master username: ' + username);
console.log('Master password: ' + password);
console.log('Password hash: ' + passwordHash);
console.log('');
console.log('Next:');
console.log('  1. Run the SQL in Turso (see the header of the file).');
console.log('  2. Sign in at /login with the credentials above.');
console.log('  3. Change the password immediately.');
