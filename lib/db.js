const { createClient } = require('@libsql/client');
const { hashPassword, randomToken } = require('./security');

const TURSO_URL = process.env.TURSO_DATABASE_URL || 'file:./local.db';
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

const PERIODS = [1, 3, 7, 30, 60, 90, 365];

const db = TURSO_TOKEN
    ? createClient({ url: TURSO_URL, authToken: TURSO_TOKEN })
    : createClient({ url: TURSO_URL });

async function addColumnIfMissing(table, column, definition) {
    try {
        await db.execute(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
        console.log(`[Turso] Added column ${table}.${column}`);
    } catch (err) {
        if (!/duplicate column/i.test(err.message)) {
            console.error(`[Turso] Failed to add ${table}.${column}:`, err.message);
        }
    }
}

async function seedMaster() {
    const existing = await db.execute("SELECT id, username FROM users WHERE role = 'master' ORDER BY created_at ASC LIMIT 1");
    if (existing.rows.length > 0) {
        return String(existing.rows[0].id);
    }

    const id = randomToken(16);
    const username = String(process.env.MASTER_USERNAME || 'master').trim();
    let password = process.env.MASTER_PASSWORD;
    let generated = false;

    if (!password) {
        password = randomToken(8);
        generated = true;
    }

    await db.execute({
        sql: 'INSERT INTO users (id, username, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        args: [id, username, hashPassword(password), 'master', 'active', Date.now()]
    });

    console.log(`[Auth] Created master account "${username}"` +
        (generated ? ` with generated password: ${password}` : ' using MASTER_PASSWORD from environment'));

    return id;
}

async function initDB() {
    await db.execute(`CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        period_days INTEGER,
        created_at INTEGER,
        activated_at INTEGER,
        expires_at INTEGER,
        device_id TEXT NOT NULL,
        note TEXT,
        status TEXT
    )`);

    await db.execute(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        created_at INTEGER NOT NULL
    )`);

    await db.execute(`CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    )`);

    await db.execute(`CREATE TABLE IF NOT EXISTS reseller_quotas (
        user_id TEXT NOT NULL,
        period_days INTEGER NOT NULL,
        max_tokens INTEGER NOT NULL DEFAULT 0,
        used_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, period_days)
    )`);

    await addColumnIfMissing('tokens', 'reseller_id', 'TEXT');

    await db.execute('CREATE INDEX IF NOT EXISTS idx_tokens_reseller ON tokens (reseller_id)');
    await db.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id)');

    const masterId = await seedMaster();

    for (const period of PERIODS) {
        await db.execute({
            sql: `INSERT OR IGNORE INTO reseller_quotas (user_id, period_days, max_tokens, used_count)
                  SELECT id, ?, 0, 0 FROM users WHERE role = 'reseller'`,
            args: [period]
        });
    }

    await db.execute({ sql: 'DELETE FROM sessions WHERE expires_at < ?', args: [Date.now()] });

    console.log('[Turso] Database schema verified');
    return masterId;
}

module.exports = { db, initDB, PERIODS };
