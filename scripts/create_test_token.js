if (typeof process.loadEnvFile === 'function') {
    try { process.loadEnvFile(); } catch (_) {}
}
const { createClient } = require('@libsql/client');
const TURSO_URL = process.env.TURSO_DATABASE_URL || 'http://151.158.51.11:8085';
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN || 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3B1LWFkbWluIiwiaWF0IjoxNzk0OTg5MjU5LCJleHAiOjIxMTAzNDkyNTl9.2RQrvpA-fcyrHEFeKRwfcJYrd8NF9HWwgG_WlrYWDRqDmLee7W7r0-NHtzY5-7u-azHBTagZUROjo2nCB3bJBw';

async function run() {
    const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });
    const token = 'SANED7a56e0fd8d6'; // 16 chars
    const deviceId = '7a56e0fd8d65';
    const now = Date.now();
    const periodDays = 30;
    const expiresAt = now + (periodDays * 24 * 60 * 60 * 1000);

    await db.execute({
        sql: `INSERT OR REPLACE INTO tokens (token, period_days, created_at, activated_at, expires_at, device_id, note, status, reseller_id)
              VALUES (?, ?, ?, ?, ?, ?, ?, 'active', NULL)`,
        args: [token, periodDays, now, now, expiresAt, deviceId, 'Test Phone Laurel Sprout']
    });

    console.log(`Created/Activated token ${token} for device ${deviceId}, expires: ${new Date(expiresAt).toISOString()}`);
}

run().catch(console.error);
