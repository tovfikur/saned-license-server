/**
 * Utility script to unblock all devices and restore revoked/blocked tokens in the Turso database.
 * Run with: node scripts/unblock_all.js
 */
const { createClient } = require('@libsql/client');

if (typeof process.loadEnvFile === 'function') {
    try { process.loadEnvFile(); } catch (_) {}
}

const TURSO_URL = process.env.TURSO_DATABASE_URL || 'http://151.158.51.11:8085';
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN || 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3B1LWFkbWluIiwiaWF0IjoxNzk0OTg5MjU5LCJleHAiOjIxMTAzNDkyNTl9.2RQrvpA-fcyrHEFeKRwfcJYrd8NF9HWwgG_WlrYWDRqDmLee7W7r0-NHtzY5-7u-azHBTagZUROjo2nCB3bJBw';

async function main() {
    console.log('[Turso] Connecting to:', TURSO_URL);
    const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

    // 1. Clear blocked devices
    await db.execute('DELETE FROM blocked_devices');
    console.log('[Turso] Cleared all records from blocked_devices table.');

    // 2. Restore any tokens that were blocked or revoked
    const blockedTokens = await db.execute("SELECT token, activated_at, expires_at, note, status FROM tokens WHERE note LIKE '%[BLOCKED]%' OR status = 'revoked'");
    const now = Date.now();
    for (const row of blockedTokens.rows) {
        const cleanNote = (row.note || '').replace(/\s*\[BLOCKED\]/g, '').trim();
        let newStatus = row.status;
        if (row.status === 'revoked') {
            if (row.activated_at) {
                newStatus = (row.expires_at && now > Number(row.expires_at)) ? 'expired' : 'active';
            } else {
                newStatus = 'available';
            }
        }
        await db.execute({
            sql: 'UPDATE tokens SET status = ?, note = ? WHERE token = ?',
            args: [newStatus, cleanNote, row.token]
        });
        console.log(` - Restored token ${row.token} -> status: ${newStatus}, note: "${cleanNote}"`);
    }

    // 3. Verification
    const countBlocked = await db.execute('SELECT COUNT(*) as count FROM blocked_devices');
    const countTokens = await db.execute("SELECT COUNT(*) as count FROM tokens WHERE note LIKE '%[BLOCKED]%' OR status = 'revoked'");

    console.log(`\n[Status] Current blocked devices: ${countBlocked.rows[0].count}`);
    console.log(`[Status] Current revoked/blocked tokens: ${countTokens.rows[0].count}`);
    console.log('[Success] All devices and licenses are unblocked.');
}

main().catch(err => {
    console.error('Error unblocking devices:', err);
    process.exit(1);
});
