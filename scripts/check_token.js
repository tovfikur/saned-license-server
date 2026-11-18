if (typeof process.loadEnvFile === 'function') {
    try { process.loadEnvFile(); } catch (_) {}
}
const { createClient } = require('@libsql/client');
const TURSO_URL = process.env.TURSO_DATABASE_URL || 'http://151.158.51.11:8085';
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN || 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3B1LWFkbWluIiwiaWF0IjoxNzk0OTg5MjU5LCJleHAiOjIxMTAzNDkyNTl9.2RQrvpA-fcyrHEFeKRwfcJYrd8NF9HWwgG_WlrYWDRqDmLee7W7r0-NHtzY5-7u-azHBTagZUROjo2nCB3bJBw';

async function run() {
    const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });
    const avail = await db.execute("SELECT * FROM tokens WHERE status = 'available' LIMIT 5");
    console.log('Available Tokens:', JSON.stringify(avail.rows, null, 2));
}
run().catch(console.error);
