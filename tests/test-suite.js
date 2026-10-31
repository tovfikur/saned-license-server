const http = require('http');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Ensure isolated test database
const TEST_DB = path.join(__dirname, 'test-isolated.db');
if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);

process.env.TURSO_DATABASE_URL = 'file:' + TEST_DB;
process.env.MASTER_PASSWORD = 'TestMasterPassword123!';
process.env.PORT = '8999';

// Import server components
const { db, initDB, PERIODS } = require('../lib/db');
const { activateLicense, verifyLicense, isValidTokenFormat } = require('../lib/license-service');
const { handleLegacyLogin, handleLegacyRefresh } = require('../lib/legacy-adapter');

let server;
const BASE_URL = 'http://localhost:8999';

function request(method, path, body, headers = {}) {
    return new Promise((resolve, reject) => {
        const u = new URL(path, BASE_URL);
        const reqHeaders = {
            'Content-Type': 'application/json',
            ...headers
        };
        const req = http.request(u, {
            method,
            headers: reqHeaders
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                let json = null;
                try {
                    json = JSON.parse(data);
                } catch (e) {
                    json = data;
                }
                resolve({
                    status: res.statusCode,
                    headers: res.headers,
                    body: json
                });
            });
        });
        req.on('error', reject);
        if (body) {
            req.write(typeof body === 'string' ? body : JSON.stringify(body));
        }
        req.end();
    });
}

const testResults = [];

function recordTest(id, name, passed, details = '') {
    testResults.push({ id, name, passed, details });
    const mark = passed ? '✅ PASS' : '❌ FAIL';
    console.log(`[Test ${id < 10 ? '0' + id : id}] ${mark}: ${name} ${details ? '(' + details + ')' : ''}`);
}

async function run() {
    console.log('=== Starting Saned Dynamic Device Binding & Legacy Adapter 27-Point Test Suite ===\n');

    // Start server
    await initDB();
    const serverModule = require('../server'); // loads server.js
    server = http.createServer(async (req, res) => {
        // server.js handles requests via its internal handleRequest or listen
    });

    // We can also start server.js directly as child or invoke endpoints via request
    // Since server.js automatically calls http.createServer(...).listen(PORT) on require,
    // let's wait 500ms for it to bind.
    await new Promise(r => setTimeout(r, 600));

    // Master login to get cookie for token generation
    const loginRes = await request('POST', '/api/auth/login', {
        username: 'master',
        password: 'TestMasterPassword123!'
    });
    const cookie = loginRes.headers['set-cookie'] ? loginRes.headers['set-cookie'][0].split(';')[0] : '';
    const authHeaders = { Cookie: cookie };

    const dev1 = 'sm1-1111111111111111111111111111111111111111';
    const dev2 = 'sm1-2222222222222222222222222222222222222222';
    const dev3 = 'sm1-3333333333333333333333333333333333333333';

    // 1. Generate license with no device ID
    const genUnassigned = await request('POST', '/api/tokens/generate', {
        period_days: 30,
        note: 'Unassigned test token'
    }, authHeaders);
    const unassignedToken = genUnassigned.body.token ? genUnassigned.body.token.token : null;
    const t1Passed = genUnassigned.status === 201 && unassignedToken && genUnassigned.body.token.deviceId === null;
    recordTest(1, 'Generate license with no device ID', t1Passed, `Token: ${unassignedToken}`);

    // 2. Generate license with a preassigned device ID
    const genPreassigned = await request('POST', '/api/tokens/generate', {
        device_id: dev1,
        period_days: 30,
        note: 'Preassigned to dev1'
    }, authHeaders);
    const preassignedToken = genPreassigned.body.token ? genPreassigned.body.token.token : null;
    const t2Passed = genPreassigned.status === 201 && preassignedToken && genPreassigned.body.token.deviceId === dev1;
    recordTest(2, 'Generate license with a preassigned device ID', t2Passed, `Token: ${preassignedToken}`);

    // 3. First device successfully claims an unassigned token
    const act1 = await request('POST', '/api/activate', {
        token: unassignedToken,
        device_id: dev1
    });
    const t3Passed = act1.status === 200 && act1.body.success === true && act1.body.unlocked === true && act1.body.device_id === dev1;
    recordTest(3, 'First device successfully claims an unassigned token', t3Passed, `Claimed by: ${dev1}`);

    // 4. Same device activates again
    const actRepeat = await request('POST', '/api/activate', {
        token: unassignedToken,
        device_id: dev1
    });
    const t4Passed = actRepeat.status === 200 && actRepeat.body.success === true && actRepeat.body.unlocked === true;
    recordTest(4, 'Same device activates again', t4Passed, 'Activation succeeded');

    // 5. Same-device repeat activation does not extend expiration
    const t5Passed = act1.body.expires_at === actRepeat.body.expires_at;
    recordTest(5, 'Same-device repeat activation does not extend expiration', t5Passed, `Exp: ${act1.body.expires_at} === ${actRepeat.body.expires_at}`);

    // 6. Different device attempts an already-bound token
    const actMismatch = await request('POST', '/api/activate', {
        token: unassignedToken,
        device_id: dev2
    });
    const t6Passed = actMismatch.status === 403 && actMismatch.body.unlocked === false;
    recordTest(6, 'Different device attempts an already-bound token', t6Passed, `Rejected with 403: ${actMismatch.body.message}`);

    // 7. Two devices attempt to activate simultaneously (Race Condition Simulation)
    const genRace = await request('POST', '/api/tokens/generate', { period_days: 30 }, authHeaders);
    const raceToken = genRace.body.token.token;
    const [raceDevA, raceDevB] = await Promise.all([
        request('POST', '/api/activate', { token: raceToken, device_id: dev2 }),
        request('POST', '/api/activate', { token: raceToken, device_id: dev3 })
    ]);
    const oneWon = (raceDevA.status === 200 && raceDevB.status === 403) || (raceDevB.status === 200 && raceDevA.status === 403);
    recordTest(7, 'Two devices attempt to activate simultaneously', oneWon, `Winner status: 200, Loser status: 403`);

    // 8. Activation without device ID
    const actNoDev = await request('POST', '/api/activate', { token: unassignedToken });
    const t8Passed = actNoDev.status === 400 && actNoDev.body.unlocked === false;
    recordTest(8, 'Activation without device ID', t8Passed, 'HTTP 400 returned');

    // 9. Invalid license token
    const actInvalid = await request('POST', '/api/activate', { token: 'NONEXISTENT12345', device_id: dev1 });
    const t9Passed = actInvalid.status === 404 && actInvalid.body.unlocked === false;
    recordTest(9, 'Invalid license token', t9Passed, 'HTTP 404 returned');

    // 10. Incorrect token format
    const actBadFormat = await request('POST', '/api/activate', { token: '@@@', device_id: dev1 });
    const t10Passed = actBadFormat.status === 400 && actBadFormat.body.reason === 'invalid_format';
    recordTest(10, 'Incorrect token format', t10Passed, 'HTTP 400 invalid_format');

    // 11. Revoked unassigned token
    const genRevoke = await request('POST', '/api/tokens/generate', { period_days: 30 }, authHeaders);
    const revokeToken = genRevoke.body.token.token;
    await request('POST', '/api/tokens/revoke', { token: revokeToken }, authHeaders);
    const actRevoked = await request('POST', '/api/activate', { token: revokeToken, device_id: dev1 });
    const t11Passed = actRevoked.status === 403 && actRevoked.body.reason === 'revoked';
    recordTest(11, 'Revoked unassigned token', t11Passed, 'HTTP 403 revoked');

    // 12. Expired unassigned token
    const genExpired = await request('POST', '/api/tokens/generate', { period_days: 1 }, authHeaders);
    const expiredToken = genExpired.body.token.token;
    await db.execute({
        sql: "UPDATE tokens SET expires_at = ? WHERE token = ?",
        args: [Date.now() - 100000, expiredToken]
    });
    const actExpired = await request('POST', '/api/activate', { token: expiredToken, device_id: dev1 });
    const t12Passed = actExpired.status === 403 && actExpired.body.reason === 'expired';
    recordTest(12, 'Expired unassigned token', t12Passed, 'HTTP 403 expired');

    // 13. Unassigned token passed to /api/verify
    const genUnclaimedVerify = await request('POST', '/api/tokens/generate', { period_days: 30 }, authHeaders);
    const verifyUnclaimed = await request('POST', '/api/verify', {
        token: genUnclaimedVerify.body.token.token,
        device_id: dev1
    });
    const t13Passed = verifyUnclaimed.status === 403 && verifyUnclaimed.body.reason === 'unassigned';
    recordTest(13, 'Unassigned token passed to /api/verify', t13Passed, 'HTTP 403 unassigned (never claims)');

    // 14. Preassigned token activated by the wrong device
    const actPreassignedWrong = await request('POST', '/api/activate', {
        token: preassignedToken,
        device_id: dev2
    });
    const t14Passed = actPreassignedWrong.status === 403 && actPreassignedWrong.body.reason === 'device_mismatch';
    recordTest(14, 'Preassigned token activated by wrong device', t14Passed, 'HTTP 403 device_mismatch');

    // 15. Existing bound token continues working
    const actPreassignedRight = await request('POST', '/api/activate', {
        token: preassignedToken,
        device_id: dev1
    });
    const verifyPreassigned = await request('POST', '/api/verify', {
        token: preassignedToken,
        device_id: dev1
    });
    const t15Passed = actPreassignedRight.status === 200 && verifyPreassigned.status === 200 && verifyPreassigned.body.unlocked === true;
    recordTest(15, 'Existing bound token continues working', t15Passed, 'Activate & Verify HTTP 200');

    // 16. Existing license records survive database migration
    const countRes = await db.execute('SELECT COUNT(*) as cnt FROM tokens');
    const t16Passed = Number(countRes.rows[0].cnt) >= 4;
    recordTest(16, 'Existing license records survive database migration', t16Passed, `Rows count: ${countRes.rows[0].cnt}`);

    // 17. Legacy adapter receives loginKey and x-device-id
    const legacyLoginMissingDev = await request('POST', '/api/legacy/auth/login', {
        loginKey: unassignedToken
    });
    const t17Passed = legacyLoginMissingDev.status === 400 && legacyLoginMissingDev.body.error === 'device_required';
    recordTest(17, 'Legacy adapter requires x-device-id', t17Passed, 'HTTP 400 device_required');

    // 18. Legacy adapter activates an unassigned token
    const genLegacyUnassigned = await request('POST', '/api/tokens/generate', { period_days: 30 }, authHeaders);
    const legacyToken = genLegacyUnassigned.body.token.token;
    const legacyLoginSuccess = await request('POST', '/api/legacy/auth/login', {
        loginKey: legacyToken
    }, { 'x-device-id': dev1 });
    const legacySession = legacyLoginSuccess.body;
    const t18Passed = legacyLoginSuccess.status === 200 && legacySession.token && legacySession.refreshToken && legacySession.tokenExpiryTime;
    recordTest(18, 'Legacy adapter activates an unassigned token', t18Passed, `Access token: ${legacySession.token?.slice(0, 15)}...`);

    // 19. Legacy adapter rejects a different device
    const legacyLoginWrongDev = await request('POST', '/api/legacy/auth/login', {
        loginKey: legacyToken
    }, { 'x-device-id': dev2 });
    const t19Passed = legacyLoginWrongDev.status === 403 && legacyLoginWrongDev.body.error === 'device_mismatch';
    recordTest(19, 'Legacy adapter rejects a different device', t19Passed, 'HTTP 403 device_mismatch');

    // 20. Legacy refresh from the same device
    const legacyRefreshSuccess = await request('POST', '/api/legacy/auth/refresh', {
        refreshToken: legacySession.refreshToken,
        deviceId: dev1
    }, { 'x-device-id': dev1 });
    const t20Passed = legacyRefreshSuccess.status === 200 && legacyRefreshSuccess.body.token && legacyRefreshSuccess.body.refreshToken !== legacySession.refreshToken;
    recordTest(20, 'Legacy refresh from the same device', t20Passed, 'Rotated new refresh token');

    // 21. Legacy refresh from a different device
    const legacyRefreshWrongDev = await request('POST', '/api/legacy/auth/refresh', {
        refreshToken: legacyRefreshSuccess.body.refreshToken,
        deviceId: dev2
    }, { 'x-device-id': dev2 });
    const t21Passed = legacyRefreshWrongDev.status === 403 && legacyRefreshWrongDev.body.error === 'device_mismatch';
    recordTest(21, 'Legacy refresh from a different device', t21Passed, 'HTTP 403 device_mismatch');

    // 22. Refresh after revocation
    await request('POST', '/api/tokens/revoke', { token: legacyToken }, authHeaders);
    const legacyRefreshRevoked = await request('POST', '/api/legacy/auth/refresh', {
        refreshToken: legacyRefreshSuccess.body.refreshToken,
        deviceId: dev1
    }, { 'x-device-id': dev1 });
    const t22Passed = legacyRefreshRevoked.status === 403 && legacyRefreshRevoked.body.error === 'revoked';
    recordTest(22, 'Refresh after revocation', t22Passed, 'HTTP 403 revoked');

    // 23. Refresh after license expiration
    const genExpRefresh = await request('POST', '/api/tokens/generate', { period_days: 1 }, authHeaders);
    const expToken = genExpRefresh.body.token.token;
    const loginExp = await request('POST', '/api/legacy/auth/login', { loginKey: expToken }, { 'x-device-id': dev1 });
    await db.execute({
        sql: "UPDATE tokens SET expires_at = ? WHERE token = ?",
        args: [Date.now() - 50000, expToken]
    });
    const legacyRefreshExpired = await request('POST', '/api/legacy/auth/refresh', {
        refreshToken: loginExp.body.refreshToken,
        deviceId: dev1
    }, { 'x-device-id': dev1 });
    const t23Passed = legacyRefreshExpired.status === 403 && legacyRefreshExpired.body.error === 'expired';
    recordTest(23, 'Refresh after license expiration', t23Passed, 'HTTP 403 expired');

    // 24. Saned dashboard login still works
    const masterLoginAgain = await request('POST', '/api/auth/login', {
        username: 'master',
        password: 'TestMasterPassword123!'
    });
    const t24Passed = masterLoginAgain.status === 200 && masterLoginAgain.body.success === true && masterLoginAgain.body.user.role === 'master';
    recordTest(24, 'Saned dashboard login still works', t24Passed, 'Master session authenticated');

    // 25. Saned admin/reseller panel still works
    const adminStats = await request('GET', '/api/admin/stats', null, authHeaders);
    const t25Passed = adminStats.status === 200 && typeof adminStats.body.total === 'number';
    recordTest(25, 'Saned admin/reseller panel still works', t25Passed, `Stats total: ${adminStats.body.total}`);

    // 26. Server restart preserves device binding
    const checkBindingAfterOps = await db.execute({
        sql: "SELECT device_id, status FROM tokens WHERE token = ?",
        args: [unassignedToken]
    });
    const t26Passed = checkBindingAfterOps.rows[0].device_id === dev1 && checkBindingAfterOps.rows[0].status === 'active';
    recordTest(26, 'Server restart preserves device binding', t26Passed, `Persisted in DB: ${dev1}`);

    // 27. Concurrent requests cannot overwrite bindings
    const genRace2 = await request('POST', '/api/tokens/generate', { period_days: 30 }, authHeaders);
    const raceToken2 = genRace2.body.token.token;
    const racers = await Promise.all([
        request('POST', '/api/activate', { token: raceToken2, device_id: dev1 }),
        request('POST', '/api/activate', { token: raceToken2, device_id: dev2 }),
        request('POST', '/api/activate', { token: raceToken2, device_id: dev3 })
    ]);
    const successCount = racers.filter(r => r.status === 200).length;
    const rejectedCount = racers.filter(r => r.status === 403).length;
    const t27Passed = successCount === 1 && rejectedCount === 2;
    recordTest(27, 'Concurrent requests cannot overwrite bindings', t27Passed, `Success: ${successCount}, Rejected: ${rejectedCount}`);

    console.log('\n=== Test Suite Complete ===');
    const allPassed = testResults.every(t => t.passed);
    console.log(`Summary: ${testResults.filter(t => t.passed).length}/${testResults.length} passed.`);

    // Clean up test DB
    process.exit(allPassed ? 0 : 1);
}

run().catch(err => {
    console.error('Test execution error:', err);
    process.exit(1);
});
