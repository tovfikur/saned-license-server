const http = require('http');
const assert = require('assert');

process.env.TURSO_DATABASE_URL = 'file:./test-calc.db';
process.env.MASTER_PASSWORD = 'testmasterpass';
process.env.PORT = '8995';

const { db, initDB } = require('../lib/db');

function request(options, body) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                let parsed = null;
                try { parsed = JSON.parse(data); } catch (_) { parsed = data; }
                resolve({ status: res.statusCode, headers: res.headers, body: parsed });
            });
        });
        req.on('error', reject);
        if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
        req.end();
    });
}

async function runTests() {
    console.log('=== Testing Pre-Calculator & Order Receipt Index ===');

    // Start server
    require('../server.js');
    await new Promise(r => setTimeout(r, 1200));

    // 1. Login as Master
    const loginRes = await request({
        hostname: 'localhost',
        port: 8995,
        path: '/api/auth/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    }, { username: 'master', password: 'testmasterpass' });

    assert.strictEqual(loginRes.status, 200, 'Login failed');
    const cookie = loginRes.headers['set-cookie'][0].split(';')[0];

    // 2. Clear existing telemetry
    const clearRes = await request({
        hostname: 'localhost',
        port: 8995,
        path: '/api/logs/clear',
        method: 'DELETE',
        headers: { Cookie: cookie }
    });
    assert.strictEqual(clearRes.status, 200);

    // 3. Post a batch of events
    const testLogs = [
        {
            tag: 'ORDER_RECEIVED',
            orderId: 990011,
            deviceId: 'device-ahmed-123',
            responseBody: 'Order arrived'
        },
        {
            tag: 'ACCEPT_REQUEST',
            orderId: 990011,
            deviceId: 'device-ahmed-123',
            httpCode: 0
        },
        {
            tag: 'ACCEPT_SUCCESS',
            orderId: 990011,
            deviceId: 'device-ahmed-123',
            httpCode: 200,
            durationMs: 142,
            responseBody: 'Accepted successfully'
        },
        {
            tag: 'ORDER_RECEIVED',
            orderId: 990022,
            deviceId: 'device-khalid-456'
        },
        {
            tag: 'ACCEPT_FAILED',
            orderId: 990022,
            deviceId: 'device-khalid-456',
            httpCode: 409,
            error: 'Order already assigned'
        }
    ];

    const postRes = await request({
        hostname: 'localhost',
        port: 8995,
        path: '/api/logs',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    }, testLogs);

    assert.strictEqual(postRes.status, 200);
    assert.strictEqual(postRes.body.calculator.total, 5, 'Total should be 5');
    assert.strictEqual(postRes.body.calculator.success, 1, 'Success should be 1');
    assert.strictEqual(postRes.body.calculator.failed, 1, 'Failed should be 1');
    assert.strictEqual(postRes.body.calculator.orderEvents, 5, 'Order events should be 5');
    console.log('✅ PASS: Telemetry ingestion calculated stats pre-emptively without log scans');

    // 4. Verify /api/admin/orders-index
    const indexRes = await request({
        hostname: 'localhost',
        port: 8995,
        path: '/api/admin/orders-index',
        method: 'GET',
        headers: { Cookie: cookie }
    });

    assert.strictEqual(indexRes.status, 200);
    assert.strictEqual(indexRes.body.orders.length, 2, 'Should index 2 distinct orders');

    const order1 = indexRes.body.orders.find(o => o.orderId === 990011);
    const order2 = indexRes.body.orders.find(o => o.orderId === 990022);

    assert(order1, 'Order 990011 missing');
    assert.strictEqual(order1.deviceId, 'device-ahmed-123');
    assert.strictEqual(order1.status, 'SUCCESS');

    assert(order2, 'Order 990022 missing');
    assert.strictEqual(order2.deviceId, 'device-khalid-456');
    assert.strictEqual(order2.status, 'FAILED');
    console.log('✅ PASS: Order index accurately recorded which device received which order');

    // 5. Verify /api/admin/stats includes calculator
    const statsRes = await request({
        hostname: 'localhost',
        port: 8995,
        path: '/api/admin/stats',
        method: 'GET',
        headers: { Cookie: cookie }
    });

    assert.strictEqual(statsRes.status, 200);
    assert.strictEqual(statsRes.body.calculator.total, 5);
    assert.strictEqual(statsRes.body.calculator.success, 1);
    assert.strictEqual(statsRes.body.calculator.failed, 1);
    assert.strictEqual(statsRes.body.calculator.orderEvents, 5);
    console.log('✅ PASS: Admin stats includes pre-calculator');

    console.log('\n=== All Calculator & Order Receipt Index Tests Passed Successfully! ===');
    process.exit(0);
}

runTests().catch(e => {
    console.error('Test failed:', e);
    process.exit(1);
});
