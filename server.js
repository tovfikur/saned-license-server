if (typeof process.loadEnvFile === 'function') {
    try { process.loadEnvFile(); } catch (_) {}
}

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { db, initDB, cleanupOldLogs, RETENTION_MS, PERIODS, DB_MODE, DB_SOURCE } = require('./lib/db');
const { hashPassword, verifyPassword } = require('./lib/security');
const {
    createSession,
    destroySession,
    deleteUserSessions,
    getSessionUser,
    setSessionCookie,
    clearSessionCookie
} = require('./lib/auth');
const { readJsonBody, sendJson, sendHtml, redirect, getClientIp } = require('./lib/http');
const { activateLicense, verifyLicense } = require('./lib/license-service');
const { handleLegacyLogin, handleLegacyRefresh } = require('./lib/legacy-adapter');

const PORT = process.env.PORT || 8888;
const PUBLIC_DIR = path.join(__dirname, 'public');

const CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const SECRET_SALT = 'AWS_PRO_REALTIME_LICENSE_SECURE_2026';
const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 5;

const pageCache = new Map();
const loginAttempts = new Map();

// In-memory telemetry log buffer for remote device debugging (up to 2000 entries)
const orderLogs = [];
const MAX_LOGS = 2000;

// Device Security: Blocklist & Unverified ID tracking
const blockedDevices = new Set();
const unverifiedDevices = new Map(); // deviceId -> { deviceId, lastSeen, ip, lastTag, lastUrl, count }
const verifiedDevicesCache = new Map(); // deviceId -> { verified: boolean, time: number }

async function checkIsDeviceVerified(deviceId) {
    if (!deviceId || deviceId === 'unknown' || deviceId === 'unknown-device') return false;
    const devKey = deviceId.trim().toLowerCase();
    if (blockedDevices.has(devKey)) return false;
    const cached = verifiedDevicesCache.get(devKey);
    if (cached && (Date.now() - cached.time < 60000)) {
        return cached.verified;
    }
    try {
        const res = await db.execute({
            sql: "SELECT token FROM tokens WHERE LOWER(device_id) = ? AND status = 'active' LIMIT 1",
            args: [devKey]
        });
        const verified = res.rows.length > 0;
        verifiedDevicesCache.set(devKey, { verified, time: Date.now() });
        return verified;
    } catch {
        return false;
    }
}

// Pre-calculated live telemetry statistics (0ms calculator, no log scans needed)
const telemetryStats = {
    total: 0,
    success: 0,
    failed: 0,
    orderEvents: 0,
    lastUpdated: Date.now()
};

function generate16CharToken() {
    let token = '';
    const bytes = crypto.randomBytes(16);
    for (let i = 0; i < 16; i++) {
        token += CHARS[bytes[i] % CHARS.length];
    }
    return token;
}

function isValidTokenFormat(token) {
    if (typeof token !== 'string') return false;
    const trimmed = token.trim();
    if (trimmed.length < 6 || trimmed.length > 64) return false;
    for (let i = 0; i < trimmed.length; i++) {
        const c = trimmed[i];
        if (!CHARS.includes(c) && c !== '-' && c !== '_') return false;
    }
    return true;
}

async function createUniqueToken(executor) {
    for (;;) {
        const token = generate16CharToken();
        const check = await executor.execute({ sql: 'SELECT token FROM tokens WHERE LOWER(token) = LOWER(?)', args: [token] });
        if (check.rows.length === 0) return token;
    }
}

function loadPage(name) {
    if (!pageCache.has(name)) {
        pageCache.set(name, fs.readFileSync(path.join(PUBLIC_DIR, name), 'utf8'));
    }
    return pageCache.get(name);
}

function sendPage(res, name) {
    try {
        sendHtml(res, 200, loadPage(name));
    } catch (err) {
        console.error('[UI] Failed to load page:', name, err.message);
        sendHtml(res, 500, '<h1>UI unavailable</h1>');
    }
}

function checkLoginLimit(ip) {
    const entry = loginAttempts.get(ip);
    if (!entry) return { allowed: true };
    if (entry.resetAt < Date.now()) {
        loginAttempts.delete(ip);
        return { allowed: true };
    }
    if (entry.count >= LOGIN_MAX_FAILURES) {
        return { allowed: false, retryAfter: Math.ceil((entry.resetAt - Date.now()) / 1000) };
    }
    return { allowed: true };
}

function recordLoginFailure(ip) {
    const now = Date.now();
    const entry = loginAttempts.get(ip);
    if (!entry || entry.resetAt < now) {
        loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
        return;
    }
    entry.count += 1;
}

function formatToken(row, now) {
    let status = row.status;
    if (status === 'active' && row.expires_at && now > Number(row.expires_at)) {
        status = 'expired';
    }
    return {
        token: String(row.token),
        periodDays: Number(row.period_days),
        createdAt: Number(row.created_at),
        activatedAt: row.activated_at ? Number(row.activated_at) : null,
        expiresAt: row.expires_at ? Number(row.expires_at) : null,
        deviceId: String(row.device_id || ''),
        note: row.note || '',
        status: status,
        resellerId: row.reseller_id ? String(row.reseller_id) : null,
        ownerName: row.reseller_username ? String(row.reseller_username) : 'Master'
    };
}

async function requireMaster(req, res) {
    const user = await getSessionUser(req);
    if (!user) {
        sendJson(res, 401, { success: false, message: 'Authentication required' });
        return null;
    }
    if (user.role !== 'master') {
        sendJson(res, 403, { success: false, message: 'Master access required' });
        return null;
    }
    return user;
}

function quotaList(rows) {
    const map = new Map();
    rows.forEach(row => map.set(Number(row.period_days), {
        periodDays: Number(row.period_days),
        maxTokens: Number(row.max_tokens),
        usedCount: Number(row.used_count)
    }));
    return PERIODS.map(period => map.get(period) || { periodDays: period, maxTokens: 0, usedCount: 0 });
}

async function handleRequest(req, res) {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const method = req.method;

    if (['/api/verify', '/api/activate', '/api/health', '/api/logs', '/api/telemetry', '/api/legacy/auth/login', '/api/legacy/auth/refresh'].includes(pathname)) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-device-id, X-App-Version, X-App-Cert, X-Nonce');
    }

    if (method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // Blocked Device Enforcement
    const headerDev = (req.headers['x-device-id'] || '').trim().toLowerCase();
    if (headerDev && blockedDevices.has(headerDev) && !pathname.startsWith('/api/devices/')) {
        return sendJson(res, 403, { success: false, error: 'Device is blocked by administrator', blocked: true });
    }

    if (pathname === '/api/health' && method === 'GET') {
        return sendJson(res, 200, { status: 'ok', time: Date.now(), database: DB_MODE, dbSource: DB_SOURCE });
    }

    // ---------------------------------------------------------------- Device Security & Blocklist Routes
    if (pathname === '/api/devices/unverified' && method === 'GET') {
        const list = Array.from(unverifiedDevices.values()).sort((a, b) => b.lastSeen - a.lastSeen);
        return sendJson(res, 200, { success: true, count: list.length, unverified: list });
    }

    if (pathname === '/api/devices/blocked' && method === 'GET') {
        try {
            const rows = await db.execute('SELECT device_id, reason, blocked_at FROM blocked_devices ORDER BY blocked_at DESC');
            return sendJson(res, 200, {
                success: true,
                count: rows.rows.length,
                blocked: rows.rows.map(r => ({ deviceId: String(r.device_id), reason: r.reason || '', blockedAt: Number(r.blocked_at) }))
            });
        } catch (e) {
            return sendJson(res, 200, { success: true, count: 0, blocked: [] });
        }
    }

    if (pathname === '/api/devices/block' && method === 'POST') {
        try {
            const body = await readJsonBody(req);
            const targetId = String(body.deviceId || body.device_id || '').trim();
            const reason = String(body.reason || 'Blocked by administrator via Live Console').trim();
            if (!targetId) {
                return sendJson(res, 400, { success: false, error: 'Device ID is required' });
            }

            const targetKey = targetId.toLowerCase();
            blockedDevices.add(targetKey);
            unverifiedDevices.delete(targetKey);
            verifiedDevicesCache.delete(targetKey);

            await db.execute({
                sql: 'INSERT OR REPLACE INTO blocked_devices (device_id, reason, blocked_at) VALUES (?, ?, ?)',
                args: [targetId, reason, Date.now()]
            });

            // Automatically revoke any tokens linked to this device
            await db.execute({
                sql: "UPDATE tokens SET status = 'revoked', note = CASE WHEN note IS NULL OR note = '' THEN '[BLOCKED]' ELSE note || ' [BLOCKED]' END WHERE LOWER(device_id) = ?",
                args: [targetKey]
            }).catch(() => {});

            console.log(`[Security] Blocked device: ${targetId} (Reason: ${reason})`);
            return sendJson(res, 200, { success: true, message: `Device ${targetId} has been blocked immediately`, deviceId: targetId });
        } catch (err) {
            return sendJson(res, 500, { success: false, error: err.message });
        }
    }

    if (pathname === '/api/devices/unblock' && method === 'POST') {
        try {
            const body = await readJsonBody(req);
            const targetId = String(body.deviceId || body.device_id || '').trim();
            if (!targetId) {
                return sendJson(res, 400, { success: false, error: 'Device ID is required' });
            }

            const targetKey = targetId.toLowerCase();
            blockedDevices.delete(targetKey);
            verifiedDevicesCache.delete(targetKey);

            await db.execute({
                sql: 'DELETE FROM blocked_devices WHERE LOWER(device_id) = ?',
                args: [targetKey]
            });

            // Restore any tokens linked to this device that were marked revoked or blocked
            try {
                const devTokens = await db.execute({
                    sql: "SELECT token, activated_at, expires_at, note, status FROM tokens WHERE LOWER(device_id) = ?",
                    args: [targetKey]
                });
                const now = Date.now();
                for (const row of devTokens.rows) {
                    if ((row.note && row.note.includes('[BLOCKED]')) || row.status === 'revoked') {
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
                    }
                }
            } catch (_) {}

            console.log(`[Security] Unblocked device: ${targetId}`);
            return sendJson(res, 200, { success: true, message: `Device ${targetId} unblocked and licenses restored`, deviceId: targetId });
        } catch (err) {
            return sendJson(res, 500, { success: false, error: err.message });
        }
    }

    if (pathname === '/api/devices/unblock-all' && method === 'POST') {
        try {
            blockedDevices.clear();
            verifiedDevicesCache.clear();

            await db.execute('DELETE FROM blocked_devices');

            // Restore all tokens that were revoked or marked with [BLOCKED]
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
            }

            console.log('[Security] Unblocked ALL devices and restored licenses');
            return sendJson(res, 200, { success: true, message: 'All devices have been unblocked and licenses restored' });
        } catch (err) {
            return sendJson(res, 500, { success: false, error: err.message });
        }
    }

    // ---------------------------------------------------------------- Telemetry / Logging API
    if ((pathname === '/api/logs' || pathname === '/api/telemetry') && method === 'POST') {
        try {
            const rawBody = await readJsonBody(req);
            const items = Array.isArray(rawBody) ? rawBody : (Array.isArray(rawBody.batch) ? rawBody.batch : [rawBody]);
            const now = Date.now();
            const clientIp = getClientIp(req);

            let incTotal = 0;
            let incSuccess = 0;
            let incFailed = 0;
            let incOrder = 0;
            const dbBatch = [];

            for (const body of items) {
                if (!body || typeof body !== 'object') continue;
                const tag = String(body.tag || 'TELEMETRY').toUpperCase();
                const orderId = parseInt(body.orderId || body.order_id || 0, 10);
                const deviceId = String(body.deviceId || body.device_id || req.headers['x-device-id'] || 'unknown');
                const devKey = deviceId.trim().toLowerCase();

                // Drop logs from blocked devices
                if (devKey && blockedDevices.has(devKey)) {
                    continue;
                }

                const isVerified = await checkIsDeviceVerified(deviceId);
                if (!isVerified && deviceId !== 'unknown' && deviceId !== 'unknown-device') {
                    const existingUnverified = unverifiedDevices.get(devKey);
                    unverifiedDevices.set(devKey, {
                        deviceId: deviceId,
                        lastSeen: now,
                        ip: clientIp,
                        lastTag: tag,
                        lastUrl: String(body.url || ''),
                        count: (existingUnverified ? existingUnverified.count + 1 : 1)
                    });
                }

                const httpCode = body.httpCode !== undefined ? Number(body.httpCode) : (body.status !== undefined ? Number(body.status) : 0);
                const error = String(body.error || '');
                const durationMs = Number(body.durationMs || 0);

                incTotal++;
                const isSuccess = (tag === 'ACCEPT_SUCCESS') || (httpCode >= 200 && httpCode < 300 && (tag.includes('ACCEPT') || tag.includes('DISPATCH')));
                const isFailed = (tag === 'ACCEPT_FAILED') || (tag === 'CRASH') || (httpCode >= 400) || (error && error.length > 0 && tag.includes('ACCEPT'));
                const isOrderEvent = orderId > 0 || tag.startsWith('ORDER_') || tag.includes('ACCEPT') || tag.includes('FAILOVER');

                if (isSuccess) incSuccess++;
                if (isFailed) incFailed++;
                if (isOrderEvent) incOrder++;

                const logEntry = {
                    id: now + '-' + Math.random().toString(36).substring(2, 7),
                    timestamp: body.timestamp || now,
                    receivedAt: now,
                    ip: clientIp,
                    tag: tag,
                    orderId: orderId,
                    deviceId: deviceId,
                    unverified: !isVerified,
                    url: String(body.url || ''),
                    method: String(body.method || 'GET').toUpperCase(),
                    headers: body.headers || {},
                    httpCode: httpCode,
                    responseBody: typeof body.responseBody === 'string' ? body.responseBody : (body.response ? JSON.stringify(body.response) : ''),
                    durationMs: durationMs,
                    error: error,
                    details: body.details || null
                };

                orderLogs.unshift(logEntry);
                if (orderLogs.length > MAX_LOGS) {
                    orderLogs.length = MAX_LOGS;
                }

                // Add to persistent telemetry log batch
                dbBatch.push({
                    sql: `INSERT OR REPLACE INTO telemetry_logs 
                          (id, timestamp, received_at, ip, tag, order_id, device_id, url, method, headers_json, http_code, response_body, duration_ms, error, details_json)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    args: [
                        logEntry.id,
                        logEntry.timestamp,
                        logEntry.receivedAt,
                        logEntry.ip,
                        logEntry.tag,
                        logEntry.orderId,
                        logEntry.deviceId,
                        logEntry.url,
                        logEntry.method,
                        logEntry.headers && Object.keys(logEntry.headers).length > 0 ? JSON.stringify(logEntry.headers) : null,
                        logEntry.httpCode,
                        logEntry.responseBody,
                        logEntry.durationMs,
                        logEntry.error,
                        logEntry.details ? JSON.stringify(logEntry.details) : null
                    ]
                });

                // Pre-index order receipt so we know which order who (device ID) received
                if (orderId > 0) {
                    let orderStatus = 'RECEIVED';
                    if (tag === 'ACCEPT_SUCCESS') orderStatus = 'SUCCESS';
                    else if (tag === 'ACCEPT_FAILED' || tag === 'CRASH') orderStatus = 'FAILED';
                    else if (tag === 'ORDER_EVALUATION') orderStatus = 'EVALUATING';
                    else if (tag === 'FAILOVER_REPAIRED') orderStatus = 'REPAIRED';
                    else if (tag === 'ACCEPT_REQUEST') orderStatus = 'ACCEPTING';

                    dbBatch.push({
                        sql: `INSERT INTO order_index (order_id, device_id, first_seen_at, last_updated_at, status, last_tag, http_code, details)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                              ON CONFLICT(order_id) DO UPDATE SET
                                  device_id = excluded.device_id,
                                  last_updated_at = excluded.last_updated_at,
                                  status = CASE 
                                      WHEN excluded.status = 'SUCCESS' THEN 'SUCCESS'
                                      WHEN order_index.status = 'SUCCESS' THEN 'SUCCESS'
                                      ELSE excluded.status
                                  END,
                                  last_tag = excluded.last_tag,
                                  http_code = CASE WHEN excluded.http_code > 0 THEN excluded.http_code ELSE order_index.http_code END,
                                  details = COALESCE(excluded.details, order_index.details)`,
                        args: [
                            orderId,
                            deviceId,
                            now,
                            now,
                            orderStatus,
                            tag,
                            httpCode,
                            logEntry.responseBody ? logEntry.responseBody.substring(0, 200) : ''
                        ]
                    });
                }
            }

            // Update in-memory calculator stats immediately (0ms)
            telemetryStats.total += incTotal;
            telemetryStats.success += incSuccess;
            telemetryStats.failed += incFailed;
            telemetryStats.orderEvents += incOrder;
            telemetryStats.lastUpdated = now;

            // Increment persistent summary in Turso
            dbBatch.push({
                sql: `UPDATE telemetry_summary 
                      SET total_events = total_events + ?,
                          success_events = success_events + ?,
                          failed_events = failed_events + ?,
                          order_events = order_events + ?,
                          last_updated_at = ?
                      WHERE id = 'global'`,
                args: [incTotal, incSuccess, incFailed, incOrder, now]
            });

            // Single network batch execute to Turso
            if (dbBatch.length > 0) {
                db.batch(dbBatch).catch(e => console.error('[Turso Batch Error]:', e.message));
            }

            return sendJson(res, 200, {
                success: true,
                count: orderLogs.length,
                ingested: items.length,
                calculator: telemetryStats
            });
        } catch (err) {
            console.error('[TELEMETRY] Ingestion error:', err.message);
            return sendJson(res, 400, { success: false, message: 'Invalid JSON payload: ' + err.message });
        }
    }

    // ---------------------------------------------------------------- Telemetry / Debug Log Routes
    if ((pathname === '/api/logs/clear' || pathname === '/api/telemetry/clear') ||
        ((pathname === '/api/logs' || pathname === '/api/telemetry') && (method === 'DELETE' || parsedUrl.searchParams.get('clear') === 'true'))) {
        const targetDevice = (parsedUrl.searchParams.get('deviceId') || '').trim().toLowerCase();
        if (targetDevice) {
            await db.execute({ sql: 'DELETE FROM telemetry_logs WHERE LOWER(device_id) = ?', args: [targetDevice] }).catch(() => {});
            await db.execute({ sql: 'DELETE FROM order_index WHERE LOWER(device_id) = ?', args: [targetDevice] }).catch(() => {});
            const before = orderLogs.length;
            for (let i = orderLogs.length - 1; i >= 0; i--) {
                if (orderLogs[i].deviceId && orderLogs[i].deviceId.toLowerCase() === targetDevice) {
                    orderLogs.splice(i, 1);
                }
            }
            return sendJson(res, 200, { success: true, message: `Cleared persistent logs for device ${targetDevice}`, count: orderLogs.length, removed: before - orderLogs.length });
        } else {
            await db.execute('DELETE FROM telemetry_logs').catch(() => {});
            await db.execute('DELETE FROM order_index').catch(() => {});
            await db.execute({
                sql: "UPDATE telemetry_summary SET total_events = 0, success_events = 0, failed_events = 0, order_events = 0, last_updated_at = ? WHERE id = 'global'",
                args: [Date.now()]
            }).catch(() => {});
            telemetryStats.total = 0;
            telemetryStats.success = 0;
            telemetryStats.failed = 0;
            telemetryStats.orderEvents = 0;
            telemetryStats.lastUpdated = Date.now();
            orderLogs.length = 0;
            return sendJson(res, 200, { success: true, message: 'All 36hr logs and pre-calculated statistics reset to 0', count: 0, calculator: telemetryStats });
        }
    }

    if ((pathname === '/api/logs' || pathname === '/api/telemetry') && method === 'GET') {
        const limitParam = (parsedUrl.searchParams.get('limit') || '').toLowerCase();
        let limit = 100; // Sensible default limit to protect server memory
        if (limitParam === 'all' || limitParam === '0' || limitParam === 'full') {
            limit = 2000; // Cap maximum at 2000 to prevent OOM crash
        } else if (limitParam) {
            limit = Math.min(Math.max(parseInt(limitParam, 10), 1), 2000);
        }

        const deviceFilter = (parsedUrl.searchParams.get('deviceId') || '').trim().toLowerCase();
        const orderFilter = (parsedUrl.searchParams.get('orderId') || '').trim();
        const tagFilter = (parsedUrl.searchParams.get('tag') || '').trim().toUpperCase();

        // FAST PATH: If no historical filter is requested and limit is small, serve directly from in-memory cache (< 0.1ms, zero DB latency)
        if (!deviceFilter && !orderFilter && !tagFilter && limitParam !== 'all' && limitParam !== 'full' && limit <= 500) {
            return sendJson(res, 200, {
                success: true,
                total: telemetryStats.total,
                successEvents: telemetryStats.success,
                failedEvents: telemetryStats.failed,
                orderEvents: telemetryStats.orderEvents,
                returned: Math.min(orderLogs.length, limit),
                retention: 'in-memory-fast',
                calculator: telemetryStats,
                logs: orderLogs.slice(0, limit)
            });
        }

        try {
            const retentionWindow = Date.now() - RETENTION_MS;
            let sql = 'SELECT * FROM telemetry_logs WHERE timestamp >= ?';
            const args = [retentionWindow];

            if (deviceFilter) {
                sql += ' AND LOWER(device_id) LIKE ?';
                args.push(`%${deviceFilter}%`);
            }
            if (orderFilter) {
                sql += ' AND order_id = ?';
                args.push(parseInt(orderFilter, 10) || 0);
            }
            if (tagFilter) {
                sql += ' AND tag LIKE ?';
                args.push(`%${tagFilter}%`);
            }

            sql += ' ORDER BY timestamp DESC LIMIT ?';
            args.push(limit);

            const rowsResult = await db.execute({ sql, args });

            const dbLogs = rowsResult.rows.map(row => ({
                id: String(row.id),
                timestamp: Number(row.timestamp),
                receivedAt: Number(row.received_at),
                ip: row.ip,
                tag: row.tag,
                orderId: Number(row.order_id),
                deviceId: row.device_id,
                url: row.url,
                method: row.method,
                headers: row.headers_json ? JSON.parse(row.headers_json) : {},
                httpCode: Number(row.http_code),
                responseBody: row.response_body || '',
                durationMs: Number(row.duration_ms),
                error: row.error || '',
                details: row.details_json ? JSON.parse(row.details_json) : null
            }));

            return sendJson(res, 200, {
                success: true,
                total: telemetryStats.total,
                successEvents: telemetryStats.success,
                failedEvents: telemetryStats.failed,
                orderEvents: telemetryStats.orderEvents,
                returned: dbLogs.length,
                retention: '36hr',
                calculator: telemetryStats,
                logs: dbLogs
            });
        } catch (dbErr) {
            console.error('[Telemetry DB Query Error]', dbErr.message);
            let filtered = orderLogs;
            if (deviceFilter) {
                filtered = filtered.filter(l => l.deviceId.toLowerCase().includes(deviceFilter));
            }
            if (orderFilter) {
                filtered = filtered.filter(l => String(l.orderId) === orderFilter);
            }
            if (tagFilter) {
                filtered = filtered.filter(l => l.tag.includes(tagFilter));
            }

            return sendJson(res, 200, {
                success: true,
                total: telemetryStats.total,
                successEvents: telemetryStats.success,
                failedEvents: telemetryStats.failed,
                orderEvents: telemetryStats.orderEvents,
                returned: Math.min(filtered.length, limit),
                retention: 'memory-fallback',
                calculator: telemetryStats,
                logs: filtered.slice(0, limit)
            });
        }
    }

    // ---------------------------------------------------------------- Legacy Adapter Routes
    const hostHeader = (req.headers.host || '').toLowerCase();
    const isLegacyHost = hostHeader.includes('drivers-dashboard.com') || process.env.IS_LEGACY_HOST === 'true';

    if ((pathname === '/api/legacy/auth/login' || (isLegacyHost && pathname === '/api/auth/login')) && method === 'POST') {
        return handleLegacyLogin(req, res);
    }

    if ((pathname === '/api/legacy/auth/refresh' || (isLegacyHost && pathname === '/api/auth/refresh')) && method === 'POST') {
        return handleLegacyRefresh(req, res);
    }

    // ---------------------------------------------------------------- Client API
    if (pathname === '/api/verify' && method === 'POST') {
        try {
            const body = await readJsonBody(req);
            const result = await verifyLicense({
                token: body.token,
                deviceId: body.device_id
            });
            return sendJson(res, result.statusCode, result.body);
        } catch (err) {
            return sendJson(res, 500, { unlocked: false, message: 'Server error: ' + err.message });
        }
    }

    if (pathname === '/api/activate' && method === 'POST') {
        try {
            const body = await readJsonBody(req);
            const result = await activateLicense({
                token: body.token,
                deviceId: body.device_id
            });
            return sendJson(res, result.statusCode, result.body);
        } catch (err) {
            return sendJson(res, 500, { success: false, unlocked: false, message: 'Server error: ' + err.message });
        }
    }

    // ------------------------------------------------------------------- Auth API
    if (pathname === '/api/auth/login' && method === 'POST') {
        const ip = getClientIp(req);
        const limit = checkLoginLimit(ip);
        if (!limit.allowed) {
            return sendJson(res, 429, { success: false, message: `Too many attempts. Try again in ${limit.retryAfter}s.` });
        }

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        const username = String(body.username || '').trim();
        const password = String(body.password || '');

        if (!username || !password) {
            return sendJson(res, 400, { success: false, message: 'Username and password are required' });
        }

        const result = await db.execute({ sql: 'SELECT * FROM users WHERE username = ?', args: [username] });
        const user = result.rows[0];

        if (!user || !verifyPassword(password, user.password_hash)) {
            recordLoginFailure(ip);
            return sendJson(res, 401, { success: false, message: 'Invalid username or password' });
        }

        if (user.status !== 'active') {
            return sendJson(res, 403, { success: false, message: 'This account has been disabled' });
        }

        loginAttempts.delete(ip);
        const session = await createSession(String(user.id));
        setSessionCookie(res, session.token, session.expiresAt);

        return sendJson(res, 200, {
            success: true,
            user: { id: String(user.id), username: String(user.username), role: String(user.role) }
        });
    }

    if (pathname === '/api/auth/logout' && method === 'POST') {
        const user = await getSessionUser(req);
        if (user) await destroySession(user.sessionToken);
        clearSessionCookie(res);
        return sendJson(res, 200, { success: true });
    }

    if (pathname === '/api/auth/me' && method === 'GET') {
        const user = await getSessionUser(req);
        if (!user) return sendJson(res, 200, { user: null });
        return sendJson(res, 200, { user: { id: user.id, username: user.username, role: user.role } });
    }

    if (pathname === '/api/auth/change-password' && method === 'POST') {
        const user = await getSessionUser(req);
        if (!user) return sendJson(res, 401, { success: false, message: 'Authentication required' });

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        const currentPassword = String(body.current_password || '');
        const newPassword = String(body.new_password || '');

        if (newPassword.length < 8) {
            return sendJson(res, 400, { success: false, message: 'New password must be at least 8 characters' });
        }

        const result = await db.execute({ sql: 'SELECT password_hash FROM users WHERE id = ?', args: [user.id] });
        if (result.rows.length === 0 || !verifyPassword(currentPassword, result.rows[0].password_hash)) {
            return sendJson(res, 400, { success: false, message: 'Current password is incorrect' });
        }

        await db.execute({
            sql: 'UPDATE users SET password_hash = ? WHERE id = ?',
            args: [hashPassword(newPassword), user.id]
        });
        await deleteUserSessions(user.id, user.sessionToken);

        return sendJson(res, 200, { success: true, message: 'Password updated' });
    }

    // ------------------------------------------------------------------- Tokens API
    if (pathname === '/api/tokens' && method === 'GET') {
        const user = await getSessionUser(req);
        if (!user) return sendJson(res, 401, { success: false, message: 'Authentication required' });

        const where = [];
        const args = [];

        if (user.role === 'reseller') {
            where.push('t.reseller_id = ?');
            args.push(user.id);
        } else {
            const resellerFilter = parsedUrl.searchParams.get('reseller_id');
            if (resellerFilter === 'master') {
                where.push('t.reseller_id IS NULL');
            } else if (resellerFilter) {
                where.push('t.reseller_id = ?');
                args.push(resellerFilter);
            }
        }

        const sql = `SELECT t.*, u.username AS reseller_username
                     FROM tokens t LEFT JOIN users u ON u.id = t.reseller_id
                     ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
                     ORDER BY t.created_at DESC`;

        const result = await db.execute({ sql, args });
        const now = Date.now();
        let tokens = result.rows.map(row => formatToken(row, now));

        const statusFilter = parsedUrl.searchParams.get('status');
        if (statusFilter) tokens = tokens.filter(t => t.status === statusFilter);

        return sendJson(res, 200, { tokens });
    }

    if (pathname === '/api/tokens/generate' && method === 'POST') {
        const user = await getSessionUser(req);
        if (!user) return sendJson(res, 401, { success: false, message: 'Authentication required' });

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        const deviceId = body.device_id && String(body.device_id).trim()
            ? String(body.device_id).trim().toLowerCase()
            : null;
        const periodDays = parseInt(body.period_days, 10);
        const note = body.note ? String(body.note).trim().slice(0, 200) : '';
        if (!PERIODS.includes(periodDays)) {
            return sendJson(res, 400, { success: false, message: 'Invalid subscription period' });
        }

        let ownerId = null;
        if (user.role === 'reseller') {
            ownerId = user.id;
        } else if (body.reseller_id) {
            ownerId = String(body.reseller_id);
        }

        if (ownerId) {
            const owner = await db.execute({
                sql: "SELECT id, username, status FROM users WHERE id = ? AND role = 'reseller'",
                args: [ownerId]
            });
            if (owner.rows.length === 0) {
                return sendJson(res, 400, { success: false, message: 'Invalid reseller selected' });
            }
            if (owner.rows[0].status !== 'active') {
                return sendJson(res, 400, { success: false, message: 'Selected reseller is disabled' });
            }
        }

        const now = Date.now();

        if (!ownerId) {
            const token = await createUniqueToken(db);
            await db.execute({
                sql: `INSERT INTO tokens (token, period_days, created_at, activated_at, expires_at, device_id, note, status, reseller_id)
                      VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, NULL)`,
                args: [token, periodDays, now, deviceId, note, 'available']
            });
            return sendJson(res, 201, {
                success: true,
                token: {
                    token,
                    periodDays,
                    createdAt: now,
                    activatedAt: null,
                    expiresAt: null,
                    deviceId,
                    note,
                    status: 'available',
                    resellerId: null,
                    ownerName: 'Master'
                }
            });
        }

        const tx = await db.transaction('write');
        try {
            const quota = await tx.execute({
                sql: 'SELECT max_tokens, used_count FROM reseller_quotas WHERE user_id = ? AND period_days = ?',
                args: [ownerId, periodDays]
            });

            if (quota.rows.length === 0 || Number(quota.rows[0].max_tokens) <= 0) {
                await tx.rollback();
                return sendJson(res, 403, { success: false, message: `This reseller is blocked from generating ${periodDays}-day tokens` });
            }
            if (Number(quota.rows[0].used_count) >= Number(quota.rows[0].max_tokens)) {
                await tx.rollback();
                return sendJson(res, 403, { success: false, message: `Quota reached for ${periodDays}-day tokens` });
            }

            const token = await createUniqueToken(tx);
            await tx.execute({
                sql: `INSERT INTO tokens (token, period_days, created_at, activated_at, expires_at, device_id, note, status, reseller_id)
                      VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?)`,
                args: [token, periodDays, now, deviceId, note, 'available', ownerId]
            });
            await tx.execute({
                sql: 'UPDATE reseller_quotas SET used_count = used_count + 1 WHERE user_id = ? AND period_days = ?',
                args: [ownerId, periodDays]
            });
            await tx.commit();

            return sendJson(res, 201, {
                success: true,
                token: {
                    token,
                    periodDays,
                    createdAt: now,
                    activatedAt: null,
                    expiresAt: null,
                    deviceId,
                    note,
                    status: 'available',
                    resellerId: ownerId,
                    ownerName: ''
                }
            });
        } catch (err) {
            try { await tx.rollback(); } catch (e) { /* already closed */ }
            throw err;
        }
    }

    if (pathname === '/api/tokens/revoke' && method === 'POST') {
        const user = await getSessionUser(req);
        if (!user) return sendJson(res, 401, { success: false, message: 'Authentication required' });

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        const tokenStr = String(body.token || '').trim();
        if (!tokenStr) return sendJson(res, 400, { success: false, message: 'Missing token' });

        const result = await db.execute({ sql: 'SELECT token, reseller_id FROM tokens WHERE LOWER(token) = LOWER(?)', args: [tokenStr] });
        if (result.rows.length === 0) return sendJson(res, 404, { success: false, message: 'Token not found' });

        if (user.role === 'reseller' && String(result.rows[0].reseller_id || '') !== user.id) {
            return sendJson(res, 403, { success: false, message: 'You can only revoke your own tokens' });
        }

        await db.execute({
            sql: 'UPDATE tokens SET status = ? WHERE LOWER(token) = LOWER(?)',
            args: ['revoked', tokenStr]
        });
        return sendJson(res, 200, { success: true, message: 'Token revoked' });
    }

    if (pathname === '/api/tokens/delete' && method === 'POST') {
        const user = await getSessionUser(req);
        if (!user) return sendJson(res, 401, { success: false, message: 'Authentication required' });
        if (user.role !== 'master') {
            return sendJson(res, 403, { success: false, message: 'Only the master account can delete tokens' });
        }

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        if (!body.token) return sendJson(res, 400, { success: false, message: 'Missing token' });
        await db.execute({
            sql: 'DELETE FROM tokens WHERE LOWER(token) = LOWER(?)',
            args: [String(body.token).trim()]
        });
        return sendJson(res, 200, { success: true, message: 'Token deleted' });
    }

    // ---------------------------------------------------------------- Reseller API
    if (pathname === '/api/me/quotas' && method === 'GET') {
        const user = await getSessionUser(req);
        if (!user) return sendJson(res, 401, { success: false, message: 'Authentication required' });
        if (user.role !== 'reseller') return sendJson(res, 200, { quotas: [] });

        const result = await db.execute({
            sql: 'SELECT period_days, max_tokens, used_count FROM reseller_quotas WHERE user_id = ? ORDER BY period_days ASC',
            args: [user.id]
        });
        const quotas = quotaList(result.rows).map(q => ({
            ...q,
            remaining: Math.max(0, q.maxTokens - q.usedCount)
        }));
        return sendJson(res, 200, { quotas });
    }

    // ------------------------------------------------------------------ Admin API
    if (pathname === '/api/admin/stats' && method === 'GET') {
        if (!(await requireMaster(req, res))) return;

        const tokens = await db.execute('SELECT status, expires_at FROM tokens');
        const now = Date.now();
        const stats = { total: 0, active: 0, available: 0, expired: 0, revoked: 0 };
        tokens.rows.forEach(row => {
            let status = row.status;
            if (status === 'active' && row.expires_at && now > Number(row.expires_at)) status = 'expired';
            stats.total += 1;
            if (stats[status] !== undefined) stats[status] += 1;
        });

        const resellers = await db.execute("SELECT status, COUNT(*) AS c FROM users WHERE role = 'reseller' GROUP BY status");
        stats.resellers = 0;
        stats.resellersDisabled = 0;
        resellers.rows.forEach(row => {
            stats.resellers += Number(row.c);
            if (row.status === 'disabled') stats.resellersDisabled += Number(row.c);
        });

        // Instant pre-calculated calculator stats (0ms, no full logs scan)
        stats.calculator = {
            total: telemetryStats.total,
            success: telemetryStats.success,
            failed: telemetryStats.failed,
            orderEvents: telemetryStats.orderEvents,
            lastUpdated: telemetryStats.lastUpdated
        };

        return sendJson(res, 200, stats);
    }

    if (pathname === '/api/admin/orders-index' && method === 'GET') {
        if (!(await requireMaster(req, res))) return;

        const limit = Math.min(Math.max(parseInt(parsedUrl.searchParams.get('limit') || '50', 10), 1), 200);
        try {
            const rows = await db.execute({
                sql: `SELECT order_id, device_id, first_seen_at, last_updated_at, status, last_tag, http_code, details 
                      FROM order_index 
                      ORDER BY last_updated_at DESC 
                      LIMIT ?`,
                args: [limit]
            });
            return sendJson(res, 200, {
                success: true,
                calculator: {
                    total: telemetryStats.total,
                    success: telemetryStats.success,
                    failed: telemetryStats.failed,
                    orderEvents: telemetryStats.orderEvents,
                    lastUpdated: telemetryStats.lastUpdated
                },
                orders: rows.rows.map(r => ({
                    orderId: Number(r.order_id),
                    deviceId: String(r.device_id || ''),
                    firstSeenAt: Number(r.first_seen_at),
                    lastUpdatedAt: Number(r.last_updated_at),
                    status: String(r.status || 'RECEIVED'),
                    lastTag: String(r.last_tag || ''),
                    httpCode: Number(r.http_code || 0),
                    details: r.details || ''
                }))
            });
        } catch (e) {
            return sendJson(res, 500, { success: false, message: e.message });
        }
    }

    if (pathname === '/api/admin/telemetry-stats' && method === 'GET') {
        if (!(await requireMaster(req, res))) return;
        return sendJson(res, 200, {
            success: true,
            calculator: telemetryStats
        });
    }

    if (pathname === '/api/admin/resellers' && method === 'GET') {
        if (!(await requireMaster(req, res))) return;

        const users = await db.execute("SELECT id, username, status, created_at FROM users WHERE role = 'reseller' ORDER BY created_at DESC");
        const quotas = await db.execute('SELECT user_id, period_days, max_tokens, used_count FROM reseller_quotas');
        const counts = await db.execute("SELECT reseller_id, COUNT(*) AS c FROM tokens WHERE reseller_id IS NOT NULL GROUP BY reseller_id");

        const quotaMap = new Map();
        quotas.rows.forEach(row => {
            const key = String(row.user_id);
            if (!quotaMap.has(key)) quotaMap.set(key, []);
            quotaMap.get(key).push(row);
        });
        const countMap = new Map();
        counts.rows.forEach(row => countMap.set(String(row.reseller_id), Number(row.c)));

        const resellers = users.rows.map(row => {
            const id = String(row.id);
            const list = quotaList(quotaMap.get(id) || []);
            return {
                id,
                username: String(row.username),
                status: String(row.status),
                createdAt: Number(row.created_at),
                tokenCount: countMap.get(id) || 0,
                quotas: list.map(q => ({ ...q, remaining: Math.max(0, q.maxTokens - q.usedCount) }))
            };
        });

        return sendJson(res, 200, { resellers });
    }

    if (pathname === '/api/admin/resellers' && method === 'POST') {
        if (!(await requireMaster(req, res))) return;

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        const username = String(body.username || '').trim();
        const password = String(body.password || '');

        if (!USERNAME_RE.test(username)) {
            return sendJson(res, 400, { success: false, message: 'Username must be 3-32 characters (letters, numbers, . _ -)' });
        }
        if (password.length < 8) {
            return sendJson(res, 400, { success: false, message: 'Password must be at least 8 characters' });
        }

        const existing = await db.execute({ sql: 'SELECT id FROM users WHERE username = ?', args: [username] });
        if (existing.rows.length > 0) {
            return sendJson(res, 409, { success: false, message: 'Username already exists' });
        }

        const id = crypto.randomBytes(16).toString('hex');
        const now = Date.now();

        await db.execute({
            sql: 'INSERT INTO users (id, username, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            args: [id, username, hashPassword(password), 'reseller', 'active', now]
        });

        for (const period of PERIODS) {
            await db.execute({
                sql: 'INSERT INTO reseller_quotas (user_id, period_days, max_tokens, used_count) VALUES (?, ?, 0, 0)',
                args: [id, period]
            });
        }

        return sendJson(res, 201, {
            success: true,
            reseller: { id, username, status: 'active', createdAt: now, tokenCount: 0, quotas: quotaList([]) }
        });
    }

    if (pathname === '/api/admin/resellers/update' && method === 'POST') {
        if (!(await requireMaster(req, res))) return;

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        const userId = String(body.user_id || '');
        if (!userId) return sendJson(res, 400, { success: false, message: 'Missing user_id' });

        const target = await db.execute({ sql: "SELECT id, username, status FROM users WHERE id = ? AND role = 'reseller'", args: [userId] });
        if (target.rows.length === 0) return sendJson(res, 404, { success: false, message: 'Reseller not found' });

        if (body.username !== undefined) {
            const username = String(body.username || '').trim();
            if (!USERNAME_RE.test(username)) {
                return sendJson(res, 400, { success: false, message: 'Username must be 3-32 characters (letters, numbers, . _ -)' });
            }
            const existing = await db.execute({ sql: 'SELECT id FROM users WHERE username = ? AND id != ?', args: [username, userId] });
            if (existing.rows.length > 0) {
                return sendJson(res, 409, { success: false, message: 'Username already exists' });
            }
            await db.execute({ sql: 'UPDATE users SET username = ? WHERE id = ?', args: [username, userId] });
        }

        if (body.password !== undefined) {
            const password = String(body.password || '');
            if (password.length < 8) {
                return sendJson(res, 400, { success: false, message: 'Password must be at least 8 characters' });
            }
            await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hashPassword(password), userId] });
            await deleteUserSessions(userId);
        }

        if (body.status !== undefined) {
            const status = String(body.status || '');
            if (!['active', 'disabled'].includes(status)) {
                return sendJson(res, 400, { success: false, message: 'Invalid status' });
            }
            await db.execute({ sql: 'UPDATE users SET status = ? WHERE id = ?', args: [status, userId] });
            if (status === 'disabled') await deleteUserSessions(userId);
        }

        return sendJson(res, 200, { success: true });
    }

    if (pathname === '/api/admin/resellers/delete' && method === 'POST') {
        if (!(await requireMaster(req, res))) return;

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        const userId = String(body.user_id || '');
        if (!userId) return sendJson(res, 400, { success: false, message: 'Missing user_id' });

        const target = await db.execute({ sql: "SELECT id FROM users WHERE id = ? AND role = 'reseller'", args: [userId] });
        if (target.rows.length === 0) return sendJson(res, 404, { success: false, message: 'Reseller not found' });

        const tx = await db.transaction('write');
        try {
            await tx.execute({ sql: 'UPDATE tokens SET reseller_id = NULL WHERE reseller_id = ?', args: [userId] });
            await tx.execute({ sql: 'DELETE FROM sessions WHERE user_id = ?', args: [userId] });
            await tx.execute({ sql: 'DELETE FROM reseller_quotas WHERE user_id = ?', args: [userId] });
            await tx.execute({ sql: "DELETE FROM users WHERE id = ? AND role = 'reseller'", args: [userId] });
            await tx.commit();
        } catch (err) {
            try { await tx.rollback(); } catch (e) { /* already closed */ }
            throw err;
        }

        return sendJson(res, 200, { success: true, message: 'Reseller deleted. Their tokens are now owned by master.' });
    }

    if (pathname === '/api/admin/resellers/quotas' && method === 'POST') {
        if (!(await requireMaster(req, res))) return;

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        const userId = String(body.user_id || '');
        if (!userId) return sendJson(res, 400, { success: false, message: 'Missing user_id' });

        const target = await db.execute({ sql: "SELECT id FROM users WHERE id = ? AND role = 'reseller'", args: [userId] });
        if (target.rows.length === 0) return sendJson(res, 404, { success: false, message: 'Reseller not found' });

        const input = body.quotas || {};
        const tx = await db.transaction('write');
        try {
            for (const period of PERIODS) {
                let raw;
                if (Array.isArray(input)) {
                    const found = input.find(q => Number(q.period_days) === period);
                    raw = found ? found.max_tokens : 0;
                } else {
                    raw = input[String(period)];
                }
                const maxTokens = Math.max(0, parseInt(raw, 10) || 0);
                await tx.execute({
                    sql: `INSERT INTO reseller_quotas (user_id, period_days, max_tokens, used_count)
                          VALUES (?, ?, ?, 0)
                          ON CONFLICT(user_id, period_days) DO UPDATE SET max_tokens = excluded.max_tokens`,
                    args: [userId, period, maxTokens]
                });
            }
            await tx.commit();
        } catch (err) {
            try { await tx.rollback(); } catch (e) { /* already closed */ }
            throw err;
        }

        return sendJson(res, 200, { success: true, message: 'Quotas updated' });
    }

    if (pathname === '/api/admin/resellers/reset-usage' && method === 'POST') {
        if (!(await requireMaster(req, res))) return;

        let body;
        try {
            body = await readJsonBody(req);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: err.message });
        }

        const userId = String(body.user_id || '');
        if (!userId) return sendJson(res, 400, { success: false, message: 'Missing user_id' });

        const target = await db.execute({ sql: "SELECT id FROM users WHERE id = ? AND role = 'reseller'", args: [userId] });
        if (target.rows.length === 0) return sendJson(res, 404, { success: false, message: 'Reseller not found' });

        if (body.period_days !== undefined) {
            const period = parseInt(body.period_days, 10);
            if (!PERIODS.includes(period)) return sendJson(res, 400, { success: false, message: 'Invalid period' });
            await db.execute({
                sql: 'UPDATE reseller_quotas SET used_count = 0 WHERE user_id = ? AND period_days = ?',
                args: [userId, period]
            });
        } else {
            await db.execute({ sql: 'UPDATE reseller_quotas SET used_count = 0 WHERE user_id = ?', args: [userId] });
        }

        return sendJson(res, 200, { success: true, message: 'Usage reset' });
    }

    // --------------------------------------------------------------------- Pages
    if (pathname === '/styles.css' && method === 'GET') {
        try {
            const css = fs.readFileSync(path.join(PUBLIC_DIR, 'styles.css'), 'utf8');
            res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
            res.end(css);
        } catch (err) {
            sendHtml(res, 404, 'Not found');
        }
        return;
    }

    if (pathname === '/favicon.ico' && method === 'GET') {
        res.writeHead(204);
        res.end();
        return;
    }

    if (pathname === '/' && method === 'GET') {
        const user = await getSessionUser(req);
        if (!user) return redirect(res, '/login');
        return redirect(res, user.role === 'master' ? '/master' : '/reseller');
    }

    if (pathname === '/login' && method === 'GET') {
        const user = await getSessionUser(req);
        if (user) return redirect(res, user.role === 'master' ? '/master' : '/reseller');
        return sendPage(res, 'login.html');
    }

    if (pathname === '/master' && method === 'GET') {
        const user = await getSessionUser(req);
        if (!user) return redirect(res, '/login');
        if (user.role !== 'master') return redirect(res, '/reseller');
        return sendPage(res, 'master.html');
    }

    if (pathname === '/reseller' && method === 'GET') {
        const user = await getSessionUser(req);
        if (!user) return redirect(res, '/login');
        if (user.role !== 'reseller') return redirect(res, '/master');
        return sendPage(res, 'reseller.html');
    }

    if (pathname === '/logs' && method === 'GET') {
        return sendPage(res, 'logs.html');
    }

    sendJson(res, 404, { message: 'Not Found' });
}

const server = http.createServer((req, res) => {
    handleRequest(req, res).catch(err => {
        console.error('[Server] Unhandled error:', err);
        if (!res.headersSent) {
            sendJson(res, 500, { success: false, message: 'Server error' });
        } else {
            res.end();
        }
    });
});

initDB().then(async () => {
    // Initialize pre-calculator from persistent summary
    try {
        const sumRow = await db.execute("SELECT * FROM telemetry_summary WHERE id = 'global'");
        if (sumRow.rows.length > 0 && Number(sumRow.rows[0].total_events) > 0) {
            telemetryStats.total = Number(sumRow.rows[0].total_events);
            telemetryStats.success = Number(sumRow.rows[0].success_events);
            telemetryStats.failed = Number(sumRow.rows[0].failed_events);
            telemetryStats.orderEvents = Number(sumRow.rows[0].order_events);
            telemetryStats.lastUpdated = Number(sumRow.rows[0].last_updated_at);
        } else {
            // One-time fast baseline calculation from existing database logs if present
            const initCounts = await db.execute(`
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN tag = 'ACCEPT_SUCCESS' OR (http_code >= 200 AND http_code < 300 AND tag LIKE '%ACCEPT%') THEN 1 ELSE 0 END) as success,
                    SUM(CASE WHEN tag = 'ACCEPT_FAILED' OR tag = 'CRASH' OR http_code >= 400 THEN 1 ELSE 0 END) as failed,
                    COUNT(DISTINCT CASE WHEN order_id > 0 THEN order_id ELSE NULL END) as order_events
                FROM telemetry_logs
            `);
            if (initCounts.rows.length > 0) {
                const r = initCounts.rows[0];
                telemetryStats.total = Number(r.total || 0);
                telemetryStats.success = Number(r.success || 0);
                telemetryStats.failed = Number(r.failed || 0);
                telemetryStats.orderEvents = Number(r.order_events || 0);
                await db.execute({
                    sql: "UPDATE telemetry_summary SET total_events = ?, success_events = ?, failed_events = ?, order_events = ?, last_updated_at = ? WHERE id = 'global'",
                    args: [telemetryStats.total, telemetryStats.success, telemetryStats.failed, telemetryStats.orderEvents, Date.now()]
                }).catch(() => {});
            }
        }
        console.log(`[Startup] Pre-calculator loaded: Total=${telemetryStats.total}, Success=${telemetryStats.success}, Failed=${telemetryStats.failed}, Orders=${telemetryStats.orderEvents}`);
    } catch (e) {
        console.warn('[Startup] Pre-calculator init warning:', e.message);
    }

    // Load blocked devices into memory set
    try {
        const bRows = await db.execute('SELECT device_id FROM blocked_devices');
        for (const row of bRows.rows) {
            if (row.device_id) blockedDevices.add(String(row.device_id).toLowerCase());
        }
        console.log(`[Startup] Loaded ${blockedDevices.size} blocked devices into memory`);
    } catch (e) {
        console.warn('[Startup] Could not load blocked devices:', e.message);
    }

    // Warm up in-memory orderLogs cache from persistent database (up to 200 latest entries)
    try {
        const recent = await db.execute('SELECT * FROM telemetry_logs ORDER BY timestamp DESC LIMIT 200');
        for (const row of recent.rows) {
            orderLogs.push({
                id: String(row.id),
                timestamp: Number(row.timestamp),
                receivedAt: Number(row.received_at),
                ip: row.ip,
                tag: row.tag,
                orderId: Number(row.order_id),
                deviceId: row.device_id,
                url: row.url,
                method: row.method,
                headers: row.headers_json ? JSON.parse(row.headers_json) : {},
                httpCode: Number(row.http_code),
                responseBody: row.response_body || '',
                durationMs: Number(row.duration_ms),
                error: row.error || '',
                details: row.details_json ? JSON.parse(row.details_json) : null
            });
        }
        console.log(`[Startup] Warmed in-memory buffer with ${orderLogs.length} persistent logs from Turso`);
    } catch (e) {
        console.warn('[Startup] Could not warm log buffer:', e.message);
    }

    server.listen(PORT, '0.0.0.0', () => {
        console.log(`[Verification Server] Running on port ${PORT}`);

        // Hourly cleanup of logs older than 36 hours
        setInterval(() => {
            cleanupOldLogs().catch(() => {});
        }, 60 * 60 * 1000);

        const keepAliveUrl = process.env.RENDER_EXTERNAL_URL || 'https://saned-license-server.onrender.com';
        setInterval(() => {
            try {
                const https = require('https');
                https.get(`${keepAliveUrl}/api/health`, (res) => {
                    console.log(`[Keep-Alive] Pinged ${keepAliveUrl}/api/health -> Status: ${res.statusCode}`);
                }).on('error', (err) => {
                    console.error('[Keep-Alive] Ping error:', err.message);
                });
            } catch (e) {
                console.error('[Keep-Alive] Exception:', e.message);
            }
        }, 8 * 60 * 1000);

        setInterval(() => {
            const now = Date.now();
            for (const [ip, entry] of loginAttempts) {
                if (entry.resetAt < now) loginAttempts.delete(ip);
            }
        }, 10 * 60 * 1000);
    });
}).catch(err => {
    console.error('[Startup] Database initialization failed:', err);
    process.exit(1);
});


