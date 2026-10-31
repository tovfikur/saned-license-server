const crypto = require('crypto');
const { db } = require('./db');
const { activateLicense, verifyLicense, normalizeDeviceId } = require('./license-service');
const { readJsonBody, sendJson } = require('./http');

function hashToken(raw) {
    return crypto.createHash('sha256').update(String(raw || '')).digest('hex');
}

/**
 * Handles legacy login requests from AWS V6.2.0.
 * Expected endpoint: POST /api/legacy/auth/login or POST /api/auth/login on legacy host
 */
async function handleLegacyLogin(req, res) {
    let body = {};
    try {
        body = await readJsonBody(req);
    } catch (e) {
        return sendJson(res, 400, { error: 'invalid_json', message: 'Malformed JSON payload' });
    }

    const loginKey = String(body.loginKey || body.token || '').trim();
    const rawDeviceId = req.headers['x-device-id'] || body.deviceId || body.device_id || '';
    const deviceId = normalizeDeviceId(rawDeviceId);

    // Missing device ID in header
    if (!deviceId) {
        return sendJson(res, 400, {
            error: 'device_required',
            message: 'x-device-id header is required for device-bound authentication'
        });
    }

    if (!loginKey) {
        return sendJson(res, 401, {
            error: 'wrong_key',
            message: 'Login key cannot be empty'
        });
    }

    // Process through shared dynamic licensing service
    const activation = await activateLicense({ token: loginKey, deviceId });

    if (activation.statusCode !== 200) {
        const failure = activation.body;
        if (activation.statusCode === 404 || failure.reason === 'invalid_format') {
            return sendJson(res, 401, { error: 'wrong_key', message: failure.message });
        }
        if (failure.reason === 'device_mismatch') {
            return sendJson(res, 403, { error: 'device_mismatch', message: failure.message });
        }
        if (failure.reason === 'revoked') {
            return sendJson(res, 403, { error: 'locked', message: failure.message });
        }
        if (failure.reason === 'expired') {
            return sendJson(res, 403, { error: 'subscription_expired', message: failure.message });
        }
        return sendJson(res, activation.statusCode, { error: 'auth_failed', message: failure.message });
    }

    const licenseData = activation.body;
    const now = Date.now();
    const sessionId = crypto.randomBytes(8).toString('hex');
    const accessToken = 'aws_acc_' + crypto.randomBytes(24).toString('hex');
    const refreshToken = 'aws_ref_' + crypto.randomBytes(24).toString('hex');

    const tokenHash = hashToken(accessToken);
    const refreshHash = hashToken(refreshToken);

    // Save session in database
    await db.execute({
        sql: `INSERT INTO legacy_sessions (id, token_hash, refresh_token_hash, license_token, device_id, expires_at, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)`,
        args: [sessionId, tokenHash, refreshHash, licenseData.token, deviceId, licenseData.expires_at, now]
    });

    // Return the exact JSON structure expected by AWS V6.2.0
    return sendJson(res, 200, {
        id: sessionId,
        token: accessToken,
        refreshToken: refreshToken,
        tokenExpiryTime: licenseData.expires_at,
        refreshTokenExpiryTime: licenseData.expires_at,
        serverTime: now
    });
}

/**
 * Handles legacy token refresh requests from AWS V6.2.0.
 * Expected endpoint: POST /api/legacy/auth/refresh or POST /api/auth/refresh on legacy host
 */
async function handleLegacyRefresh(req, res) {
    let body = {};
    try {
        body = await readJsonBody(req);
    } catch (e) {
        return sendJson(res, 400, { error: 'invalid_json', message: 'Malformed JSON payload' });
    }

    const refreshTokenRaw = String(body.refreshToken || '').trim();
    const rawDeviceId = req.headers['x-device-id'] || body.deviceId || body.device_id || '';
    const deviceId = normalizeDeviceId(rawDeviceId);

    if (!refreshTokenRaw) {
        return sendJson(res, 401, { error: 'unauthorized', message: 'refreshToken is required' });
    }

    if (!deviceId) {
        return sendJson(res, 400, { error: 'device_required', message: 'Device ID is required' });
    }

    const refreshHash = hashToken(refreshTokenRaw);
    const sessionRes = await db.execute({
        sql: 'SELECT * FROM legacy_sessions WHERE refresh_token_hash = ?',
        args: [refreshHash]
    });

    if (sessionRes.rows.length === 0) {
        return sendJson(res, 401, { error: 'unauthorized', message: 'Invalid or expired refresh token' });
    }

    const session = sessionRes.rows[0];

    // Device exclusivity check
    if (String(session.device_id).toLowerCase() !== deviceId) {
        return sendJson(res, 403, {
            error: 'device_mismatch',
            message: 'Refresh token was not issued for this device'
        });
    }

    // Verify underlying license status through Saned
    const licenseCheck = await verifyLicense({ token: session.license_token, deviceId });

    if (licenseCheck.statusCode !== 200) {
        // License was revoked or expired -> revoke session
        await db.execute({
            sql: 'DELETE FROM legacy_sessions WHERE id = ?',
            args: [session.id]
        });
        const err = licenseCheck.body;
        return sendJson(res, 403, {
            error: err.reason || 'subscription_expired',
            message: err.message
        });
    }

    const now = Date.now();
    const newAccessToken = 'aws_acc_' + crypto.randomBytes(24).toString('hex');
    const newRefreshToken = 'aws_ref_' + crypto.randomBytes(24).toString('hex');

    const newTokenHash = hashToken(newAccessToken);
    const newRefreshHash = hashToken(newRefreshToken);
    const expiresAt = licenseCheck.body.expires_at;

    // Rotate refresh token atomically in database
    await db.execute({
        sql: `UPDATE legacy_sessions 
              SET token_hash = ?, refresh_token_hash = ?, expires_at = ?, created_at = ?
              WHERE id = ?`,
        args: [newTokenHash, newRefreshHash, expiresAt, now, session.id]
    });

    return sendJson(res, 200, {
        id: session.id,
        token: newAccessToken,
        refreshToken: newRefreshToken,
        tokenExpiryTime: expiresAt,
        refreshTokenExpiryTime: expiresAt,
        serverTime: now
    });
}

module.exports = {
    handleLegacyLogin,
    handleLegacyRefresh,
    hashToken
};
