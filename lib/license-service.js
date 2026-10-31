const { db, PERIODS } = require('./db');

const CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

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

function normalizeDeviceId(raw) {
    if (typeof raw !== 'string') return '';
    return raw.trim().toLowerCase();
}

/**
 * Atomic license activation with dynamic first-activation device binding.
 */
async function activateLicense({ token, deviceId }) {
    const tokenStr = String(token || '').trim();
    const normalizedDevice = normalizeDeviceId(deviceId);

    if (!tokenStr || !normalizedDevice) {
        return {
            statusCode: 400,
            body: { success: false, unlocked: false, message: 'Missing token or device_id' }
        };
    }

    if (!isValidTokenFormat(tokenStr)) {
        return {
            statusCode: 400,
            body: { success: false, unlocked: false, reason: 'invalid_format', message: 'Invalid 16-character token format' }
        };
    }

    const result = await db.execute({
        sql: 'SELECT * FROM tokens WHERE LOWER(token) = LOWER(?)',
        args: [tokenStr]
    });

    if (result.rows.length === 0) {
        return {
            statusCode: 404,
            body: { success: false, unlocked: false, message: 'Invalid 16-character token. Token does not exist.' }
        };
    }

    const found = result.rows[0];
    const preSetDevice = String(found.device_id || '').trim().toLowerCase();
    const now = Date.now();

    // Case D: Revoked token
    if (found.status === 'revoked') {
        return {
            statusCode: 403,
            body: { success: false, unlocked: false, reason: 'revoked', message: 'This token has been revoked by admin' }
        };
    }

    // Case B: Already assigned token
    if (preSetDevice) {
        if (preSetDevice !== normalizedDevice) {
            return {
                statusCode: 403,
                body: {
                    success: false,
                    unlocked: false,
                    reason: 'device_mismatch',
                    message: `Wrong device! This token was issued for device ID: ${preSetDevice}`
                }
            };
        }

        // Check if expired
        if (found.expires_at && now > Number(found.expires_at)) {
            await db.execute({
                sql: "UPDATE tokens SET status = 'expired' WHERE LOWER(token) = LOWER(?)",
                args: [tokenStr]
            });
            return {
                statusCode: 403,
                body: { success: false, unlocked: false, reason: 'expired', message: 'This token has already expired' }
            };
        }

        let expiresAt = found.expires_at ? Number(found.expires_at) : null;

        // First activation of a preassigned token
        if (!found.activated_at) {
            expiresAt = now + (Number(found.period_days) * 24 * 60 * 60 * 1000);
            await db.execute({
                sql: "UPDATE tokens SET activated_at = ?, expires_at = ?, status = 'active' WHERE LOWER(token) = LOWER(?)",
                args: [now, expiresAt, tokenStr]
            });
        }
        // Case C: Previously activated token by the same device -> retain existing expiration

        const daysLeft = Math.max(0, Math.ceil((Number(expiresAt) - now) / (1000 * 60 * 60 * 24)));
        return {
            statusCode: 200,
            body: {
                success: true,
                unlocked: true,
                token: found.token,
                device_id: preSetDevice,
                expires_at: Number(expiresAt),
                days_left: daysLeft,
                period_days: Number(found.period_days),
                message: 'Device verified and unlocked!'
            }
        };
    }

    // Unassigned token (preSetDevice is empty)
    // Case G: Unassigned token with an existing activation timestamp -> inconsistent record
    if (found.activated_at) {
        return {
            statusCode: 409,
            body: {
                success: false,
                unlocked: false,
                reason: 'inconsistent_state',
                message: 'Inconsistent license record: token has activation date but no bound device. Requires administrative review.'
            }
        };
    }

    // Case E: Check expiration if somehow already expired
    if (found.expires_at && now > Number(found.expires_at)) {
        return {
            statusCode: 403,
            body: { success: false, unlocked: false, reason: 'expired', message: 'This token has already expired' }
        };
    }

    // Case A: First successful activation claims the device ID atomically
    const calculatedExpiresAt = now + (Number(found.period_days) * 24 * 60 * 60 * 1000);
    const updateResult = await db.execute({
        sql: `UPDATE tokens 
              SET device_id = ?, activated_at = ?, expires_at = ?, status = 'active' 
              WHERE LOWER(token) = LOWER(?) 
                AND (device_id IS NULL OR TRIM(device_id) = '') 
                AND activated_at IS NULL 
                AND status != 'revoked'`,
        args: [normalizedDevice, now, calculatedExpiresAt, tokenStr]
    });

    // Concurrency Protection: If rowsAffected is 0, another request won the race
    if (updateResult.rowsAffected === 0) {
        const reload = await db.execute({
            sql: 'SELECT * FROM tokens WHERE LOWER(token) = LOWER(?)',
            args: [tokenStr]
        });

        if (reload.rows.length === 0) {
            return {
                statusCode: 404,
                body: { success: false, unlocked: false, message: 'Token no longer exists' }
            };
        }

        const reloaded = reload.rows[0];
        const currentDevice = String(reloaded.device_id || '').trim().toLowerCase();

        // If the same device won the race
        if (currentDevice === normalizedDevice && reloaded.expires_at) {
            const daysLeft = Math.max(0, Math.ceil((Number(reloaded.expires_at) - now) / (1000 * 60 * 60 * 24)));
            return {
                statusCode: 200,
                body: {
                    success: true,
                    unlocked: true,
                    token: reloaded.token,
                    device_id: currentDevice,
                    expires_at: Number(reloaded.expires_at),
                    days_left: daysLeft,
                    period_days: Number(reloaded.period_days),
                    message: 'Device verified and unlocked!'
                }
            };
        }

        // Another device claimed it
        return {
            statusCode: 403,
            body: {
                success: false,
                unlocked: false,
                reason: 'device_mismatch',
                message: `Wrong device! This token was claimed by device ID: ${currentDevice}`
            }
        };
    }

    const daysLeft = Number(found.period_days);
    return {
        statusCode: 200,
        body: {
            success: true,
            unlocked: true,
            token: found.token,
            device_id: normalizedDevice,
            expires_at: calculatedExpiresAt,
            days_left: daysLeft,
            period_days: Number(found.period_days),
            message: 'Device activated and bound successfully'
        }
    };
}

/**
 * License verification without claiming or modifying unassigned tokens.
 */
async function verifyLicense({ token, deviceId }) {
    const tokenStr = String(token || '').trim();
    const normalizedDevice = normalizeDeviceId(deviceId);

    if (!tokenStr || !normalizedDevice) {
        return {
            statusCode: 400,
            body: { unlocked: false, message: 'Missing token or device_id' }
        };
    }

    if (!isValidTokenFormat(tokenStr)) {
        return {
            statusCode: 400,
            body: { unlocked: false, reason: 'invalid_format', message: 'Invalid 16-character token format' }
        };
    }

    const result = await db.execute({
        sql: 'SELECT * FROM tokens WHERE LOWER(token) = LOWER(?)',
        args: [tokenStr]
    });

    if (result.rows.length === 0) {
        return {
            statusCode: 404,
            body: { unlocked: false, message: 'Invalid 16-character token. Token does not exist.' }
        };
    }

    const found = result.rows[0];
    const preSetDevice = String(found.device_id || '').trim().toLowerCase();
    const now = Date.now();

    // Verification must NEVER claim an unassigned token
    if (!preSetDevice) {
        return {
            statusCode: 403,
            body: {
                unlocked: false,
                reason: 'unassigned',
                message: 'This token has not been activated or bound to any device yet'
            }
        };
    }

    if (preSetDevice !== normalizedDevice) {
        return {
            statusCode: 403,
            body: {
                unlocked: false,
                reason: 'device_mismatch',
                message: `Device mismatch! This token was generated for device ${preSetDevice}`
            }
        };
    }

    if (found.status === 'revoked') {
        return {
            statusCode: 403,
            body: { unlocked: false, reason: 'revoked', message: 'Token has been revoked by admin' }
        };
    }

    if (found.expires_at && now > Number(found.expires_at)) {
        await db.execute({
            sql: "UPDATE tokens SET status = 'expired' WHERE LOWER(token) = LOWER(?)",
            args: [tokenStr]
        });
        return {
            statusCode: 403,
            body: {
                unlocked: false,
                reason: 'expired',
                expires_at: Number(found.expires_at),
                message: `Subscription expired on ${new Date(Number(found.expires_at)).toLocaleDateString()}`
            }
        };
    }

    const daysLeft = found.expires_at
        ? Math.max(0, Math.ceil((Number(found.expires_at) - now) / (1000 * 60 * 60 * 24)))
        : Number(found.period_days);

    return {
        statusCode: 200,
        body: {
            unlocked: true,
            token: found.token,
            device_id: preSetDevice,
            expires_at: Number(found.expires_at),
            days_left: daysLeft,
            period_days: Number(found.period_days),
            message: 'Active license verified'
        }
    };
}

module.exports = {
    isValidTokenFormat,
    normalizeDeviceId,
    activateLicense,
    verifyLicense
};
