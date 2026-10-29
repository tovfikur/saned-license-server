const { db } = require('./db');
const { randomToken } = require('./security');
const { parseCookies } = require('./http');

const SESSION_COOKIE = 'saned_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function isSecureRequest() {
    return Boolean(process.env.RENDER || process.env.RENDER_EXTERNAL_URL || process.env.NODE_ENV === 'production');
}

async function createSession(userId) {
    const token = randomToken(32);
    const now = Date.now();
    const expiresAt = now + SESSION_TTL_MS;

    await db.execute({
        sql: 'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
        args: [token, userId, now, expiresAt]
    });

    return { token, expiresAt };
}

async function destroySession(token) {
    if (!token) return;
    await db.execute({ sql: 'DELETE FROM sessions WHERE token = ?', args: [token] });
}

async function deleteUserSessions(userId, exceptToken = null) {
    if (exceptToken) {
        await db.execute({
            sql: 'DELETE FROM sessions WHERE user_id = ? AND token != ?',
            args: [userId, exceptToken]
        });
    } else {
        await db.execute({ sql: 'DELETE FROM sessions WHERE user_id = ?', args: [userId] });
    }
}

async function getSessionUser(req) {
    const cookies = parseCookies(req);
    const token = cookies[SESSION_COOKIE];
    if (!token) return null;

    const result = await db.execute({
        sql: `SELECT s.token, s.expires_at, u.id, u.username, u.role, u.status
              FROM sessions s JOIN users u ON u.id = s.user_id
              WHERE s.token = ?`,
        args: [token]
    });

    if (result.rows.length === 0) return null;
    const row = result.rows[0];

    if (Number(row.expires_at) < Date.now() || row.status !== 'active') {
        await destroySession(token);
        return null;
    }

    return {
        id: String(row.id),
        username: String(row.username),
        role: String(row.role),
        sessionToken: token
    };
}

function setSessionCookie(res, token, expiresAt) {
    const parts = [
        `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${Math.floor((expiresAt - Date.now()) / 1000)}`
    ];
    if (isSecureRequest()) parts.push('Secure');
    res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res) {
    const parts = [`${SESSION_COOKIE}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
    if (isSecureRequest()) parts.push('Secure');
    res.setHeader('Set-Cookie', parts.join('; '));
}

module.exports = {
    SESSION_COOKIE,
    createSession,
    destroySession,
    deleteUserSessions,
    getSessionUser,
    setSessionCookie,
    clearSessionCookie
};
