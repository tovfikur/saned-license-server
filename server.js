const http = require('http');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');

const PORT = process.env.PORT || 8888;
const TURSO_URL = process.env.TURSO_DATABASE_URL || "libsql://saned-license-db-tovfikur.aws-ap-northeast-1.turso.io";
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN || "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3OTMwNDEwMzAsImlkIjoiMDFhMTc5OTItYmYwMS03YzViLWExZmYtMTU2NDFkNTgwMjhjIiwia2lkIjoiUUJzcEpWZzYydEZnb1VoTXItUEtMaVVrWWhlSnhOa2FUNkdrR3pSRkNzVSIsInJpZCI6ImExMzk1ODk1LTlkYWItNGRmYS04ZjczLWRhYTk2MDk0NzcyNCJ9.gUcFOe7BIbE7SMXVtG7vUB7pAu9E_PkXwS1ri_S78ot1vBd3U9OZNSqk2Q7cQh9OGLMLuV4XaPmADjzFassBDA";

const db = createClient({
    url: TURSO_URL,
    authToken: TURSO_TOKEN
});

async function initDB() {
    try {
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
        console.log('[Turso] Database schema verified with pre-set device_id requirement');
    } catch (e) {
        console.error('[Turso] Initialization error:', e.message);
    }
}

initDB();

const CHARS = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
function generate8CharToken() {
    let token = '';
    const bytes = crypto.randomBytes(8);
    for (let i = 0; i < 8; i++) {
        token += CHARS[bytes[i] % CHARS.length];
    }
    return token;
}

const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;

    function readJsonBody() {
        return new Promise((resolve, reject) => {
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                try {
                    const data = body ? JSON.parse(body) : {};
                    resolve(data);
                } catch (err) {
                    reject(err);
                }
            });
        });
    }

    function sendJson(statusCode, data) {
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
    }

    // Health check
    if (pathname === '/api/health' && req.method === 'GET') {
        return sendJson(200, { status: 'ok', time: Date.now(), database: 'turso-libsql' });
    }

    // API: Verify token for device at startup
    // Request: { "token": "XXXXXXXX", "device_id": "..." }
    if (pathname === '/api/verify' && req.method === 'POST') {
        try {
            const body = await readJsonBody();
            const tokenStr = String(body.token || '').trim().toUpperCase();
            const deviceId = String(body.device_id || '').trim().toLowerCase();

            if (!tokenStr || !deviceId) {
                return sendJson(400, { unlocked: false, message: 'Missing token or device_id' });
            }

            const result = await db.execute({
                sql: 'SELECT * FROM tokens WHERE token = ?',
                args: [tokenStr]
            });

            if (result.rows.length === 0) {
                return sendJson(404, { unlocked: false, reason: 'not_found', message: 'Invalid token. Token not found.' });
            }

            const found = result.rows[0];
            const preSetDevice = String(found.device_id || '').trim().toLowerCase();

            // Strict Device ID check
            if (preSetDevice !== deviceId) {
                return sendJson(403, {
                    unlocked: false,
                    reason: 'device_mismatch',
                    message: `Device mismatch! This token was generated for device ${preSetDevice}`
                });
            }

            if (found.status === 'revoked') {
                return sendJson(403, { unlocked: false, reason: 'revoked', message: 'Token has been revoked by admin' });
            }

            const now = Date.now();
            if (found.expires_at && now > found.expires_at) {
                await db.execute({
                    sql: 'UPDATE tokens SET status = ? WHERE token = ?',
                    args: ['expired', tokenStr]
                });
                return sendJson(403, {
                    unlocked: false,
                    reason: 'expired',
                    expires_at: found.expires_at,
                    message: `Subscription expired on ${new Date(Number(found.expires_at)).toLocaleDateString()}`
                });
            }

            const daysLeft = found.expires_at ? Math.max(0, Math.ceil((Number(found.expires_at) - now) / (1000 * 60 * 60 * 24))) : Number(found.period_days);
            return sendJson(200, {
                unlocked: true,
                token: found.token,
                expires_at: found.expires_at,
                days_left: daysLeft,
                period_days: found.period_days,
                message: 'Active license verified'
            });
        } catch (err) {
            return sendJson(500, { unlocked: false, message: 'Server error: ' + err.message });
        }
    }

    // API: Activate token on device
    // Request: { "token": "XXXXXXXX", "device_id": "..." }
    if (pathname === '/api/activate' && req.method === 'POST') {
        try {
            const body = await readJsonBody();
            const tokenStr = String(body.token || '').trim().toUpperCase();
            const deviceId = String(body.device_id || '').trim().toLowerCase();

            if (!tokenStr || !deviceId) {
                return sendJson(400, { success: false, unlocked: false, message: 'Missing token or device_id' });
            }

            const result = await db.execute({
                sql: 'SELECT * FROM tokens WHERE token = ?',
                args: [tokenStr]
            });

            if (result.rows.length === 0) {
                return sendJson(404, { success: false, unlocked: false, message: 'Invalid 8-character token. Token does not exist.' });
            }

            const found = result.rows[0];
            const preSetDevice = String(found.device_id || '').trim().toLowerCase();

            // STRICT DEVICE ID MATCH: The token MUST belong to this pre-set device ID!
            if (preSetDevice !== deviceId) {
                return sendJson(403, {
                    success: false,
                    unlocked: false,
                    message: `Wrong device! This token was issued for device ID: ${preSetDevice}`
                });
            }

            if (found.status === 'revoked') {
                return sendJson(403, { success: false, unlocked: false, message: 'This token has been revoked by admin' });
            }

            const now = Date.now();
            let expiresAt = found.expires_at;

            // First activation: compute expiration from now + period_days
            if (!found.activated_at) {
                expiresAt = now + (Number(found.period_days) * 24 * 60 * 60 * 1000);
                await db.execute({
                    sql: 'UPDATE tokens SET activated_at = ?, expires_at = ?, status = ? WHERE token = ?',
                    args: [now, expiresAt, 'active', tokenStr]
                });
            } else if (now > found.expires_at) {
                await db.execute({
                    sql: 'UPDATE tokens SET status = ? WHERE token = ?',
                    args: ['expired', tokenStr]
                });
                return sendJson(403, { success: false, unlocked: false, message: 'This token has already expired' });
            }

            const daysLeft = Math.max(0, Math.ceil((Number(expiresAt) - now) / (1000 * 60 * 60 * 24)));
            return sendJson(200, {
                success: true,
                unlocked: true,
                token: found.token,
                expires_at: expiresAt,
                days_left: daysLeft,
                period_days: found.period_days,
                message: 'Device verified and unlocked!'
            });
        } catch (err) {
            return sendJson(500, { success: false, unlocked: false, message: 'Server error: ' + err.message });
        }
    }

    // API: List tokens (Admin)
    if (pathname === '/api/tokens' && req.method === 'GET') {
        try {
            const result = await db.execute('SELECT * FROM tokens ORDER BY created_at DESC');
            const now = Date.now();
            const formatted = result.rows.map(row => {
                let status = row.status;
                if (status === 'active' && row.expires_at && now > row.expires_at) {
                    status = 'expired';
                }
                return {
                    token: row.token,
                    periodDays: Number(row.period_days),
                    createdAt: Number(row.created_at),
                    activatedAt: row.activated_at ? Number(row.activated_at) : null,
                    expiresAt: row.expires_at ? Number(row.expires_at) : null,
                    deviceId: row.device_id,
                    note: row.note,
                    status: status
                };
            });
            return sendJson(200, { tokens: formatted });
        } catch (err) {
            return sendJson(500, { error: err.message });
        }
    }

    // API: Generate new token with PRE-SET Device ID (Admin)
    if (pathname === '/api/tokens/generate' && req.method === 'POST') {
        try {
            const body = await readJsonBody();
            const deviceId = String(body.device_id || '').trim().toLowerCase();
            const periodDays = parseInt(body.period_days, 10) || 30;
            const note = body.note ? String(body.note).trim() : '';

            if (!deviceId) {
                return sendJson(400, {
                    success: false,
                    message: 'Target Device ID is required. Every token must be pre-set for a device.'
                });
            }

            let token = generate8CharToken();
            let check = await db.execute({ sql: 'SELECT token FROM tokens WHERE token = ?', args: [token] });
            while (check.rows.length > 0) {
                token = generate8CharToken();
                check = await db.execute({ sql: 'SELECT token FROM tokens WHERE token = ?', args: [token] });
            }

            const now = Date.now();
            await db.execute({
                sql: `INSERT INTO tokens (token, period_days, created_at, activated_at, expires_at, device_id, note, status)
                      VALUES (?, ?, ?, NULL, NULL, ?, ?, ?)`,
                args: [token, periodDays, now, deviceId, note, 'available']
            });

            return sendJson(201, {
                success: true,
                token: {
                    token: token,
                    periodDays: periodDays,
                    createdAt: now,
                    activatedAt: null,
                    expiresAt: null,
                    deviceId: deviceId,
                    note: note,
                    status: 'available'
                }
            });
        } catch (err) {
            return sendJson(500, { success: false, message: 'Server error: ' + err.message });
        }
    }

    // API: Revoke token
    if (pathname === '/api/tokens/revoke' && req.method === 'POST') {
        try {
            const body = await readJsonBody();
            if (!body.token) return sendJson(400, { success: false, message: 'Missing token' });
            await db.execute({
                sql: 'UPDATE tokens SET status = ? WHERE token = ?',
                args: ['revoked', String(body.token).trim().toUpperCase()]
            });
            return sendJson(200, { success: true, message: 'Token revoked' });
        } catch (err) {
            return sendJson(500, { success: false, message: err.message });
        }
    }

    // API: Delete token
    if (pathname === '/api/tokens/delete' && req.method === 'POST') {
        try {
            const body = await readJsonBody();
            if (!body.token) return sendJson(400, { success: false, message: 'Missing token' });
            await db.execute({
                sql: 'DELETE FROM tokens WHERE token = ?',
                args: [String(body.token).trim().toUpperCase()]
            });
            return sendJson(200, { success: true, message: 'Token deleted' });
        } catch (err) {
            return sendJson(500, { success: false, message: err.message });
        }
    }

    // Web Dashboard (GET /)
    if (pathname === '/' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(getDashboardHtml());
        return;
    }

    sendJson(404, { message: 'Not Found' });
});

function getDashboardHtml() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Saned Assistant - License Admin Dashboard</title>
<style>
  :root {
    --bg: #0f172a;
    --card: #1e293b;
    --border: #334155;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  body { background: var(--bg); color: var(--text); padding: 2rem 1rem; }
  .container { max-width: 1040px; margin: 0 auto; }
  header { margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
  h1 { font-size: 1.8rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem; }
  .badge-app { font-size: 0.75rem; background: var(--accent); color: white; padding: 0.2rem 0.6rem; border-radius: 9999px; }
  .badge-turso { font-size: 0.75rem; background: #059669; color: white; padding: 0.2rem 0.6rem; border-radius: 9999px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
  .card-title { font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem; color: #e2e8f0; display: flex; align-items: center; gap: 0.5rem; }
  .form-row { display: flex; gap: 1rem; flex-wrap: wrap; align-items: flex-end; }
  .form-group { display: flex; flex-direction: column; gap: 0.4rem; flex: 1; min-width: 200px; }
  label { font-size: 0.85rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
  select, input { background: #0f172a; border: 1px solid var(--border); color: #fff; padding: 0.65rem 0.9rem; border-radius: 8px; font-size: 0.95rem; outline: none; }
  select:focus, input:focus { border-color: var(--accent); }
  button { background: var(--accent); color: white; border: none; padding: 0.65rem 1.4rem; border-radius: 8px; font-weight: 600; cursor: pointer; transition: background 0.2s; font-size: 0.95rem; white-space: nowrap; }
  button:hover { background: var(--accent-hover); }
  .btn-danger { background: #b91c1c; }
  .btn-danger:hover { background: var(--danger); }
  .btn-small { padding: 0.35rem 0.7rem; font-size: 0.8rem; border-radius: 6px; }
  .token-table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  .token-table th, .token-table td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
  .token-table th { color: var(--text-muted); font-weight: 600; background: #162032; font-size: 0.8rem; text-transform: uppercase; }
  .token-box { font-family: monospace; font-size: 1.15rem; font-weight: 700; color: #38bdf8; letter-spacing: 0.1em; background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 4px; display: inline-block; }
  .device-box { font-family: monospace; font-size: 0.95rem; color: #a5f3fc; background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 4px; display: inline-block; }
  .status-tag { padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; display: inline-block; }
  .status-available { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
  .status-active { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
  .status-expired { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
  .status-revoked { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; }
  .stat-value { font-size: 2rem; font-weight: 700; margin-top: 0.3rem; }
  .copy-btn { cursor: pointer; background: #334155; border: none; color: #cbd5e1; border-radius: 4px; padding: 0.2rem 0.5rem; font-size: 0.75rem; margin-left: 0.4rem; }
  .copy-btn:hover { background: #475569; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>Saned Assistant <span class="badge-app">License Manager</span> <span class="badge-turso">Turso Cloud</span></h1>
      <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.2rem;">Pre-Set Device Verification & Subscription Control</p>
    </div>
    <div style="color: #34d399; font-size: 0.85rem;">● Turso Cloud DB Active</div>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div style="color: var(--text-muted); font-size: 0.85rem;">Total Licenses</div>
      <div class="stat-value" id="stat-total" style="color: #60a5fa;">0</div>
    </div>
    <div class="stat-card">
      <div style="color: var(--text-muted); font-size: 0.85rem;">Active Devices</div>
      <div class="stat-value" id="stat-active" style="color: #34d399;">0</div>
    </div>
    <div class="stat-card">
      <div style="color: var(--text-muted); font-size: 0.85rem;">Available Tokens</div>
      <div class="stat-value" id="stat-available" style="color: #cbd5e1;">0</div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">🔑 Generate Token for Pre-Set Device</div>
    <form id="gen-form" onsubmit="generateToken(event)">
      <div class="form-row">
        <div class="form-group" style="flex: 1.4;">
          <label>Target Device ID (Required) *</label>
          <input type="text" id="device-id-input" placeholder="e.g. cf4ade3f1edec2c7" required style="font-family: monospace;">
        </div>
        <div class="form-group" style="flex: 1;">
          <label>Subscription Period</label>
          <select id="period-select">
            <option value="1">1 Day</option>
            <option value="3">3 Days</option>
            <option value="7">7 Days (1 Week)</option>
            <option value="30" selected>30 Days (1 Month)</option>
            <option value="60">60 Days (2 Months)</option>
            <option value="90">90 Days (3 Months)</option>
            <option value="365">365 Days (1 Year)</option>
          </select>
        </div>
        <div class="form-group" style="flex: 1;">
          <label>Customer Name / Note (Optional)</label>
          <input type="text" id="note-input" placeholder="e.g. Driver Ahmed">
        </div>
        <div>
          <button type="submit">+ Issue Token</button>
        </div>
      </div>
    </form>
  </div>

  <div class="card">
    <div class="card-title">📋 Issued Licenses & Pre-Set Devices</div>
    <div style="overflow-x: auto;">
      <table class="token-table">
        <thead>
          <tr>
            <th>Token</th>
            <th>Pre-Set Device ID</th>
            <th>Duration</th>
            <th>Status</th>
            <th>Expires On</th>
            <th>Customer Note</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="tokens-body">
          <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Loading tokens...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
async function fetchTokens() {
  try {
    const res = await fetch('/api/tokens');
    const data = await res.json();
    renderTokens(data.tokens || []);
  } catch (e) {
    console.error(e);
  }
}

function renderTokens(tokens) {
  const tbody = document.getElementById('tokens-body');
  document.getElementById('stat-total').innerText = tokens.length;
  document.getElementById('stat-active').innerText = tokens.filter(t => t.status === 'active').length;
  document.getElementById('stat-available').innerText = tokens.filter(t => t.status === 'available').length;

  if (tokens.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No tokens issued yet. Enter a Device ID and click "+ Issue Token" above.</td></tr>';
    return;
  }

  tbody.innerHTML = tokens.map(t => {
    let expiresStr = 'Not yet activated';
    if (t.expiresAt) {
      const expDate = new Date(t.expiresAt);
      const daysLeft = Math.max(0, Math.ceil((t.expiresAt - Date.now()) / (1000 * 60 * 60 * 24)));
      expiresStr = expDate.toLocaleDateString() + ' (' + daysLeft + 'd left)';
    }

    const deviceStr = '<span class="device-box">' + t.deviceId + '</span>';

    return '<tr>' +
      '<td><span class="token-box">' + t.token + '</span><button class="copy-btn" onclick="copyToken(\\'' + t.token + '\\')">Copy</button></td>' +
      '<td>' + deviceStr + '</td>' +
      '<td>' + t.periodDays + ' Days</td>' +
      '<td><span class="status-tag status-' + t.status + '">' + t.status + '</span></td>' +
      '<td>' + expiresStr + '</td>' +
      '<td style="color: var(--text-muted);">' + (t.note || '-') + '</td>' +
      '<td>' +
        (t.status === 'active' ? '<button class="btn-danger btn-small" onclick="revokeToken(\\'' + t.token + '\\')">Revoke</button> ' : '') +
        '<button class="btn-small" style="background: #475569;" onclick="deleteToken(\\'' + t.token + '\\')">Delete</button>' +
      '</td>' +
    '</tr>';
  }).join('');
}

async function generateToken(e) {
  e.preventDefault();
  const deviceId = document.getElementById('device-id-input').value.trim();
  const periodDays = document.getElementById('period-select').value;
  const note = document.getElementById('note-input').value.trim();

  if (!deviceId) {
    alert('Please enter the target Device ID');
    return;
  }

  try {
    const res = await fetch('/api/tokens/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, period_days: periodDays, note: note })
    });
    const data = await res.json();
    if (data.success) {
      document.getElementById('device-id-input').value = '';
      document.getElementById('note-input').value = '';
      fetchTokens();
      alert('Token generated successfully: ' + data.token.token + ' for device ' + deviceId);
    } else {
      alert('Error: ' + data.message);
    }
  } catch (err) {
    alert('Error generating token: ' + err.message);
  }
}

async function revokeToken(token) {
  if (!confirm('Revoke token ' + token + '? The device will be locked out immediately.')) return;
  await fetch('/api/tokens/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token })
  });
  fetchTokens();
}

async function deleteToken(token) {
  if (!confirm('Delete token ' + token + '?')) return;
  await fetch('/api/tokens/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token })
  });
  fetchTokens();
}

function copyToken(token) {
  navigator.clipboard.writeText(token);
  alert('Copied token: ' + token);
}

fetchTokens();
setInterval(fetchTokens, 10000);
</script>
</body>
</html>`;
}

server.listen(PORT, '0.0.0.0', () => {
    console.log(`[Verification Server] Running on port ${PORT} connected to Turso Cloud DB`);

    // Keep-alive ping for free-tier hosting (e.g. Render) to prevent sleep after 15 min inactivity
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
    }, 8 * 60 * 1000); // Ping every 8 minutes (well under Render's 15-minute idle limit)
});
