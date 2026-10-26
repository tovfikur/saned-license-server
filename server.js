const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8888;
const DB_FILE = path.join(__dirname, 'database.json');

// Initialize or load DB
function loadDB() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const raw = fs.readFileSync(DB_FILE, 'utf-8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error('Error loading DB, creating new:', e.message);
    }
    const initial = { tokens: [] };
    saveDB(initial);
    return initial;
}

function saveDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

// Generate an 8-character uppercase alphanumeric token
// Using unambiguous characters (no 0/O, 1/I)
const CHARS = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
function generate8CharToken() {
    let token = '';
    const bytes = crypto.randomBytes(8);
    for (let i = 0; i < 8; i++) {
        token += CHARS[bytes[i] % CHARS.length];
    }
    return token;
}

const server = http.createServer((req, res) => {
    // CORS headers
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

    // Helper to read JSON body
    function readJsonBody(callback) {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const data = body ? JSON.parse(body) : {};
                callback(null, data);
            } catch (err) {
                callback(err, null);
            }
        });
    }

    // Helper to send JSON response
    function sendJson(statusCode, data) {
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
    }

    // API: Health check
    if (pathname === '/api/health' && req.method === 'GET') {
        return sendJson(200, { status: 'ok', time: Date.now() });
    }

    // API: Verify token for device
    // Request: { "token": "XXXXXXXX", "device_id": "..." }
    if (pathname === '/api/verify' && req.method === 'POST') {
        readJsonBody((err, body) => {
            if (err || !body.token || !body.device_id) {
                return sendJson(400, { unlocked: false, message: 'Missing token or device_id' });
            }

            const db = loadDB();
            const tokenStr = String(body.token).trim().toUpperCase();
            const deviceId = String(body.device_id).trim();

            const found = db.tokens.find(t => t.token === tokenStr);

            if (!found) {
                return sendJson(404, { unlocked: false, reason: 'not_found', message: 'Token not found' });
            }

            if (found.status === 'revoked') {
                return sendJson(403, { unlocked: false, reason: 'revoked', message: 'Token has been revoked by admin' });
            }

            if (found.deviceId && found.deviceId !== deviceId) {
                return sendJson(403, { unlocked: false, reason: 'device_mismatch', message: 'Token is bound to another device' });
            }

            const now = Date.now();
            if (found.expiresAt && now > found.expiresAt) {
                found.status = 'expired';
                saveDB(db);
                return sendJson(403, {
                    unlocked: false,
                    reason: 'expired',
                    expires_at: found.expiresAt,
                    message: `Subscription expired on ${new Date(found.expiresAt).toLocaleDateString()}`
                });
            }

            // Valid active token
            const daysLeft = found.expiresAt ? Math.max(0, Math.ceil((found.expiresAt - now) / (1000 * 60 * 60 * 24))) : 0;
            return sendJson(200, {
                unlocked: true,
                token: found.token,
                expires_at: found.expiresAt,
                days_left: daysLeft,
                period_days: found.periodDays,
                message: 'Active license verified'
            });
        });
        return;
    }

    // API: Activate token on device
    // Request: { "token": "XXXXXXXX", "device_id": "..." }
    if (pathname === '/api/activate' && req.method === 'POST') {
        readJsonBody((err, body) => {
            if (err || !body.token || !body.device_id) {
                return sendJson(400, { success: false, unlocked: false, message: 'Missing token or device_id' });
            }

            const db = loadDB();
            const tokenStr = String(body.token).trim().toUpperCase();
            const deviceId = String(body.device_id).trim();

            const found = db.tokens.find(t => t.token === tokenStr);

            if (!found) {
                return sendJson(404, { success: false, unlocked: false, message: 'Invalid 8-character token' });
            }

            if (found.status === 'revoked') {
                return sendJson(403, { success: false, unlocked: false, message: 'Token has been revoked' });
            }

            if (found.deviceId && found.deviceId !== deviceId) {
                return sendJson(403, { success: false, unlocked: false, message: 'Token is already used on another device' });
            }

            const now = Date.now();

            // First activation: bind device and compute expiration based on periodDays
            if (!found.deviceId) {
                found.deviceId = deviceId;
                found.activatedAt = now;
                found.expiresAt = now + (found.periodDays * 24 * 60 * 60 * 1000);
                found.status = 'active';
                saveDB(db);
            } else if (now > found.expiresAt) {
                found.status = 'expired';
                saveDB(db);
                return sendJson(403, { success: false, unlocked: false, message: 'This token has already expired' });
            }

            const daysLeft = Math.max(0, Math.ceil((found.expiresAt - now) / (1000 * 60 * 60 * 24)));
            return sendJson(200, {
                success: true,
                unlocked: true,
                token: found.token,
                expires_at: found.expiresAt,
                days_left: daysLeft,
                period_days: found.periodDays,
                message: 'App successfully unlocked!'
            });
        });
        return;
    }

    // API: List tokens (Admin)
    if (pathname === '/api/tokens' && req.method === 'GET') {
        const db = loadDB();
        const now = Date.now();
        // Update expired statuses
        let changed = false;
        db.tokens.forEach(t => {
            if (t.status === 'active' && t.expiresAt && now > t.expiresAt) {
                t.status = 'expired';
                changed = true;
            }
        });
        if (changed) saveDB(db);
        return sendJson(200, { tokens: db.tokens });
    }

    // API: Generate new token (Admin)
    // Request: { "period_days": 30, "note": "Customer 1" }
    if (pathname === '/api/tokens/generate' && req.method === 'POST') {
        readJsonBody((err, body) => {
            const periodDays = parseInt(body.period_days, 10) || 30;
            const note = body.note ? String(body.note).trim() : '';

            const db = loadDB();
            let token = generate8CharToken();
            while (db.tokens.some(t => t.token === token)) {
                token = generate8CharToken();
            }

            const newToken = {
                token: token,
                periodDays: periodDays,
                createdAt: Date.now(),
                activatedAt: null,
                expiresAt: null,
                deviceId: null,
                note: note,
                status: 'available' // available, active, expired, revoked
            };

            db.tokens.unshift(newToken);
            saveDB(db);

            return sendJson(201, { success: true, token: newToken });
        });
        return;
    }

    // API: Revoke / Delete token (Admin)
    if (pathname === '/api/tokens/revoke' && req.method === 'POST') {
        readJsonBody((err, body) => {
            if (!body.token) return sendJson(400, { success: false, message: 'Missing token' });
            const db = loadDB();
            const found = db.tokens.find(t => t.token === body.token);
            if (found) {
                found.status = 'revoked';
                saveDB(db);
                return sendJson(200, { success: true, message: 'Token revoked' });
            }
            return sendJson(404, { success: false, message: 'Token not found' });
        });
        return;
    }

    if (pathname === '/api/tokens/delete' && req.method === 'POST') {
        readJsonBody((err, body) => {
            if (!body.token) return sendJson(400, { success: false, message: 'Missing token' });
            const db = loadDB();
            db.tokens = db.tokens.filter(t => t.token !== body.token);
            saveDB(db);
            return sendJson(200, { success: true, message: 'Token deleted' });
        });
        return;
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
  .container { max-width: 1000px; margin: 0 auto; }
  header { margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
  h1 { font-size: 1.8rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem; }
  .badge-app { font-size: 0.75rem; background: var(--accent); color: white; padding: 0.2rem 0.6rem; border-radius: 9999px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
  .card-title { font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem; color: #e2e8f0; }
  .form-row { display: flex; gap: 1rem; flex-wrap: wrap; align-items: flex-end; }
  .form-group { display: flex; flex-direction: column; gap: 0.4rem; flex: 1; min-width: 180px; }
  label { font-size: 0.85rem; color: var(--text-muted); font-weight: 500; }
  select, input { background: #0f172a; border: 1px solid var(--border); color: #fff; padding: 0.65rem 0.9rem; border-radius: 8px; font-size: 0.95rem; outline: none; }
  select:focus, input:focus { border-color: var(--accent); }
  button { background: var(--accent); color: white; border: none; padding: 0.65rem 1.4rem; border-radius: 8px; font-weight: 600; cursor: pointer; transition: background 0.2s; font-size: 0.95rem; }
  button:hover { background: var(--accent-hover); }
  .btn-danger { background: #b91c1c; }
  .btn-danger:hover { background: var(--danger); }
  .btn-small { padding: 0.35rem 0.7rem; font-size: 0.8rem; border-radius: 6px; }
  .token-table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  .token-table th, .token-table td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
  .token-table th { color: var(--text-muted); font-weight: 600; background: #162032; font-size: 0.8rem; text-transform: uppercase; }
  .token-box { font-family: monospace; font-size: 1.1rem; font-weight: 700; color: #38bdf8; letter-spacing: 0.1em; background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 4px; display: inline-block; }
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
      <h1>Saned Assistant <span class="badge-app">Server Verification</span></h1>
      <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.2rem;">Token Generator & Active License Manager</p>
    </div>
    <div style="color: var(--text-muted); font-size: 0.85rem;" id="server-status">● Server Online (Port ${PORT})</div>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div style="color: var(--text-muted); font-size: 0.85rem;">Total Generated</div>
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
    <div class="card-title">⚡ Generate 8-Character Token</div>
    <form id="gen-form" onsubmit="generateToken(event)">
      <div class="form-row">
        <div class="form-group">
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
        <div class="form-group">
          <label>Customer Name / Note (Optional)</label>
          <input type="text" id="note-input" placeholder="e.g. Driver Ahmed">
        </div>
        <div>
          <button type="submit">+ Generate Token</button>
        </div>
      </div>
    </form>
  </div>

  <div class="card">
    <div class="card-title">🔑 Tokens & Device Bindings</div>
    <div style="overflow-x: auto;">
      <table class="token-table">
        <thead>
          <tr>
            <th>Token</th>
            <th>Duration</th>
            <th>Status</th>
            <th>Bound Device ID</th>
            <th>Expires On</th>
            <th>Customer / Note</th>
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
    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No tokens generated yet. Click "Generate Token" above.</td></tr>';
    return;
  }

  tbody.innerHTML = tokens.map(t => {
    let expiresStr = '-';
    if (t.expiresAt) {
      const expDate = new Date(t.expiresAt);
      const daysLeft = Math.max(0, Math.ceil((t.expiresAt - Date.now()) / (1000 * 60 * 60 * 24)));
      expiresStr = expDate.toLocaleDateString() + ' (' + daysLeft + 'd left)';
    }

    const deviceStr = t.deviceId ? '<span style="font-family: monospace; color: #a5f3fc;">' + t.deviceId + '</span>' : '<span style="color: var(--text-muted);">Not activated</span>';

    return '<tr>' +
      '<td><span class="token-box">' + t.token + '</span><button class="copy-btn" onclick="copyToken(\\'' + t.token + '\\')">Copy</button></td>' +
      '<td>' + t.periodDays + ' Days</td>' +
      '<td><span class="status-tag status-' + t.status + '">' + t.status + '</span></td>' +
      '<td>' + deviceStr + '</td>' +
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
  const periodDays = document.getElementById('period-select').value;
  const note = document.getElementById('note-input').value;
  try {
    const res = await fetch('/api/tokens/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ period_days: periodDays, note: note })
    });
    const data = await res.json();
    if (data.success) {
      document.getElementById('note-input').value = '';
      fetchTokens();
    }
  } catch (err) {
    alert('Error generating token: ' + err.message);
  }
}

async function revokeToken(token) {
  if (!confirm('Are you sure you want to revoke token ' + token + '? The user will be locked out immediately.')) return;
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
    console.log(`[Verification Server] Running at http://localhost:${PORT}`);
    console.log(`[Verification Server] Accessible on local network or via adb reverse`);
});
