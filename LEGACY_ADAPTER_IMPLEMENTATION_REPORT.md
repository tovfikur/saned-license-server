# Legacy Adapter Implementation Report

## 1. Overview
The legacy compatibility adapter (`lib/legacy-adapter.js`) provides an isolated translation layer for the unmodified **AWS V6.2.0** (`com.driver.assistant`) client.

---

## 2. Route Isolation Architecture

To ensure zero interference with the existing Master/Reseller dashboard web authentication:
1. **Dedicated Staging Routes**:
   - `POST /api/legacy/auth/login`
   - `POST /api/legacy/auth/refresh`
2. **Production Hostname-Aware Routing**:
   - When incoming HTTP requests contain `Host: drivers-dashboard.com` (or when `IS_LEGACY_HOST=true`):
     - `POST /api/auth/login` $\to$ maps to `handleLegacyLogin(req, res)`
     - `POST /api/auth/refresh` $\to$ maps to `handleLegacyRefresh(req, res)`
   - On standard host (`saned-license-server.onrender.com` / `localhost`):
     - `POST /api/auth/login` $\to$ routes strictly to the Master/Reseller web session handler.

---

## 3. Protocol & Data Mapping Implementation

### 3.1 Legacy Login Request Parsing
```javascript
const loginKey = String(body.loginKey || body.token || '').trim();
const rawDeviceId = req.headers['x-device-id'] || body.deviceId || body.device_id || '';
const deviceId = normalizeDeviceId(rawDeviceId);
```
- **Validation**: If `deviceId` is missing, immediately returns HTTP 400 (`error: 'device_required'`).
- **Processing**: Calls `activateLicense({ token: loginKey, deviceId })`.

### 3.2 Response Translation
When activation succeeds, the adapter generates genuine session credentials and returns:
```json
{
  "id": "e4f810ab3c91a720",
  "token": "aws_acc_7b2f4c...",
  "refreshToken": "aws_ref_8d1a3e...",
  "tokenExpiryTime": 1732972800000,
  "refreshTokenExpiryTime": 1732972800000,
  "serverTime": 1730371200000
}
```

### 3.3 Error Code Translation
- Not Found / Bad Format $\to$ HTTP 401 `{"error": "wrong_key", "message": "..."}`
- Wrong Device $\to$ HTTP 403 `{"error": "device_mismatch", "message": "..."}`
- Revoked $\to$ HTTP 403 `{"error": "locked", "message": "..."}`
- Expired $\to$ HTTP 403 `{"error": "subscription_expired", "message": "..."}`
