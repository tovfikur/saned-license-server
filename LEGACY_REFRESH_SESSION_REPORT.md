# Legacy Refresh & Session Handling Report

## 1. Overview
Rather than duplicating the 16-character license token or returning synthetic credentials, the adapter implements a genuine session management subsystem backed by Turso DB.

---

## 2. Session Architecture

```
+-----------------------------------------------------------------------------------+
|                        LEGACY SESSION SECURITY MODEL                              |
+-----------------------------------------------------------------------------------+
| 1. CREDENTIAL GENERATION                                                          |
|    - Access Token: 'aws_acc_' + 24 cryptographically random bytes (hex)           |
|    - Refresh Token: 'aws_ref_' + 24 cryptographically random bytes (hex)          |
+-----------------------------------------------------------------------------------+
| 2. AT-REST PROTECTION                                                             |
|    - Database never stores plaintext tokens.                                      |
|    - Stores SHA-256 hashes: token_hash, refresh_token_hash.                       |
+-----------------------------------------------------------------------------------+
| 3. HARDWARE & LICENSE ANCHOR                                                      |
|    - Every session record references the license_token and device_id.             |
|    - Re-authentication from any different device ID is rejected.                  |
+-----------------------------------------------------------------------------------+
| 4. REFRESH ROTATION                                                               |
|    - Using a refresh token invalidates the previous credential pair.              |
|    - Issues newly minted access and refresh tokens.                               |
+-----------------------------------------------------------------------------------+
```

---

## 3. Refresh Endpoint Lifecycle (`POST /api/legacy/auth/refresh`)

1. **Inbound Verification**:
   - Computes `incomingHash = sha256(body.refreshToken)`.
   - Queries `SELECT * FROM legacy_sessions WHERE refresh_token_hash = ?`.
   - Validates `session.device_id.toLowerCase() === incomingDeviceId.toLowerCase()`.
2. **Underlying License Status Audit**:
   - Calls `verifyLicense({ token: session.license_token, deviceId: session.device_id })`.
   - If the license token was revoked by an admin or elapses its subscription period:
     - Deletes the session record from `legacy_sessions`.
     - Returns HTTP 403 `{"error": "subscription_expired", "message": "..."}`.
3. **Token Rotation**:
   - Generates `newAccessToken` and `newRefreshToken`.
   - Updates `legacy_sessions` with new hashes and timestamps.
   - Returns HTTP 200 with new credentials.
