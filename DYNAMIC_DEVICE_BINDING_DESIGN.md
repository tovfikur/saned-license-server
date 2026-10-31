# Dynamic Device Binding Architecture & Design

## 1. System Overview
The dynamic device-binding system allows administrators and resellers to generate unassigned license tokens. The first device to activate an unassigned token automatically claims and permanently binds it to that device's hardware identifier.

---

## 2. Token Lifecycle State Machine

```
+-----------------------------------------------------------------------------------+
|                           TOKEN STATE TRANSITIONS                                 |
+-----------------------------------------------------------------------------------+
| 1. CREATION                                                                       |
|    - Admin / Reseller generates token without device_id (NULL or empty string).   |
|    - Status: 'available'                                                          |
|    - device_id: NULL, activated_at: NULL, expires_at: NULL                        |
+-----------------------------------------------------------------------------------+
| 2. FIRST ACTIVATION (Atomic Claim)                                                |
|    - Device submits POST /api/activate with token & device_id.                     |
|    - Database executes atomic conditional update.                                 |
|    - Status: 'active'                                                             |
|    - device_id: <bound_id>, activated_at: <now>, expires_at: <now + period_ms>    |
+-----------------------------------------------------------------------------------+
| 3. RECURRING VERIFICATION & RE-ACTIVATION                                         |
|    - Same device activates again -> Returns HTTP 200 (preserves expires_at).      |
|    - Same device calls /api/verify -> Returns HTTP 200 (Active license verified). |
|    - Different device calls /api/activate or /api/verify -> Returns HTTP 403.     |
+-----------------------------------------------------------------------------------+
| 4. EXPIRATION / REVOCATION                                                        |
|    - If now > expires_at -> Status transitions to 'expired' (HTTP 403).           |
|    - If Admin revokes token -> Status transitions to 'revoked' (HTTP 403).        |
+-----------------------------------------------------------------------------------+
```

---

## 3. Concurrency Protection & Atomic Claiming

To prevent race conditions where two distinct devices attempt to activate an unassigned token concurrently, the server executes an atomic conditional update:

```sql
UPDATE tokens 
SET device_id = ?, activated_at = ?, expires_at = ?, status = 'active' 
WHERE LOWER(token) = LOWER(?) 
  AND (device_id IS NULL OR TRIM(device_id) = '') 
  AND activated_at IS NULL 
  AND status != 'revoked';
```

### Race Resolution Logic:
1. If `rowsAffected > 0`: The current request successfully won the race and bound the token.
2. If `rowsAffected === 0`: A competing process modified the record. The server immediately executes `SELECT * FROM tokens WHERE LOWER(token) = LOWER(?)`:
   - If `reloaded.device_id === normalizedDevice`: The same device won the race concurrently; returns HTTP 200 with the existing expiration date.
   - If `reloaded.device_id !== normalizedDevice`: Another device claimed the token; returns HTTP 403 `Wrong device! This token was claimed by device ID: ...`.

---

## 4. Rule Verification Matrix (Cases A through G)

| Case | Scenario Description | Expected Server Response | Actual Server Handling |
|---|---|---|---|
| **Case A** | Unassigned token (`device_id` NULL/empty, `activated_at` NULL) | Claims device, sets `activated_at` & `expires_at`, returns HTTP 200 | Atomic conditional update assigns device. |
| **Case B** | Already assigned token, matching device ID | Allows activation if valid; rejects if differing device with HTTP 403 | Enforces `preSetDevice === normalizedDevice`. |
| **Case C** | Previously activated token activated again by same device | HTTP 200; does NOT reset `activated_at` or extend `expires_at` | Retains existing `expires_at` calculation. |
| **Case D** | Revoked token | Returns HTTP 403 `revoked`; never assigns device | Checked before binding update. |
| **Case E** | Expired token | Returns HTTP 403 `expired`; never assigns device | Checks `now > expires_at`. |
| **Case F** | Missing `device_id` in request | Returns HTTP 400 `Missing token or device_id` | Input validation rejects missing device ID. |
| **Case G** | Unassigned token with existing activation date | Returns HTTP 409 `inconsistent_state` | Rejects silent binding and requests admin review. |
