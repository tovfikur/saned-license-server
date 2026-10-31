# Saned API Implementation Report

## 1. Overview
The mobile licensing endpoints in `server.js` have been refactored to delegate to `lib/license-service.js`, unifying dynamic device binding across native and legacy client flows.

---

## 2. Updated Endpoint Behavior

### 2.1 Endpoint: `POST /api/activate`
- **Location**: `server.js#L179-191`, `lib/license-service.js#L26-175`.
- **Request Schema**:
  ```json
  {
    "token": "A1B2C3D4E5F6G7H8",
    "device_id": "sm1-954f467dd88cbc8190c47a8318fadffc607f573a"
  }
  ```
- **Response Schema (HTTP 200)**:
  ```json
  {
    "success": true,
    "unlocked": true,
    "token": "A1B2C3D4E5F6G7H8",
    "device_id": "sm1-954f467dd88cbc8190c47a8318fadffc607f573a",
    "expires_at": 1732972800000,
    "days_left": 30,
    "period_days": 30,
    "message": "Device activated and bound successfully"
  }
  ```
- **Error Responses**:
  - `400`: Missing `token` or `device_id` / invalid format.
  - `404`: Non-existent token.
  - `403`: Token revoked, expired, or bound to another device.
  - `409`: Inconsistent legacy record (activation date exists without bound device).

### 2.2 Endpoint: `POST /api/verify`
- **Location**: `server.js#L165-177`, `lib/license-service.js#L180-264`.
- **Core Constraint**: **Never claims unassigned tokens**. If an unassigned token is submitted to `/api/verify`, the endpoint returns HTTP 403 (`reason: 'unassigned'`).
- **Response Schema (HTTP 200)**:
  ```json
  {
    "unlocked": true,
    "token": "A1B2C3D4E5F6G7H8",
    "device_id": "sm1-954f467dd88cbc8190c47a8318fadffc607f573a",
    "expires_at": 1732972800000,
    "days_left": 30,
    "period_days": 30,
    "message": "Active license verified"
  }
  ```

---

## 3. Admin & Reseller Token Creation API
- **Endpoint**: `POST /api/tokens/generate`
- **Update**: `body.device_id` is now strictly optional.
- **Master & Reseller Support**: If omitted or whitespace, the server inserts `device_id = NULL`.
- **Response**: Emits `token.deviceId = null` for unassigned tokens.
