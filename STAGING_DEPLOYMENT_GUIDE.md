# Staging Deployment & Verification Guide

## 1. Overview
This guide provides the operational steps to test the upgraded server and legacy compatibility adapter in a staging environment prior to production deployment.

---

## 2. Staging Deployment Steps

### Step 1: Run Automated Tests
Before starting the server, execute the 27-point test suite:
```bash
node tests/test-suite.js
```
Confirm that `27/27 passed` is displayed and exit code is `0`.

### Step 2: Start Local Server Instance
```bash
node server.js
```
The server will start on port `8888` (or the configured `PORT`).

### Step 3: Test Dynamic Device Binding via cURL
1. **Generate an Unassigned Token**:
   - Open browser at `http://localhost:8888/master`.
   - Log in using Master credentials.
   - Leave `Target Device ID` empty and click **Generate Token**.
   - Note the generated 16-character token: `TOKEN_X`.

2. **Activate from First Device**:
   ```bash
   curl -X POST http://localhost:8888/api/activate \
     -H "Content-Type: application/json" \
     -d '{"token": "TOKEN_X", "device_id": "sm1-954f467dd88cbc8190c47a8318fadffc607f573a"}'
   ```
   **Expected**: HTTP 200 `{ "success": true, "unlocked": true, "device_id": "sm1-954f467..." }`.

3. **Verify Different Device is Rejected**:
   ```bash
   curl -X POST http://localhost:8888/api/activate \
     -H "Content-Type: application/json" \
     -d '{"token": "TOKEN_X", "device_id": "sm1-otherdevice1111111111111111111111111"}'
   ```
   **Expected**: HTTP 403 `{ "success": false, "reason": "device_mismatch" }`.

### Step 4: Test Legacy Adapter via Isolated Staging Route
```bash
curl -X POST http://localhost:8888/api/legacy/auth/login \
  -H "Content-Type: application/json" \
  -H "x-device-id: sm1-954f467dd88cbc8190c47a8318fadffc607f573a" \
  -d '{"loginKey": "TOKEN_X"}'
```
**Expected**: HTTP 200 with `{ "id": "...", "token": "aws_acc_...", "refreshToken": "aws_ref_...", "tokenExpiryTime": ..., "serverTime": ... }`.
