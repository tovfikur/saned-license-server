# Security Review: Dynamic Binding & Legacy Adapter

## 1. Threat Analysis & Mitigations

| Threat Vector | Attack Scenario | Implemented Mitigation | Verification Status |
|---|---|---|---|
| **Activation Race Condition** | Two different devices attempt to claim an unassigned token simultaneously. | Atomic conditional `UPDATE ... WHERE (device_id IS NULL OR TRIM(device_id) = '') AND activated_at IS NULL`. Exactly one request wins; loser receives HTTP 403. | **Verified via Automated Test 07 & 27**. |
| **Credential Thefts via DB Dump** | An unauthorized actor gains read access to the database. | Access and refresh tokens are stored exclusively as cryptographic SHA-256 hashes in `legacy_sessions`. | **Verified in `legacy-adapter.js`**. |
| **Token Hijacking Across Devices** | Stored refresh token is exfiltrated and replayed on a different device. | Refresh endpoint strictly enforces `session.device_id === incomingDeviceId`. | **Verified via Automated Test 21**. |
| **Administrative Bypass** | Revoked license continues operating via active session. | Refresh handler calls `verifyLicense` against the master `tokens` table; revoking a token kills the active session immediately. | **Verified via Automated Test 22**. |
| **Session Clock Tampering** | Manipulating local device time to extend session. | Expiration timestamps are calculated on the server and verified via network timestamps during every verify/refresh call. | **Verified in `license-service.js`**. |
| **Logging Information Leakage** | License keys or session tokens leaked into server logs. | Logging strictly records timestamps, endpoints, and status codes; sensitive tokens are never printed to console. | **Verified across all modules**. |
