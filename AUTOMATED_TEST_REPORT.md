# Automated Test Execution Report

## Execution Environment
- **Test Runner**: `tests/test-suite.js`
- **Execution Date**: 2026-10-31
- **Platform**: Node.js v20.x on Windows
- **Database**: Isolated test instance

---

## 27-Point Test Results

| Test # | Test Scenario | Expected Behavior | Observed Result | Status |
|---|---|---|---|---|
| **01** | Generate license with no device ID | Returns HTTP 201 with `deviceId: null` | Token created with null device ID | **PASS** |
| **02** | Generate license with preassigned device ID | Returns HTTP 201 with `deviceId: dev1` | Token created bound to dev1 | **PASS** |
| **03** | First device claims unassigned token | HTTP 200, sets `device_id` & `expires_at` | Token bound to dev1 atomically | **PASS** |
| **04** | Same device activates again | HTTP 200 success response | Succeeded without error | **PASS** |
| **05** | Same-device activation retains expiration | Does not reset or extend `expires_at` | Timestamps match exactly | **PASS** |
| **06** | Different device attempts bound token | HTTP 403 device mismatch | HTTP 403 returned with error | **PASS** |
| **07** | Simultaneous activation race (2 devices) | Exactly one winner, one loser | Winner: HTTP 200, Loser: HTTP 403 | **PASS** |
| **08** | Activation without device ID | HTTP 400 Bad Request | HTTP 400 returned | **PASS** |
| **09** | Invalid license token | HTTP 404 Not Found | HTTP 404 returned | **PASS** |
| **10** | Incorrect token format | HTTP 400 `invalid_format` | HTTP 400 returned | **PASS** |
| **11** | Revoked unassigned token | HTTP 403 `revoked` | HTTP 403 returned | **PASS** |
| **12** | Expired unassigned token | HTTP 403 `expired` | HTTP 403 returned | **PASS** |
| **13** | Unassigned token passed to `/api/verify` | HTTP 403 `unassigned` (never claims) | HTTP 403 returned | **PASS** |
| **14** | Preassigned token activated by wrong device | HTTP 403 `device_mismatch` | HTTP 403 returned | **PASS** |
| **15** | Existing bound token continues working | HTTP 200 activate and verify | Both operations succeeded | **PASS** |
| **16** | Existing records survive migration | Row count preserved in database | All rows intact | **PASS** |
| **17** | Legacy adapter requires `x-device-id` | HTTP 400 `device_required` | HTTP 400 returned | **PASS** |
| **18** | Legacy adapter activates unassigned token | Returns genuine session tokens & epoch | Returned accessToken & refreshToken | **PASS** |
| **19** | Legacy adapter rejects different device | HTTP 403 `device_mismatch` | HTTP 403 returned | **PASS** |
| **20** | Legacy refresh from same device | Rotates refresh token & returns new pair | HTTP 200 with new credentials | **PASS** |
| **21** | Legacy refresh from different device | HTTP 403 `device_mismatch` | HTTP 403 returned | **PASS** |
| **22** | Refresh after revocation | HTTP 403 `revoked` and session cleared | HTTP 403 returned | **PASS** |
| **23** | Refresh after license expiration | HTTP 403 `expired` | HTTP 403 returned | **PASS** |
| **24** | Saned dashboard login still works | Master session authenticated | Cookie session issued | **PASS** |
| **25** | Saned admin/reseller panel works | `/api/admin/stats` returns stats object | Returned valid counts | **PASS** |
| **26** | Server restart preserves binding | DB retains bound device and active status | Persisted across operations | **PASS** |
| **27** | Concurrent requests cannot overwrite | 3 simultaneous racers $\to$ 1 winner, 2 losers | Success: 1, Rejected: 2 | **PASS** |

**Summary: 27 / 27 Tests Passed (100% Success Rate).**
