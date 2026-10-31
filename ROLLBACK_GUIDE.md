# Rollback & Recovery Guide

## 1. Overview
In the event that production deployment on Render requires immediate rollback, this document defines the exact step-by-step procedure.

---

## 2. Rollback Triggers
- Unexpected database error during live token activation.
- Failure of Master or Reseller dashboard authentication.
- Any regression in existing active license verifications.

---

## 3. Rollback Procedure

### Step 1: Git Revert / Render Deployment Rollback
1. Open the **Render Dashboard** (`https://dashboard.render.com`).
2. Navigate to `saned-license-server`.
3. Go to the **Events** or **Deploys** tab.
4. Locate the previous successful deployment.
5. Click **Rollback to this deploy**.

### Step 2: Database Schema Compatibility
Because the schema additions are 100% additive:
- The `legacy_sessions` table does not affect previous server versions (it is simply ignored).
- Making `tokens.device_id` nullable does not conflict with older code.
- If necessary to drop `legacy_sessions`:
  ```sql
  DROP TABLE IF EXISTS legacy_sessions;
  ```

### Step 3: Verification After Rollback
1. Execute health check:
   ```bash
   curl -s https://saned-license-server.onrender.com/api/health
   ```
2. Confirm Master login at `/login`.
3. Test active token verification via `POST /api/verify`.
