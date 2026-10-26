# Saned Assistant License & Verification Server

Lightweight, zero-dependency license management server and admin dashboard for Saned Assistant.

## Features
- **Zero External Dependencies**: Built with native Node.js (`http`, `crypto`, `fs`).
- **Web Admin Dashboard**: Visit `http://localhost:8888` (or deployed URL) to generate tokens with 1 click.
- **8-Character Token System**: Generates unambiguous alphanumeric tokens (e.g. `M7M6WG4F`).
- **Device-Bound Activations**: Binds tokens to specific Android hardware IDs.
- **Configurable Subscription Periods**: 1 day, 7 days, 30 days, 90 days, 365 days.
- **Instant Revocation**: Real-time lock-out for revoked or expired devices.

## Quick Start
```bash
node server.js
```
or on Windows double-click `start_server.bat`.

## API Endpoints
- `GET /` — Admin Dashboard
- `GET /api/health` — Health check
- `POST /api/activate` — Activate 8-character token for device
- `POST /api/verify` — Verify device token & status at startup
- `GET /api/tokens` — List all tokens
- `POST /api/tokens/generate` — Generate token with period
- `POST /api/tokens/revoke` — Revoke token
