@echo off
title Saned Assistant Verification Server
cd /d "%~dp0"
echo Starting Saned Assistant Verification Server on port 8888...
echo Panels: http://localhost:8888/login
echo.
echo Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN to use Turso.
echo Without them, a local file database (local.db) is used.
echo.
node server.js
pause
