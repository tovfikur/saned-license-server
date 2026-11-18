@echo off
title Saned Assistant Verification Server
cd /d "%~dp0"
echo Starting Saned Assistant Verification Server on port 8888 (Turso DB 151.158.51.11:8085)...
echo Panels: http://localhost:8888/login
echo.
node server.js
pause
