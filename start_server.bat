@echo off
title Saned Assistant Verification Server
cd /d "%~dp0"
echo Starting Saned Assistant Verification Server on port 8888...
echo Admin dashboard will be available at: http://localhost:8888
echo.
node server.js
pause
