@echo off
title Web Vulnerability Dashboard
echo Starting Flask backend...
start "Flask Backend" /min cmd /k "cd /d %~dp0backend && set PYTHONPATH=C:\Lib\site-packages && python app.py"
timeout /t 3 /nobreak >nul
echo Starting React frontend...
start "React Frontend" /min cmd /k "cd /d %~dp0frontend && set BROWSER=none && npm start"
echo Both servers starting... Opening browser in 20s
timeout /t 20 /nobreak >nul
start http://localhost:3000
exit
