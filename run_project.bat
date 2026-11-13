@echo off
TITLE NetShield AI Launcher
echo ========================================================
echo               Starting NetShield AI
echo ========================================================
echo.

:: Check PostgreSQL and MongoDB
echo [1/3] Ensuring Database Services are running...
net start postgresql-x64-18 >nul 2>&1
net start MongoDB >nul 2>&1

:: Start Backend
echo [2/3] Starting FastAPI Backend on http://127.0.0.1:8000 ...
start "NetShield AI - Backend" cmd /k "cd /d %~dp0backend && ..\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

:: Start Frontend
echo [3/3] Starting React Frontend on http://127.0.0.1:5173 ...
start "NetShield AI - Frontend" cmd /k "cd /d %~dp0frontend && npm run dev -- --host 127.0.0.1 --port 5173"

echo.
echo ========================================================
echo NetShield AI is starting!
echo Backend API Docs: http://127.0.0.1:8000/docs
echo Web Dashboard:    http://127.0.0.1:5173
echo.
echo Default Credentials:
echo   - Admin:   admin@netshield.ai   / AdminNetShield123!
echo   - Analyst: analyst@netshield.ai / AnalystNetShield123!
echo ========================================================
timeout /t 3 >nul
start http://127.0.0.1:5173/login
pause
