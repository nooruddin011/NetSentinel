@echo off
setlocal
echo === Argus - AI Threat Detection ===
if not exist .env copy .env.example .env >nul
if not exist backend\venv (
  echo Creating virtual environment and installing backend dependencies...
  python -m venv backend\venv
  call backend\venv\Scripts\activate.bat
  pip install -r backend\requirements.txt
) 
start "Argus backend" cmd /k "cd backend && venv\Scripts\activate.bat && uvicorn app.main:app --reload"
cd frontend && call npm install --no-audit --no-fund && cd ..
start "Argus frontend" cmd /k "cd frontend && npm run dev"
echo.
echo Open http://localhost:5173  (Sign in as admin: password = ADMIN_PASSWORD in .env, or printed once in the backend window. Others: use Create account)
pause
