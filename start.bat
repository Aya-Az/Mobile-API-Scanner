@echo off
echo ========================================
echo   Mobile API Vulnerability Scanner
echo   OWASP Mobile Top 10 ^& API Top 10
echo ========================================
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe. Installez Python 3.10+ depuis python.org
    pause
    exit /b 1
)

if not exist "venv" (
    echo [INFO] Creation de l'environnement virtuel...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo [INFO] Installation des dependances...
pip install -r requirements.txt -q

if not exist "reports\output" mkdir reports\output
if not exist "static" mkdir static

echo.
echo [OK] Demarrage du serveur...
echo [OK] Interface web: http://localhost:8000
echo [OK] Documentation API: http://localhost:8000/docs
echo.
echo Appuyez sur Ctrl+C pour arreter
echo.

python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
