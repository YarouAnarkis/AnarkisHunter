@echo off
:: AnarkisHunter — install.bat
:: Setup script untuk Windows

echo.
echo  AnarkisHunter Penetration Testing Framework
echo  FOR AUTHORIZED PENETRATION TESTING ONLY
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Please install Python 3.11+
    exit /b 1
)
echo [+] Python found

:: Create virtual environment
echo [*] Creating virtual environment...
python -m venv .venv
call .venv\Scripts\activate.bat
echo [+] Virtual environment created

:: Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip -q

:: Install dependencies
echo [*] Installing dependencies...
pip install -r requirements.txt

echo.
echo [+] Installation complete!
echo.
echo Usage:
echo   .venv\Scripts\activate
echo   python webpentest.py --url http://target.local --all
echo   python webpentest.py --help
echo.
echo [!] LEGAL: Only use on systems you have explicit written authorization to test.
pause
