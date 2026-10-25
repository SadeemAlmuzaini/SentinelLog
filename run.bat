@echo off
cd /d "%~dp0"

if exist venv\Scripts\activate.bat goto :haveenv

echo Creating virtual environment with the Python launcher (py -3)...
py -3 -m venv venv

:haveenv
if exist venv\Scripts\activate.bat goto :activate

echo.
echo ERROR: Failed to create the virtual environment.
echo Make sure Python 3.10+ is installed from https://www.python.org/downloads/
echo and that "py --version" works in a normal Command Prompt.
echo.
pause
exit /b 1

:activate
call venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt

echo.
echo Starting SentinelLog at http://127.0.0.1:5000
echo Press CTRL+C in this window to stop the server.
echo.

python backend\app.py

pause
