@echo off
echo ================================================
echo   SecureAuth -- Secure Login System
echo ================================================
echo.
echo [1/2] Installing Flask...
pip install -r requirements.txt
echo.
echo [2/2] Starting server...
echo.
echo Open your browser and go to: http://localhost:5000
echo Press CTRL+C to stop the server.
echo.
python app.py
pause
 