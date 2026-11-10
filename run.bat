@echo off
title NIDS Monitor - Server
cd /d "%~dp0"
echo ==========================================
echo   NIDS Monitor - Network IDS System
echo   Kelompok 10 - AI for Security
echo ==========================================
echo.
echo [*] Memulai server Flask (MySQL / XAMPP)...
echo [*] Pastikan modul MySQL di XAMPP sudah AKTIF (hijau).
echo [*] Akses di browser: http://localhost:5000
echo [*] Tekan CTRL+C untuk menghentikan server
echo.

set PYTHONUTF8=1
if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" app.py
) else if exist "C:\Users\ThinkPad\AppData\Local\Programs\Python\Python311\python.exe" (
    "C:\Users\ThinkPad\AppData\Local\Programs\Python\Python311\python.exe" app.py
) else if exist "C:\Users\Pongo\AppData\Local\Programs\Python\Python311\python.exe" (
    "C:\Users\Pongo\AppData\Local\Programs\Python\Python311\python.exe" app.py
) else (
    python app.py
)

pause
