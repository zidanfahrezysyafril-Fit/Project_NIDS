@echo off
title NIDS Monitor - Server
echo ==========================================
echo   NIDS Monitor - Network IDS System
echo   Kelompok 10 - AI for Security
echo ==========================================
echo.
echo [*] Memulai server Flask...
echo [*] Akses di browser: http://localhost:5000
echo [*] Tekan CTRL+C untuk menghentikan server
echo.

set PYTHONUTF8=1
"C:\Users\Pongo\AppData\Local\Programs\Python\Python311\python.exe" app.py

pause
