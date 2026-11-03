@echo off
title NIDS Monitor - Server
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
if exist "C:\Users\ThinkPad\AppData\Local\Programs\Python\Python311\python.exe" (
    "C:\Users\ThinkPad\AppData\Local\Programs\Python\Python311\python.exe" app.py
) else (
    python app.py
)

pause
