@echo off
rem Sleep ~7s without needing a console (timeout.exe refuses headless jobs).
ping -n 8 127.0.0.1 >nul
exit /b 0
