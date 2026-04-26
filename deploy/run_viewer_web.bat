@echo off
setlocal
cd /d "%~dp0"

if exist "python\python.exe" (
    set PYTHON=python\python.exe
    set PYTHONPATH=%~dp0
) else if exist "..\python\python.exe" (
    set PYTHON=..\python\python.exe
    set PYTHONPATH=%~dp0
) else (
    set PYTHON=python
)

echo.
echo ===================================================
echo   감사 로그 웹 조회 서버
echo   브라우저에서 http://localhost:8888 접속
echo ===================================================
echo.

%PYTHON% log_viewer_web.py %*
pause
