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
echo   감사 로그 CLI 조회
echo ===================================================
echo.

%PYTHON% log_viewer.py %*
pause
