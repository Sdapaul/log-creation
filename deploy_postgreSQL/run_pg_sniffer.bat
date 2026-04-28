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
echo   PostgreSQL 패킷 스니퍼
echo   관리자(Administrator) 권한으로 실행해야 합니다.
echo ===================================================
echo.

%PYTHON% pg_sniffer.py %*

if %ERRORLEVEL% neq 0 (
    echo.
    echo [오류] 실행 실패. 관리자 권한으로 CMD 를 열고 다시 시도하세요.
    pause
)
