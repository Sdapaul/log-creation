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
echo   PostgreSQL 감사 프록시 (Superset 전용)
echo   root 권한 불필요 -- 일반 계정으로 실행 가능
echo ===================================================
echo.
echo   Superset DB URI 예시:
echo   postgresql+psycopg2://user:pass@이서버IP:5433/dbname?sslmode=disable
echo.

%PYTHON% pg_proxy.py %*

if %ERRORLEVEL% neq 0 (
    echo.
    echo [오류] 실행 실패. config.py 의 PG_HOST / PG_PORT 를 확인하세요.
    pause
)
