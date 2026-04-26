@echo off
setlocal
cd /d "%~dp0"

if exist "python\python.exe" (
    set PYTHON=python\python.exe
) else if exist "..\python\python.exe" (
    set PYTHON=..\python\python.exe
) else (
    set PYTHON=python
)

echo.
echo ===================================================
echo   감사 로그 웹 조회 서버 시작 중 ...
echo   잠시 후 브라우저가 자동으로 열립니다.
echo ===================================================
echo.

:: 서버를 별도 창에서 실행 (창을 닫으면 서버 종료)
start "감사 로그 웹 뷰어 [서버]" cmd /k "%PYTHON% log_viewer_web.py %*"

:: 서버 기동 대기
timeout /t 2 /nobreak > nul

:: 기본 브라우저로 자동 오픈
start "" "http://localhost:8888"
