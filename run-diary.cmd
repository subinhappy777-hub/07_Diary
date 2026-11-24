@echo off
cd /d "%~dp0"
set "PORT=42831"
curl.exe --silent --output NUL --max-time 2 http://127.0.0.1:42831/api/session
if not errorlevel 1 (
  echo 하루결 서버가 이미 실행 중입니다. 브라우저에서 http://127.0.0.1:42831 을 여세요.
  start "" "http://127.0.0.1:42831"
  exit /b 0
)
echo 하루결 서버를 http://127.0.0.1:42831 에서 시작합니다.
node server.js
pause
