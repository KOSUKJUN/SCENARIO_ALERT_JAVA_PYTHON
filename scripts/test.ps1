# 전체 테스트 (Windows PowerShell): Python 런타임 + Java 단위 + 통합 테스트를 컨테이너에서 실행한다.
# 통합 테스트는 개발 DB 를 초기화하므로, 끝나면 init 을 다시 돌려 개발 환경을 채운다.
# 사용: powershell -ExecutionPolicy Bypass -File scripts\test.ps1
# docker 는 진행 메시지를 stderr 로 내므로 'Stop' 모드로 두지 않는다 (PowerShell 5.1 은 stderr 를 오류로 바꾼다). 종료 코드로 판단한다.
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)

docker compose up -d mariadb clickhouse
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker compose stop server worker

docker compose --profile test run --rm --no-deps --build tester
$rc = $LASTEXITCODE

Write-Host "== 개발 환경 다시 채우기 (reset-data, init, server/worker)"
docker compose run --rm -e APP_MODE=reset-data init | Out-Null
docker compose run --rm init | Out-Null
docker compose up -d --build server worker

if ($rc -eq 0) { Write-Host "== 모든 테스트 통과 (보고서: test-reports\)" -ForegroundColor Green }
else { Write-Host "== 테스트 실패 (보고서: test-reports\)" -ForegroundColor Red }
exit $rc
