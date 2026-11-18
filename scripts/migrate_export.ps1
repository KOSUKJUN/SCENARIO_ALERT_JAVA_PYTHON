# 이 PC 의 시나리오 탐지 스택을 다른 PC(Docker Desktop)로 옮기기 위한 묶음 만들기.
# 묶음 = 도커 이미지(docker save) + 데이터 볼륨(MariaDB·ClickHouse) + 프로젝트 파일(소스·설정·data/ 의 ATT&CK·D3FEND) + 설치 스크립트.
# 옮길 PC 는 인터넷이 없어도 된다 (이미지를 다시 받거나 빌드하지 않는다).
#
# 사용 (프로젝트 폴더에서):
#   powershell -ExecutionPolicy Bypass -File scripts\migrate_export.ps1 [-Out D:\scenario-migrate] [-IncludeTester]
#     -Out           : 묶음을 만들 폴더 (기본: 프로젝트 옆 scenario-migrate-<날짜시각>)
#     -IncludeTester : 테스트 이미지(약 1.3GB)도 넣는다 (옮긴 PC 에서 테스트를 돌릴 때만)
# 데이터가 일관되게 복사되도록 볼륨을 복사하는 동안(수십 초~수 분) 스택을 멈췄다가 다시 띄운다.
param(
    [string]$Out = '',
    [switch]$IncludeTester
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$project = 'scenario_alert_java_python'
$ver = if ($env:APP_VERSION) { $env:APP_VERSION } else { '0.3.0' }
$helper = 'mariadb:10.11'   # 볼륨 복사에 쓰는 이미지 (tar 가 있고 묶음에 어차피 들어간다)

function Run([string]$exe, [string[]]$argv) {
    & $exe @argv
    if ($LASTEXITCODE -ne 0) { throw "실패: $exe $($argv -join ' ')" }
}

# 있는지 확인만 하는 docker 호출. PowerShell 5.1 은 Stop 모드에서 오류 출력만으로 멈추므로 잠시 Continue 로 둔다.
function Probe([string[]]$argv) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & docker @argv 2>&1 | Out-Null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    return $code -eq 0
}

if (-not (Probe @('version'))) { throw 'Docker 가 실행 중이 아닙니다' }
if (-not $Out) { $Out = Join-Path (Split-Path -Parent $root) ("scenario-migrate-" + (Get-Date -Format 'yyyyMMdd-HHmm')) }
if ((Test-Path $Out) -and (Get-ChildItem $Out -Force | Select-Object -First 1)) { throw "묶음 폴더가 비어 있지 않습니다: $Out" }
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
Write-Host "묶음 폴더: $Out"

$images = @($helper, 'clickhouse/clickhouse-server:25.3.2.39', "scenario-engine-java/server:$ver",
    "scenario-engine-java/web:$ver", "scenario-engine-java/mockcase:$ver")
if ($IncludeTester) { $images += "scenario-engine-java/tester:$ver" }
foreach ($i in $images) {
    if (-not (Probe @('image', 'inspect', $i))) { throw "이미지가 없습니다: $i (먼저 docker compose build 또는 docker build 로 만드세요)" }
}
$volumes = @('mariadb-data', 'clickhouse-data')
foreach ($v in $volumes) {
    if (-not (Probe @('volume', 'inspect', "${project}_$v"))) { throw "볼륨이 없습니다: ${project}_$v" }
}

# 1) 스택 멈춤 → 볼륨 복사 (소유자·권한 그대로) → 다시 띄움
$running = @(docker compose ps --status running --services)
$runningIds = @(docker compose ps --status running -q)   # 다시 켤 때 이 컨테이너만 (의존 서비스 init 을 다시 돌리지 않는다)
Write-Host "스택 멈춤 (실행 중: $($running -join ', '))"
Run docker @('compose', 'stop')
try {
    foreach ($v in $volumes) {
        Write-Host "볼륨 복사: ${project}_$v"
        Run docker @('run', '--rm', '-v', "${project}_${v}:/v:ro", '-v', "${Out}:/b", $helper,
            'tar', '--numeric-owner', '-czf', "/b/volume-$v.tgz", '-C', '/v', '.')
    }
} finally {
    if ($runningIds.Count) {
        Write-Host "스택 다시 띄움: $($running -join ', ')"
        Run docker @('compose', 'start', 'mariadb', 'clickhouse') | Out-Null   # DB 먼저 (의존 서비스 없음)
        for ($i = 0; $i -lt 40; $i++) {
            $h = @(docker compose ps mariadb clickhouse --format '{{.Health}}')
            if (($h | Where-Object { $_ -ne 'healthy' }).Count -eq 0) { break }
            Start-Sleep -Seconds 3
        }
        Run docker (@('start') + $runningIds) | Out-Null
    }
}

# 2) 이미지
Write-Host "이미지 저장 (수 GB, 몇 분 걸립니다): $($images -join ', ')"
Run docker (@('save', '-o', (Join-Path $Out 'images.tar')) + $images)

# 3) 프로젝트 파일 (빌드 산출물·node_modules 는 뺀다. data/ 의 ATT&CK·D3FEND 릴리스는 넣는다)
Write-Host "프로젝트 파일 묶기"
Run tar.exe @('-czf', (Join-Path $Out 'project.tgz'), '--exclude=./web/node_modules', '--exclude=./web/dist',
    '--exclude=./web/test-results', '--exclude=./web/playwright-report', '--exclude=./target', '--exclude=./test-reports',
    '-C', $root, '.')

# 4) 설치 스크립트와 목록 (sha256 으로 옮긴 뒤 손상 확인)
Copy-Item (Join-Path $PSScriptRoot 'migrate_import.ps1') $Out
$files = Get-ChildItem $Out -File | Where-Object { $_.Name -ne 'migrate_import.ps1' } | ForEach-Object {
    [pscustomobject]@{ file = $_.Name; size = $_.Length; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
}
$manifest = [ordered]@{
    created_at = (Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz'); project = $project; app_version = $ver
    images = $images; volumes = $volumes; services = $running; files = @($files)
}
$manifest | ConvertTo-Json -Depth 5 | Out-File (Join-Path $Out 'manifest.json') -Encoding utf8
$total = ($files | Measure-Object -Property size -Sum).Sum
Write-Host ""
Write-Host ("완료: {0} ({1:N1} GB)" -f $Out, ($total / 1GB))
Write-Host "이 폴더를 통째로 옮길 PC 에 복사한 뒤, 그 PC 에서:"
Write-Host "  powershell -ExecutionPolicy Bypass -File <묶음 폴더>\migrate_import.ps1 -Dest C:\scenario_Alert_java_python"
