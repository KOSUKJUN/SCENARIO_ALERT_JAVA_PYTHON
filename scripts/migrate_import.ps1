# 다른 PC 에서 만든 묶음(migrate_export.ps1)으로 시나리오 탐지 스택을 그대로 설치한다 (Docker Desktop, 인터넷 불필요).
# 순서: 파일 손상 확인(sha256) → 프로젝트 풀기 → 이미지 불러오기 → 데이터 볼륨 복원 → 스택 띄우기.
#
# 사용 (묶음 폴더를 이 PC 에 복사한 뒤):
#   powershell -ExecutionPolicy Bypass -File <묶음 폴더>\migrate_import.ps1 [-Dest C:\scenario_Alert_java_python] [-Force] [-NoStart]
#     -Dest    : 프로젝트를 풀 폴더 (기본: 사용자 문서\scenario_Alert_java_python). 비어 있어야 한다
#     -Force   : 이 PC 에 같은 이름의 데이터 볼륨이 이미 있으면 지우고 덮어쓴다 (기존 데이터가 사라진다)
#     -NoStart : 복원만 하고 띄우지 않는다
#     -Project : 도커 프로젝트 이름 (기본 scenario_alert_java_python. 한 PC 에 두 벌 둘 때만 바꾼다)
param(
    [string]$Dest = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'scenario_Alert_java_python'),
    [switch]$Force,
    [switch]$NoStart,
    [string]$Project = 'scenario_alert_java_python'
)
$ErrorActionPreference = 'Stop'
$bundle = $PSScriptRoot
$helper = 'mariadb:10.11'

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

if (-not (Probe @('version'))) { throw 'Docker Desktop 이 실행 중이 아닙니다. 먼저 Docker Desktop 을 켜세요' }
$m = Get-Content (Join-Path $bundle 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json

# 1) 손상 확인
Write-Host '파일 확인 (sha256)'
foreach ($f in $m.files) {
    $p = Join-Path $bundle $f.file
    if (-not (Test-Path $p)) { throw "묶음에 파일이 없습니다: $($f.file)" }
    if ((Get-FileHash $p -Algorithm SHA256).Hash.ToLower() -ne $f.sha256) { throw "파일이 손상되었습니다 (sha256 다름): $($f.file). 다시 복사하세요" }
}

# 2) 기존 볼륨 확인 (실수로 덮어쓰지 않는다)
foreach ($v in $m.volumes) {
    $name = "${Project}_$v"
    if (Probe @('volume', 'inspect', $name)) {
        if (-not $Force) { throw "이 PC 에 볼륨 $name 이 이미 있습니다. 덮어쓰려면 -Force (기존 데이터가 사라집니다)" }
        $users = @(docker ps -aq --filter "volume=$name")
        if ($users.Count) { Run docker (@('rm', '-f') + $users) | Out-Null }
        Run docker @('volume', 'rm', $name) | Out-Null
    }
}

# 3) 프로젝트 풀기
if ((Test-Path $Dest) -and (Get-ChildItem $Dest -Force | Select-Object -First 1)) { throw "설치 폴더가 비어 있지 않습니다: $Dest" }
New-Item -ItemType Directory -Force $Dest | Out-Null
$Dest = (Resolve-Path $Dest).Path
Write-Host "프로젝트 풀기: $Dest"
Run tar.exe @('-xzf', (Join-Path $bundle 'project.tgz'), '-C', $Dest)

# 4) 이미지
Write-Host '이미지 불러오기 (몇 분 걸립니다)'
Run docker @('load', '-i', (Join-Path $bundle 'images.tar'))

# 5) 볼륨 복원 (docker compose 가 자기 볼륨으로 알아보도록 라벨을 단다)
foreach ($v in $m.volumes) {
    $name = "${Project}_$v"
    Write-Host "볼륨 복원: $name"
    Run docker @('volume', 'create', '--label', "com.docker.compose.project=$Project", '--label', "com.docker.compose.volume=$v", $name) | Out-Null
    Run docker @('run', '--rm', '-v', "${name}:/v", '-v', "${bundle}:/b:ro", $helper,
        'tar', '--numeric-owner', '-xzf', "/b/volume-$v.tgz", '-C', '/v')
}

if ($NoStart) {
    Write-Host "복원 완료. 띄우기: cd $Dest; docker compose -p $Project up -d --no-build mariadb clickhouse server worker web mockcase"
    exit 0
}

# 6) 띄우기 (init 은 돌리지 않는다: 데이터가 이미 있다. 빌드하지 않는다: 이미지를 불러왔다)
Set-Location $Dest
$services = @('mariadb', 'clickhouse', 'server', 'worker', 'web', 'mockcase')
Write-Host "스택 띄우기: $($services -join ', ')"
Run docker (@('compose', '-p', $Project, 'up', '-d', '--no-build') + $services)
Write-Host '서버 준비 기다리는 중'
$port = if ($env:API_HOST_PORT) { $env:API_HOST_PORT } else { '8000' }
$ok = $false
for ($i = 0; $i -lt 60 -and -not $ok; $i++) {
    Start-Sleep -Seconds 3
    try { $ok = (Invoke-WebRequest "http://localhost:$port/api/v1/health" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200 } catch { }
}
Write-Host ''
if ($ok) { Write-Host '설치 완료.' } else { Write-Host '컨테이너는 띄웠지만 서버 응답을 아직 받지 못했습니다. docker compose logs server 로 확인하세요.' }
Write-Host '  관리 화면      http://localhost:8080'
Write-Host '  API            http://localhost:8000'
Write-Host '  모의 사고처리  http://localhost:8090'
Write-Host "  프로젝트 폴더  $Dest"
