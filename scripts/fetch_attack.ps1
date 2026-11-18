# MITRE ATT&CK STIX 번들 받기 (인터넷이 되는 PC 에서 실행 → 받은 파일을 폐쇄망으로 반입).
# 공식 저장소 mitre-attack/attack-stix-data 의 index.json 에서 버전을 찾아 data/attack/ 에 받고 sha256 을 출력한다.
# 반입 후: 서버의 ATTACK_DIR(기본 data/attack)에 복사하고 init 을 돌리거나, 화면 ATT&CK > 버전 관리에서 올린다.
#
# 사용: powershell -ExecutionPolicy Bypass -File scripts\fetch_attack.ps1 [-Version 20.1] [-Domain enterprise-attack] [-List]
#   -Version 생략: 최신 버전
#   -Domain : enterprise-attack (기본) | ics-attack | mobile-attack
#   -List   : 받을 수 있는 버전만 보여 준다
param(
    [string]$Version = '',
    [string]$Domain = 'enterprise-attack',
    [switch]$List
)
$ErrorActionPreference = 'Stop'
$base = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master'
$index = Invoke-RestMethod "$base/index.json"
$names = @{ 'enterprise-attack' = 'Enterprise ATT&CK'; 'ics-attack' = 'ICS ATT&CK'; 'mobile-attack' = 'Mobile ATT&CK' }
$col = $index.collections | Where-Object { $_.name -eq $names[$Domain] }
if (-not $col) { throw "알 수 없는 도메인: $Domain" }
if ($List) {
    $col.versions | Select-Object -First 15 | ForEach-Object { '{0,-8} {1}' -f $_.version, $_.modified.Substring(0, 10) }
    exit 0
}
$v = if ($Version) { $col.versions | Where-Object { $_.version -eq $Version } } else { $col.versions | Select-Object -First 1 }
if (-not $v) { throw "버전 $Version 이 없습니다 (-List 로 확인)" }
$dir = Join-Path (Split-Path -Parent $PSScriptRoot) 'data\attack'
New-Item -ItemType Directory -Force $dir | Out-Null
$file = Join-Path $dir "$Domain-$($v.version).json"
Write-Host "받는 중: $($v.url)"
Invoke-WebRequest $v.url -OutFile $file -UseBasicParsing
$sha = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
Write-Host "저장: $file ($([math]::Round((Get-Item $file).Length / 1MB, 1)) MB)"
Write-Host "sha256: $sha   (반입 후 화면의 sha256 과 같은지 확인)"
