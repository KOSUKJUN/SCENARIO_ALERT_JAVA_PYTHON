# MITRE D3FEND 릴리스 받기 (인터넷이 되는 PC 에서 실행 → 받은 폴더를 폐쇄망으로 반입).
# https://d3fend.mitre.org/ontologies/d3fend/<버전>/ 의 d3fend.json(온톨로지) 과 d3fend-full-mappings.csv(ATT&CK 매핑)를
# data/d3fend/<버전>/ 에 받고 sha256 을 출력한다.
# 반입 후: 서버의 D3FEND_DIR(기본 data/d3fend)/<버전>/ 에 복사하고 init 을 돌리거나, 화면 D3FEND 대응 > 버전 관리에서 두 파일을 올린다.
#
# 사용: powershell -ExecutionPolicy Bypass -File scripts\fetch_d3fend.ps1 -Version 1.6.0
#   버전 목록: https://d3fend.mitre.org/resources/ontology/ (매핑 CSV 는 0.14.0 부터 있다)
param(
    [Parameter(Mandatory = $true)][string]$Version
)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "버전 형식이 아닙니다: $Version (예: 1.6.0)" }
$base = "https://d3fend.mitre.org/ontologies/d3fend/$Version"
$dir = Join-Path (Split-Path -Parent $PSScriptRoot) "data\d3fend\$Version"
New-Item -ItemType Directory -Force $dir | Out-Null
foreach ($f in @('d3fend.json', 'd3fend-full-mappings.csv')) {
    $out = Join-Path $dir $f
    Write-Host "받는 중: $base/$f"
    Invoke-WebRequest "$base/$f" -OutFile $out -UseBasicParsing
    $sha = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
    Write-Host ("저장: {0} ({1} MB)  sha256: {2}" -f $out, [math]::Round((Get-Item $out).Length / 1MB, 1), $sha)
}
Write-Host "폴더 $dir 를 통째로 서버의 D3FEND_DIR 에 복사하세요 (폴더 이름 = 버전)."
