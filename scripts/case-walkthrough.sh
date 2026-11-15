#!/usr/bin/env bash
# 사고 사례(docs/cases.md) 기능을 실행 중인 스택(API :8000)에 대고 끝까지 돌려 본다.
#  1) 룰·순서도 적재 확인  2) 룰 수정 → 새 버전  3) 순서도 수정 → v2 Python 코드 생성  4) 컴파일·시뮬레이션
#  5) 사례 데이터 주입 → 실시간 경보  6) 백테스트  7) 전달(모의 사고처리 :8090)
# 사용: bash scripts/case-walkthrough.sh   (node 필요: JSON 처리용)
set -euo pipefail
API=${API:-http://localhost:8000/api/v1}
MOCK=${MOCK:-http://localhost:8090}
WAIT=${WAIT:-150}
T=${T:-test-reports/tmp}; mkdir -p "$T"   # /tmp 는 Git Bash 와 node 가 다르게 본다

j() { node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const o=JSON.parse(s);console.log(eval(process.argv[1]))})" "$1"; }
api() { curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }

TOKEN=$(curl -sS -X POST "$API/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' | j 'o.token')
echo "== 1. 적재 확인"
api "$API/single-rules" | j '"single rules: "+o.length+" / org 대상: "+o.filter(r=>r.entity_type==="org").map(r=>r.rule_id).join(",")'
api "$API/scenarios" | j '"scenarios: "+o.length+" / 사례 순서도: "+o.filter(s=>/WAF_ATTACKER|WANNACRY_HOST|TI_CONTACT|P2P|EXPOSED|ORG_OUTBREAK/.test(s.scenario_id)).map(s=>s.scenario_id+"(v"+s.version+","+s.status+")").join(" ")'
api "$API/meta/fields" | j '"entity_types: "+JSON.stringify(o.entity_types)'

echo "== 2. 단일룰 수정 → 새 버전 (SR_COINMINER 에 XMRig 페이로드 조건 추가, 사례 5)"
api "$API/single-rules/SR_COINMINER" > test-reports/tmp/coin.json
node -e '
const o=JSON.parse(require("fs").readFileSync("test-reports/tmp/coin.json","utf8")); const d=o.definition;
d.filter.any.push({field:"payload",op:"regex",value:"xmrig|\"algo\"\\s*:\\s*\"rx/0\""});
d.description += " 사례: 페이로드에 XMRig 채굴 옵션(algo: rx/0).";
process.stdout.write(JSON.stringify({definition:d, change_note:"사례 5: XMRig 페이로드 정규식 추가"}));' > test-reports/tmp/coin_put.json
api -X PUT "$API/single-rules/SR_COINMINER" --data-binary @test-reports/tmp/coin_put.json | j '"SR_COINMINER → v"+o.rule.version+" warnings="+o.warnings.length'

echo "== 3. 순서도 수정 → v2 Python 코드 (SC_REMOTE_TOOL_MALICIOUS 에 '도구만이면 낮음' 가지, 사례 11)"
node -e 'const g=JSON.parse(require("fs").readFileSync("rules/builtin/scenarios/SC_REMOTE_TOOL_MALICIOUS.json","utf8"));
process.stdout.write(JSON.stringify({graph:g, change_note:"사례 11: 원격제어 도구만 있어도 낮음 경보"}));' > test-reports/tmp/rt_put.json
api -X PUT "$API/scenarios/SC_REMOTE_TOOL_MALICIOUS" --data-binary @test-reports/tmp/rt_put.json | j '"SC_REMOTE_TOOL_MALICIOUS → v"+o.scenario.version'
api "$API/scenarios/SC_REMOTE_TOOL_MALICIOUS/code" | j '"generated code: "+o.python_code.split("\n").length+" lines, generator="+o.generator_version+", n4(check) 포함="+o.python_code.includes("\"n4\"")'
ls data/scenarios/SC_REMOTE_TOOL_MALICIOUS/ 2>/dev/null | tr '\n' ' '; echo

echo "== 4. 컴파일(org 대상 룰)·시뮬레이션(저장 전 초안)"
node -e 'const y=require("fs").readFileSync("rules/builtin/single/SR_ORG_SMB_OUTBREAK.yaml","utf8");' 2>/dev/null || true
api "$API/single-rules/SR_ORG_SMB_OUTBREAK" | j '"SR_ORG_SMB_OUTBREAK entity="+JSON.stringify(o.definition.entity)+" / SQL 에 org_id AS entity: "+(o.compiled_sql||"").includes("org_id AS entity")'
node -e 'const g=JSON.parse(require("fs").readFileSync("rules/builtin/scenarios/SC_WANNACRY_HOST.json","utf8")); g.id="SC_WANNACRY_HOST_DRAFT";
process.stdout.write(JSON.stringify({graph:g, org_id:"ORG001", entity:"10.10.1.52"}));' > test-reports/tmp/sim.json
api -X POST "$API/scenarios/simulate" --data-binary @test-reports/tmp/sim.json | j '"simulate 10.10.1.52 (기존 샘플의 WannaCry 호스트): ok="+o.ok+" alert="+(o.alert?o.alert.severity+" "+o.alert.title:"none")+" hits="+(o.hits||[]).length+" code_sha="+(o.code_sha256||"").slice(0,12)'

echo "== 5. 사례 데이터 주입 (화면 '테스트 데이터'와 같은 API)"
KEYS="waf_attacker waf_attacker_burst wannacry_device wannacry_spread wannacry_fileserver ti_contact_legacy ti_contact_scan p2p_usage p2p_malicious exposed_admin_port exposed_admin_port_success remote_tool_only smb_ipc_kiosk neg_p2p_below neg_admin_port_few"
T0=$(date +%s)
for k in $KEYS; do
  api -X POST "$API/dev/sample-data/inject" -d "{\"scenario\":\"$k\",\"org_id\":\"ORG001\"}" | j '"  "+o.injected[0].scenario+" host="+o.injected[0].host+" events="+o.injected[0].events+" → "+o.injected[0].expect'
done
echo "  ... ${WAIT}초 대기 (평가 주기 1분 + 지연 15초, 순서도 lookaround)"
sleep "$WAIT"

echo "== 6. 실시간 경보 (주입 이후 생성분)"
api "$API/alerts?limit=200" > test-reports/tmp/alerts.json
node -e '
const o=JSON.parse(require("fs").readFileSync("test-reports/tmp/alerts.json","utf8")); const t0=new Date('"$T0"'*1000-120000);
const a=(o.items||[]).filter(x=>new Date(x.created_at)>=t0).sort((p,q)=>p.source_id.localeCompare(q.source_id));
for (const x of a) console.log("  "+x.source_id.padEnd(26)+x.severity.padEnd(9)+x.entity.padEnd(16)+(x.delivery_status||"")+"  "+x.title);
console.log("  total "+a.length);'

echo "== 7. 백테스트 (SC_ORG_OUTBREAK, 최근 1시간) → 실시간과 같은 대상인지"
FROM=$(date -d "-1 hour" '+%Y-%m-%dT%H:%M:00' 2>/dev/null || date -v-1H '+%Y-%m-%dT%H:%M:00')
TO=$(date '+%Y-%m-%dT%H:%M:00')
JOB=$(api -X POST "$API/backtests" -d "{\"target_type\":\"scenario\",\"target_id\":\"SC_ORG_OUTBREAK\",\"time_from\":\"$FROM\",\"time_to\":\"$TO\"}" | j 'o.job_id')
for i in $(seq 1 30); do
  S=$(api "$API/backtests/$JOB" | j 'o.status'); [ "$S" = "done" ] && break; sleep 3
done
api "$API/backtests/$JOB" | j '"  status="+o.status+" alerts="+JSON.stringify((o.result&&o.result.alerts||[]).map(a=>a.entity+":"+a.severity))'

echo "== 8. 전달: 모의 사고처리 시스템이 받은 사건"
curl -sS "$MOCK/api/cases" | j '"  cases="+(Array.isArray(o)?o.length:(o.items||[]).length)'
