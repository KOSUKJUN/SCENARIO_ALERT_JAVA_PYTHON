# Java 버전 구조 (Python 원본 대비)

설계안([design.md](design.md))의 두 층 구조는 그대로다. 단일룰은 ClickHouse SQL 로 변환해 히트를 만들고,
순서도는 히트를 조합해 경보를 만든다. 바뀐 것은 **각 층을 실행하는 언어**와, 순서도 평가를 **시나리오마다 생성되는 코드**로 바꾼 점이다.

## 1. 무엇이 어디서 도는가

| 단계 (설계안 7장) | 담당 | 위치 |
|---|---|---|
| 실행 대상 선택 (SKIP LOCKED), 따라잡기 | Java | `detection/Scheduler` |
| 단일룰 정의 검증, SQL 변환, `INSERT … SELECT` 실행 | Java | `singlerule/*` |
| 단독 경보 (`alert_on_hit`) | Java | `detection/DetectionService` |
| 후보 대상 선정, 히트 조회 (ClickHouse), 자산 태그 조회 (MariaDB) | Java | `detection/DetectionService` |
| **순서도 평가** (노드 따라가기, 경보 노드 도달, 가장 높은 등급 선택, 경로) | **Python, 시나리오별 생성 코드** | `data/scenarios/<ID>/v<N>.py` + `python/scenario_runtime/runtime.py` |
| 경보 생성·상향·억제, 전달·재시도 | Java | `alerting/*` |
| 백테스트 (단일룰 SQL, 순서도는 같은 생성 코드로) | Java + 생성 코드 | `backtest/BacktestService` |
| 화면 시뮬레이션 (저장 전 초안) | Java + 초안의 생성 코드 | `api/ScenariosController#simulate` |

## 2. 시나리오별 Python 코드 생성

순서도를 저장하면(`POST/PUT /scenarios`, 기본 순서도 적재 포함) 다음이 한 트랜잭션에서 일어난다.

1. `GraphValidator` 가 그래프를 검증한다 (순환, 시작 1개, 마름모 yes/no, within, 참조 룰, 최대 기간 7일 …).
2. `ScenarioCodeGenerator` 가 노드를 위상 순서로 펼친 Python 모듈을 만든다.
3. 코드와 sha256 을 `scenario_versions.python_code / code_sha256 / generator_version` 에 저장한다.
4. 파일 `SCENARIO_CODE_DIR/<ID>/v<N>.py` 로도 쓴다 (캐시. 없으면 평가 때 DB 에서 다시 쓴다).

생성 예 (SC_SMB_WORM 일부):

```python
def evaluate(hits, asset_tags):
    ev = rt.Evaluation(hits, asset_tags)

    # [n0] start
    t0_n0 = ev.start("n0")

    # [n1] rule  <- n0
    t1_n1 = ev.rule("n1", "SR_SMB_OUT_FANOUT", t0_n0, within=None)

    # [n2] check  <- n1
    t2_n2_yes, t2_n2_no = ev.check("n2", ("SR_WANNACRY_SIG", "SR_TI_HIT"), t1_n1, lookaround=86400)

    # [n3] asset  <- n2
    t3_n3_yes, t3_n3_no = ev.asset("n3", ("legacy_os", "medical_device", "kiosk"), t2_n2_no)

    # [a1] alert  <- n2, n3
    ev.alert("a1", "critical",
             "SMB 웜 전파 (고위험): {{entity}}",
             "네트워크 격리(포맷 금지), ...",
             (t2_n2_yes, t3_n3_yes))
    ...
    return ev.result()
```

- 노드 연산의 의미(within, lookaround, and/or 합류, 토큰 상한)는 `runtime.py` 한 곳에만 있다. 원본 `evaluator.py` 와 같은 규칙이다.
  생성 코드는 "이 순서도의 모양"만 담는다. 그래서 새 시나리오는 코드 수정 없이 화면에서 등록되고,
  새 노드 유형이 필요할 때만 런타임과 생성기를 고친다 (CLAUDE.md "일반 기능으로 추가").
- 버전마다 파일이 따로 생기고 이전 버전 코드는 DB 에 남는다. 경보는 `source_version` 으로 어떤 코드가 만들었는지 추적된다.
- 저장 전 초안(시뮬레이션·백테스트 초안)은 같은 생성기로 `_drafts/<sha256>.py` 에 만든다. 실시간과 다른 평가 로직이 없다.

### 안전장치

- 생성 코드에는 검증을 통과한 그래프만 들어간다. 사용자 문자열(이름, 제목, 대응 방법, 룰 ID, 태그)은 모두
  이스케이프한 문자열 리터럴로만 들어가고, 주석에는 정규식으로 검증된 노드 ID·노드 유형만 쓴다 (테스트: 따옴표·줄바꿈·U+2028 주입).
- Python 은 `-I`(격리 모드)·`-B`(.pyc 안 씀)로 띄운다. 생성 코드는 DB·네트워크에 접근하지 않는다.
- worker 는 요청에 담긴 sha256 과 파일 내용이 다르면 실행을 거부한다 (파일이 바뀌었으면 Java 가 DB 원본으로 다시 쓴다).
- 응답 제한 시간(기본 30초)을 넘기거나 프로세스가 죽으면 그 프로세스를 버리고 새로 띄운다. 평가는 상태가 없어 결과가 같다.

## 3. Java ↔ Python 통신

- 서버마다 Python 상주 프로세스 `PYTHON_WORKERS`(기본 2)개. `python3 -I -B -u python/scenario_runtime/worker.py`
- 표준 입출력 JSON 한 줄씩. 요청 하나에 같은 순서도의 여러 대상(최대 200건)을 묶는다.
  실시간은 한 평가 구간의 새 히트 대상들을, 백테스트는 모든 (대상, 평가 시각)을 한 번에 보낸다.
- 억제 정책(`decide`)과 경보 기록은 Java 에 둔다. Python 은 "어느 경보 노드에 어떤 경로로 도달했는가"만 돌려준다.

```
요청: {"id":2,"op":"evaluate","module":".../SC_SMB_WORM/v3.py","sha256":"…",
       "cases":[{"org_id":"ORG001","entity":"10.10.1.50","hits":[…],"asset_tags":["legacy_os"],"new_hit_keys":[…]}]}
응답: {"id":2,"ok":true,"results":[{"node_status":{…},"reached_alerts":["a1"],
       "chosen":{"node":"a1","severity":"critical","title":"…","path":[…],"first_seen":"…","last_seen":"…"}}]}
```

## 4. 원본과 다르게 판단한 것

| 항목 | 원본 (Python) | Java 버전 | 이유 |
|---|---|---|---|
| 순서도 평가 | 공통 `evaluate(graph, …)` 가 그래프를 해석 | 시나리오·버전마다 생성한 코드 실행 | 요청 사항. 노드 의미는 런타임 한 곳에 두어 시나리오마다 로직이 갈라지지 않게 했다 |
| 생성 코드 보관 | — | MariaDB 가 원본, 파일은 캐시 | 서버를 여러 대 띄워도 공유 디스크 없이 같은 코드(같은 sha256)를 쓴다 (무상태 원칙) |
| 실행 방식 | 프로세스 안 함수 호출 | 상주 프로세스 풀 + 배치 요청 | 평가마다 프로세스를 띄우면 1분 주기·백테스트에서 느리다 |
| MariaDB 마이그레이션 | Alembic | Flyway (`V1__initial.sql`) | Java 표준. 스키마는 같고 `python_code` 등 3칼럼만 추가 |
| ClickHouse 접속 | clickhouse-connect | HTTP 인터페이스 직접 (서버 측 `{name:Type}` 파라미터) | 원본과 같은 파라미터 방식을 그대로 쓰려고 (값은 SQL 에 잇지 않는다) |
| 모의 사고처리 시스템 | FastAPI | 의존성 없는 Java 단일 파일 | "시나리오 외에는 Java" |
| 그래프 검증 | — | `description`, `label` 길이·타입 검사 추가 | 생성 코드에 들어가는 값이라 미리 거른다 |
| 화면 | — | 버전 탭에 "Python 코드" 보기 | 생성 결과를 바로 확인 |
| 단일룰 화면 | 메뉴 "단일룰" 따로 | 화면 이름 **이벤트 탐지모듈**, 시나리오 분석의 [이벤트 탐지모듈 관리] 새 창 + 순서도 편집기 옆 패널에서 만들기·편집, 왼쪽 시나리오 그룹 (`scenario_groups`, Flyway V6) (2026-11-21) | 요청 사항. 이벤트 탐지모듈은 시나리오의 재료라 한 화면에서 다룬다. API·DB·룰 ID·스냅샷은 그대로 ([design.md](design.md) 변경 이력) |
| 대상 유형 | host (src_ip, dst_ip) | host + **org (org_id)** | 사고 사례 "PC 여러 대 동시 감염"은 기관 단위 집계가 필요하다 ([cases.md](cases.md) 2장) |
| 기본 룰·순서도 | 14 + 7 | 24 + 14 | 사고 사례 12건을 대입해 7 + 6 추가, 1개 수정 ([cases.md](cases.md) 1장). PHP2Shell 3 + 1 추가 (5장) |
| 원본 이벤트 테이블 | `codlog.log_integrated_success_all`, 필드마다 컬럼 | 대상 서버와 같은 `codlog.log_integrated_success_all` (MergeTree, `fields` JSON, 기관은 로그 수집원 매핑) | 대상 스키마에 맞춤 (2026-11-17 → 2026-11-21). 아래 5장 |
| 경보 저장 | MariaDB `alerts` | 본문은 ClickHouse `codlog.alert_integrated_all`, 상태(억제·경로·판정·전달·ATT&CK)는 MariaDB `alert_state` | 요청 (2026-11-21). 아래 5장 |

## 5. 원본 로그·경보 테이블 (2026-11-21 대상 ClickHouse 구조로 변경)

대상 ClickHouse(25.3)의 `codlog` DB 두 테이블을 **같은 이름·구조**로 쓴다 (테스트 사본: [clickhouse/source/001](../clickhouse/source/001_log_integrated_success_all.sql),
[002](../clickhouse/source/002_alert_integrated_all.sql), 대상 서버의 SHOW CREATE TABLE 결과를 그대로 옮김). 접속 주소·계정은 환경 변수(`CH_URL`, `CH_USER` …)로만 받는다.

| 테이블 | 엔진·키 | 이 시스템이 하는 일 |
|---|---|---|
| `codlog.log_integrated_success_all` (원본 로그) | MergeTree 하나, `ORDER BY (_collect_time, _parser_cd, _asset_id)`, 30일 TTL | 읽기만. 탐지 뷰 `detect.v_events` 와 최초 관측 MV(`views/031`)가 이 테이블을 본다 |
| `codlog.alert_integrated_all` (경보) | ReplacingMergeTree(`_collect_time`), `ORDER BY (window_ms, _data_type, attack, risk)`, 30일 TTL | **이 시스템의 경보 본문을 여기에만 넣는다** (`alerting/AlertStore`) |

원본 로그 → 탐지 뷰 매핑은 이전과 같다:

| 원본 | 탐지 뷰(`detect.v_events`) | 비고 |
|---|---|---|
| `_event_cd` / `_collect_time` / `_data_type` | `event_id` / `mgr_time` (평가 시간축) / `data_tp` | |
| `_asset_id` (로그 수집원) | `log_source`, **`org_id` = MariaDB `log_sources` 매핑** (딕셔너리 `dict_log_sources`) | 원본에 기관 컬럼이 없다. 매핑 없는 수집원은 `UNASSIGNED` |
| 공통 필드 (모두 Nullable) | 같은 이름 | `src_lat`/`src_lng` 는 문자열 |
| `fields` (**JSON 타입**) | `ifNull(toString(fields.키), '')` 로 action·risk·payload·uri… | `count` 도 fields 안 (없으면 1건) |

### 경보 = ClickHouse 본문 + MariaDB 상태

| 어디 | 무엇 |
|---|---|
| ClickHouse `codlog.alert_integrated_all` | `_alert_cd`(= 경보 ID), `_data_type`(**`SCENARIO`** 시나리오 / **`EVENT_MODULE`** 이벤트 탐지모듈 단독), `attack`(= 제목), `risk`(LOW/MEDIUM/HIGH/CRITICAL), `max_lvl`(1~4), `event_sdt`/`event_edt`/`event_time`(최초/최종), `window_ms`(최초 시각의 1시간 구간), `count`(탐지 횟수), `rull_grp_cd`(룰 그룹 코드 = 시나리오 그룹 코드), `group_cd`·`group_nm`(CODPRO 그룹 = 대상 기관 코드·기관명), `src_ip`·`dst_ip`(대상 IP 는 첫 모듈의 대상 필드 칸), 포트·국가·장비·조치·에이전트(첫 근거 이벤트), `tmuser`(작성자), `fields`(기관·대상·출처·버전·경보 노드·대응 절차·모듈 목록·ATT&CK·silent) |
| MariaDB `alert_state` (Flyway V7, 이전 `alerts`) | 같은 ID 로 억제 상태(출처·기관·대상·등급·최종 시각), 경로(path), 판정, 전달 상태, ATT&CK·D3FEND 스냅샷, `ch_window_ms`(ClickHouse 행 찾기) |

- 같은 경보가 다시 탐지되면 같은 키로 다시 넣어 횟수·최종 시각을 갱신한다(늦게 넣은 행이 남는다). 등급이 오르면 키가 바뀌므로 이전 행을 가벼운 DELETE 로 지우고 넣는다.
- 같은 시간·제목·등급에 다른 경보가 있으면(다른 기관의 같은 IP) 제목 뒤에 `[기관]` 을 붙여 덮어쓰지 않는다.
- ClickHouse 쓰기는 MariaDB 트랜잭션 안에서 한다. 실패하면 MariaDB 도 되돌리고 다음 주기에 같은 구간을 다시 평가한다.
- 테스트운영(silent) 경보도 넣고 `fields.silent=true` 로 표시한다 (다른 화면이 거를 수 있게).
- 경보 목록·상세·전달 내용은 상태를 MariaDB 에서 고르고 본문을 ClickHouse 에서 붙인다. `rull_grp_cd` 는 경보를 만들 때의 그룹 코드다(나중에 그룹을 바꿔도 그대로).
- 이전 MariaDB 경보는 V7 이 `alerts_legacy` 로 남기고 init 이 ClickHouse 로 옮긴 뒤 그 행을 지운다.

### 실제 테이블이 있는 서버에 붙일 때

- 대상 서버 경보 테이블은 2026-11-21 에 `group_cd`·`group_nm` 이 추가되고 `grp_cd` → `rull_grp_cd` 이름 변경이 예정돼 있다 (이 시스템은 `rull_grp_cd` 를 쓴다. 이름 변경 전에는 경보 쓰기가 실패한다). 로컬 사본은 `source/003` 이 바꾼다.
- **`CH_MANAGE_SOURCE=false`** 로 띄운다 (앱 기본값도 false, 개발 스택 compose 만 true). true 면 init 이 `clickhouse/source/` 사본을 만들고 reset-data 가 원본 로그를 비운다.
  reset-data 는 false 여도 경보 테이블에서 이 시스템이 넣은 행(`SCENARIO`/`EVENT_MODULE`)만 지운다.
- 탐지 계정 권한: `SELECT` on `codlog.log_integrated_success_all`, `SELECT, INSERT, ALTER DELETE, ALTER UPDATE` on `codlog.alert_integrated_all`
  (가벼운 DELETE 는 `ALTER UPDATE(_row_exists)` 도 쓴다), `detect.*` 전부.
- 딕셔너리(020)는 MariaDB 를 원본으로 읽으므로 대상 ClickHouse 가 이 시스템의 MariaDB 에 접속할 수 있어야 한다.

## 6. MITRE ATT&CK (폐쇄망 내부 사본, 버전 관리)

MITRE 공식 STIX 2.1 번들(mitre-attack/attack-stix-data 의 `enterprise-attack-<버전>.json`, ics·mobile 도 가능)을 MariaDB 에
버전별로 넣어 쓴다. 탐지 중에는 인터넷을 쓰지 않는다.

| 항목 | 내용 |
|---|---|
| 저장 | `attack_versions`(도메인·버전·파일 sha256·활성 여부), `attack_objects`(전술 TA, 기법·하위 기법 T, 완화 M, 그룹 G, 소프트웨어 S, 탐지 전략 DET), `attack_relations`(기법을 향한 mitigates·detects·uses). Flyway V3 |
| 반입 | 인터넷 PC 에서 `scripts\fetch_attack.ps1 -Version 20.1` → 파일을 서버 `ATTACK_DIR`(기본 `data/attack`, compose 가 `/app/data/attack` 로 연결)에 복사하면 `init` 이 가져온다. 또는 화면 ATT&CK > 버전 관리에서 올린다 (admin) |
| 버전 | 도메인마다 활성 버전은 하나. 같은 파일은 다시 넣지 않고(sha256), 같은 버전의 다른 파일은 거부한다. 처음 가져온 도메인은 바로 활성, init 은 가장 높은 버전을 활성화한다. 활성 버전은 지울 수 없다 |
| 옮기기 | 버전 목록의 "내보내기"(`GET /api/v1/attack/versions/{domain}/{version}/export`, admin)로 패키지 `attack_<도메인>_<버전>.zip` 을 받아, 다른 서버에서 "패키지 가져오기"(`POST /api/v1/attack/versions/import-package`)로 올리거나 `ATTACK_DIR` 에 두면 init 이 가져온다. 패키지 = `manifest.json`(형식·버전 행·테이블별 행 수와 sha256) + 테이블별 JSONL. 원본 번들의 파일 이름·sha256 을 그대로 옮기므로 같은 원본을 다시 넣어도 "이미 가져옴" 이다. 변조(sha256 불일치)·모르는 파일·다른 종류의 패키지는 거부한다. 공통 형식은 `common/VersionPackage` |
| 비교 | 활성화 전에 활성 버전과 비교: 추가·없어짐·폐기(대체 기법)·사용 중단·이름·전술 변경과, **현재 룰·순서도가 참조하는 기법 중 영향받는 것** |
| 룰·순서도 | 단일룰 정의의 `attack: [T1190]`, 순서도 경보 노드의 `attack`. 형식은 검증기가, 존재 여부는 저장 때 활성 버전으로 검사 (없거나 폐기면 오류, 사용 중단이면 경고, 데이터가 없으면 경고만) |
| 경보 | 기법 = 고른 경보 노드의 attack + **경로에서 실제로 성립한 룰**의 attack + 같은 평가에서 함께 성립한 경보 노드의 attack. 억제 시간 안에 같은 대상의 다음 단계가 보이면 등급이 같아도 기법을 누적하고 다시 전달한다(전달 중 기법이 바뀌면 그 전달 결과로 덮어쓰지 않는다). 만들 때(등급 상향 때) 활성 버전의 이름·전술과 버전을 `alerts.attack`, `alerts.attack_version` 에 함께 저장한다(나중에 버전이 바뀌어도 경보 내용은 그대로). 사고처리 시스템 전달 내용에도 들어간다 |
| 화면 | ATT&CK 메뉴: 탐지 커버리지 매트릭스(전술 × 기법, 단일룰/순서도/30일 경보 수), 기법 찾기·상세(완화, 탐지 전략, 그룹, 소프트웨어, 이 시스템의 탐지), 버전 관리. 룰 편집기·순서도 경보 노드에 기법 고르기, 경보 목록 필터(상위 기법이면 하위 포함)·상세 표시 |

설계 원칙과의 관계: ATT&CK 은 경보에 붙는 설명 정보라 탐지 판정(단일룰 SQL, 순서도 생성 코드)을 바꾸지 않는다.
생성 코드에는 들어가지 않으므로 GENERATOR 버전도 그대로다. 서버는 활성 버전을 메모리에 두지 않고 매번 DB 에서 읽는다(서버·worker 여러 대가 같은 버전을 본다).
기본 룰 23개에 기법을 달았다(P2P 는 정책 위반이라 매핑하지 않음). 테스트는 공식 19.2·20.1 번들에서 잘라 낸 작은 번들(`src/test/resources/attack`)을 쓴다.

## 7. MITRE D3FEND 대응방책 (폐쇄망 내부 사본, 버전 관리, 2026-11-18)

MITRE D3FEND 공식 릴리스를 MariaDB 에 버전별로 넣고, ATT&CK 기법과 이어서 경보의 대응방책으로 쓴다.
한 버전은 두 파일이다: 온톨로지 `d3fend.json`(JSON-LD: 전술, 방어 기법 D3-xxx, ATT&CK 완화 M 과의 관계)과
D3FEND 가 추론한 ATT&CK 매핑 `d3fend-full-mappings.csv`(ATT&CK 기법 ↔ 방어 기법, 디지털 아티팩트 근거).

| 항목 | 내용 |
|---|---|
| 저장 | `d3fend_versions`(버전·두 파일 sha256·활성), `d3fend_tactics`, `d3fend_techniques`(상위 기법·깊이·전술·정의·KB 설명), `d3fend_attack_map`(ATT&CK → 방어 기법, enterprise/ics, 근거 3개까지), `d3fend_mitigation_map`(ATT&CK M ↔ 방어 기법). 경보 `alerts.d3fend`, `alerts.d3fend_version`. Flyway V5 |
| 읽기 | 방어 기법 = `d3fend-id` 가 `D3-` 인 노드. 상위 = subClassOf 의 다른 방어 기법, 전술 = 자신이나 조상의 `d3f:enables`. 전술에 닿지 않는 노드(분석 모델 D3-ARMA 등, 분석 기법 D3A-)는 대응방책이 아니라 뺀다. 매핑 CSV 는 `query_def_tech_label`(이름)로 온톨로지와 잇고 SPARTA 행은 버린다 |
| 반입 | 인터넷 PC 에서 `scripts\fetch_d3fend.ps1 -Version 1.6.0` → `data/d3fend/<버전>/` 폴더째 서버 `D3FEND_DIR`(기본 `data/d3fend`)에 복사하면 `init` 이 가져온다(ATT&CK 다음, 기본 룰 앞). 또는 화면 D3FEND 대응 > 버전 관리에서 두 파일을 올린다 (admin) |
| 버전 | 활성 버전 하나. 같은 파일 쌍은 다시 넣지 않고, 같은 버전의 다른 파일은 거부. 활성 버전은 지울 수 없다. 비교: 기법 추가·없어짐·이름·전술/상위 변경, 정의 갱신, 매핑 증감, **지정 대응방책 중 없어지는 기법** |
| 옮기기 | ATT&CK 과 같다: "내보내기"(`GET /api/v1/d3fend/versions/{version}/export`) → `d3fend_<버전>.zip` (`d3fend_tactics`·`d3fend_techniques`·`d3fend_attack_map`·`d3fend_mitigation_map` JSONL), 받는 서버에서 "패키지 가져오기"(`POST /api/v1/d3fend/versions/import-package`) 또는 `D3FEND_DIR` 에 zip 그대로 둔다. 원본 두 파일의 sha256 을 유지한다 |
| 지정 대응방책 | 단일룰 정의의 `d3fend: [D3-NI, D3-PT]`, 순서도 경보 노드의 `d3fend`. 형식은 검증기가, 존재 여부는 저장 때 활성 버전으로 검사(없으면 오류, 데이터가 없으면 경고). 편집 화면에서 ATT&CK 기법 기준 사고 대응 기법을 추천한다 |
| 경보 | 지정 대응방책 = ATT&CK 과 같은 범위(고른·함께 성립한 경보 노드 + 경로에서 성립한 룰). 생성·상향 때 이름·전술·버전을 스냅샷으로 저장하고, 억제 시간 안에 다음 단계가 보이면 누적해 다시 전달한다. 사고처리 시스템 전달 내용에 `d3fend`, `d3fend_version` 이 들어간다 |
| 권고 대응방책 | `POST /api/v1/d3fend/countermeasures {attack, d3fend}`: 활성 버전의 매핑으로 계산(경보에 저장하지 않는다). 전술 순서 격리 → 퇴출 → 복구(사고 대응) → 탐지 → 강화 → 기만 → 모델링, 전술 안에서는 지정 → ATT&CK 완화(M)와 연결된 권고 → 더 많은 기법에 대응. 하위 기법(T1059.004)에 매핑이 없으면 상위(T1059)를 쓴다 |
| 화면 | D3FEND 대응 메뉴: 대응 기법 매트릭스(전술 × 기법 트리, 매핑 수/지정 수), 대응방책 연계(룰·경보 노드별 ATT&CK·지정, 사고 대응 지정 없는 곳 거르기, 권고 보기), 버전 관리. 경보 상세의 "대응방책" 카드, ATT&CK 기법 상세의 "D3FEND 대응 기법" |

경보의 "대응 절차"(playbook)는 사람이 쓴 글로 그대로 두고, D3FEND 는 그 옆에 구조화된 대응 기법으로 붙는다.
ATT&CK 과 같이 탐지 판정을 바꾸지 않는 메타데이터라 생성 코드·GENERATOR 버전은 그대로다.
기본 룰 9개와 SC_PHP2SHELL 경보 노드 5개에 지정 대응방책을 달았다(이미 설치된 환경은 기본 룰을 덮어쓰지 않으므로 화면에서 추가한다).
테스트는 공식 1.5.0·1.6.0 에서 잘라 낸 릴리스(`src/test/resources/d3fend`, `scripts/make_d3fend_fixture.py`)를 쓴다.
