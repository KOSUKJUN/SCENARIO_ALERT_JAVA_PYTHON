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
| 대상 유형 | host (src_ip, dst_ip) | host + **org (org_id)** | 사고 사례 "PC 여러 대 동시 감염"은 기관 단위 집계가 필요하다 ([cases.md](cases.md) 2장) |
| 기본 룰·순서도 | 14 + 7 | 21 + 13 | 사고 사례 12건을 대입해 7 + 6 추가, 1개 수정 ([cases.md](cases.md) 1장) |

미결 사항(운영 데이터 필드 채움 비율, inst_id 대응표, 사고처리 시스템 API 규격, 실제 EPS)은 원본과 같다.
