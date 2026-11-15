# 시나리오 기반 탐지 엔진 (Java + 시나리오별 Python)

[scenario-alert-engine-python](https://github.com/KOSUKJUN/scenario-alert-engine-python) 을 Java(Spring Boot)로 옮긴 버전입니다.
설계 기준은 같은 [docs/design.md](docs/design.md) 이고, 바뀐 구조는 [docs/architecture.md](docs/architecture.md) 에 있습니다.

| 부분 | 언어 | 설명 |
|---|---|---|
| API·인증·설정·경보·전달·백테스트·스케줄러 | **Java 21 / Spring Boot 3.3** | Python 원본의 FastAPI 서버를 그대로 옮김 (API 경로·응답 형식 동일) |
| **단일룰 탐지** (정의 검증 → ClickHouse SQL 변환 → 실행) | **Java** | 컴파일 결과가 Python 원본 스냅샷과 글자 하나까지 같다 (테스트로 고정) |
| **시나리오(순서도) 탐지** | **Python (시나리오마다 생성)** | 순서도를 저장하면 Java 가 그 버전 전용 Python 모듈을 생성하고, 평가는 그 코드가 한다 |
| 관리 화면 | Vue 3 (원본 그대로) | 버전 탭에 "Python 코드" 보기만 추가 |
| 저장소 | ClickHouse 24.8, MariaDB 10.11 | 스키마 동일 (+ `scenario_versions.python_code`) |

```
순서도 저장 ──▶ Java: 그래프 검증 ──▶ Java: Python 코드 생성 ──▶ MariaDB(scenario_versions.python_code) + data/scenarios/SC_X/vN.py
                                                                         │
실시간(스케줄러)·백테스트·화면 시뮬레이션 ──▶ Java: 히트 조회(ClickHouse) ──▶ Python 상주 프로세스가 SC_X/vN.py 실행 ──▶ Java: 경보 억제·상향·전달
```

## 1. 필요한 것

- **Docker Desktop** (필수. 테스트 환경 전체가 compose 로 뜬다. Python 도 컨테이너 안에 있다)
- 로컬에서 Java 단위 테스트를 돌릴 때만: JDK 21, Maven 3.9 이상

## 2. 테스트 환경 띄우기

```bash
docker compose up -d --build
```

처음에는 이미지 빌드로 몇 분 걸립니다. `init` 서비스가 다음을 하고 끝납니다.

1. MariaDB 마이그레이션(Flyway), ClickHouse 테이블·딕셔너리·뷰 생성
2. 기준 데이터(테스트 기관 3곳, 자산, 리스트, 사용자)와 기본 룰 14개·순서도 7개(운영 상태)
   — **순서도 7개마다 Python 평가 코드가 생성된다** (`./data/scenarios/` 에서 바로 볼 수 있다)
3. 최근 2시간 샘플 이벤트

| 화면 | 주소 |
|---|---|
| 관리 화면 | http://localhost:8080 |
| API 문서 (Swagger) | http://localhost:8000/api/v1/docs |
| 상태 점검 (MariaDB·ClickHouse·Python) | http://localhost:8000/api/v1/health |
| 모의 사고처리 시스템 (경보 수신함) | http://localhost:8090 |

개발용 계정 (로그인 화면에서 이름을 누르면 채워진다)

| 아이디 | 비밀번호 | 역할 |
|---|---|---|
| admin | admin123 | 관리자 (운영 전환, 사용자·기관 관리) |
| author | author123 | 작성자 (룰·순서도·리스트 작성, 백테스트) |
| analyst | analyst123 | 분석가 (경보 조회·판정) |
| viewer | viewer123 | 조회자 |

포트가 겹치면 `.env.example` 을 `.env` 로 복사해 `WEB_HOST_PORT` 등을 바꿉니다.

### 써 보기

1. **테스트 데이터** 메뉴에서 시나리오(예: `smb_worm_legacy`)를 **주입** → 1~2분 뒤 **경보** 메뉴에 경보가 생긴다
2. 경보 상세: 순서도 경로 강조, 노드별 근거 이벤트, 판정 등록, 예외 리스트 추가
3. http://localhost:8090 에서 같은 경보가 사건으로 접수됐는지 확인, 종결하면 판정이 탐지 서버로 돌아온다
4. **순서도 → SC_SMB_WORM → 시뮬레이션** (ORG001 / 10.10.1.50)
5. **시나리오 추가 → Python 코드 생성 확인**
   - 순서도 편집기에서 새 순서도를 만들어 저장 → **버전** 탭 → **Python 코드** 버튼
   - 또는 호스트의 `./data/scenarios/<순서도ID>/v1.py` 를 연다. 고쳐서 저장하면 `v2.py` 가 새로 생긴다
   - API: `GET /api/v1/scenarios/{id}/code?version=N`, 저장 전 미리보기 `POST /api/v1/scenarios/codegen`
6. **사고 사례 대입** ([docs/cases.md](docs/cases.md)): 관제 보고서 사례 12건을 단일룰 7개·순서도 6개로 옮겼다.
   **테스트 데이터** 메뉴의 `[사례] …` 항목을 주입하면 각 사례의 경보가 난다 (예: `wannacry_device`, `exposed_admin_port_success`).
   기관 단위 집계(대상 유형 `org`)는 `ti_contact_*`·`wannacry_spread` 등 445 접근 항목을 3개 이상 주입하면 `SC_ORG_OUTBREAK` 경보(대상 `ORG001`)가 난다.

데이터 초기화 (이벤트·히트·경보만 지우고 룰은 유지):

```bash
docker compose run --rm -e APP_MODE=reset-data init
```

전부 지우고 처음부터: `docker compose down -v` 후 `docker compose up -d --build`

## 3. 테스트

| 종류 | 명령 | 비고 |
|---|---|---|
| Java 단위 (DB·Python 불필요) | `mvn test` | 컴파일러 스냅샷(Python 원본과 비교), 단일룰 검증 21종·SQL 주입 13종, 그래프 검증 17종, 코드 생성. Python 이 없으면 생성 코드 실행 테스트는 건너뛴다 |
| **전체** (Python 런타임 + Java 단위 + 통합) | `docker compose up -d mariadb clickhouse` 후 `docker compose --profile test run --rm --no-deps --build tester` | 약 3~5분. **개발 DB 를 초기화한다.** 보고서는 `./test-reports/` |
| 전체 테스트 한 번에 (Windows) | `scripts\test.ps1` | 위 두 줄 + 끝난 뒤 개발 환경 다시 채우기 |

통합 테스트가 확인하는 것 (원본의 M3~M5 수용 기준):

- 기본 순서도 7개 × 합성 이벤트: 기대 경보가 정확히 1건씩, 반례(임계치 바로 아래·허용 시간 밖·예외 리스트)는 경보 없음, 정상 트래픽에서 경보 0건
- 서버 1대로 50분 평가 → "중단" → 서버 2대 동시 따라잡기: 같은 구간 중복 실행 없음, 중복 경보 없음, 빈틈 없음
- 백테스트와 실시간 경보 일치 (둘 다 같은 생성 코드를 실행)
- 순서도 저장 → 버전별 Python 코드 생성, 시뮬레이션이 생성 코드로 동작, API 권한

## 4. 디렉터리

```
src/main/java/com/scenarioalert/engine/
  singlerule/     단일룰 검증(RuleValidator), SQL 변환(RuleCompiler), 실행(RuleRunner)      ← Java 탐지
  scenario/       그래프 검증(GraphValidator), Python 코드 생성(ScenarioCodeGenerator),
                  생성 코드 실행 프로세스 풀(PythonScenarioEngine), 코드 파일 캐시(ScenarioCodeStore)
  detection/      스케줄러(SKIP LOCKED, 따라잡기), 후처리(새 히트 → 단독 경보 / 순서도 평가)
  alerting/       경보 생성·상향·억제(GET_LOCK), 사고처리 webhook 전달·재시도
  backtest/ lifecycle/ api/ auth/ repo/ ch/ sample/ meta/ common/ config/
src/main/resources/db/migration/   MariaDB 스키마 (Flyway)
python/scenario_runtime/           시나리오 평가 런타임(runtime.py)과 상주 프로세스(worker.py)  ← Python
python/tests/                      Python 런타임 테스트 (unittest)
data/scenarios/                    생성된 시나리오별 Python 코드 (서버가 씀, 캐시)
clickhouse/ mariadb/ rules/builtin/  원본과 동일 (SQL, 초기 계정, 기본 룰 14개·순서도 7개)
web/                               관리 화면 (Vue, 원본 + 코드 보기)
mockcase/                          모의 사고처리 시스템 (Java 단일 파일)
testdata/scenarios/                순서도별 합성 이벤트·기대 경보 (원본과 동일)
src/test/                          Java 단위 테스트, it/ 통합 테스트
```
