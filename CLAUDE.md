# 프로젝트: ClickHouse 기반 시나리오 탐지 서버 (Java + 시나리오별 Python)

원본은 scenario-alert-engine-python 이다. 설계 기준은 docs/design.md, Java 버전 구조는 docs/architecture.md 이다.
설계와 다르게 구현해야 하면 먼저 이유를 설명하고 확인을 받는다.

## 언어 경계 (요청 사항)
- 시나리오(순서도) 평가만 Python 이다. 순서도를 저장할 때마다 Java(ScenarioCodeGenerator)가 그 버전 전용 Python 모듈을 생성한다.
- 그 밖의 모든 것(API, 단일룰 검증·SQL 변환·실행, 스케줄러, 경보, 전달, 백테스트, 모의 사고처리 시스템)은 Java 다.
- 노드 연산의 의미는 python/scenario_runtime/runtime.py 한 곳에만 둔다. 생성 코드는 순서도 모양만 담는다.
  새 시나리오가 코드 수정을 요구하면 그 시나리오가 아니라 일반 기능(노드 유형·연산)으로 런타임과 생성기에 함께 추가하고 GENERATOR 버전을 올린다.
- 생성 코드의 원본은 MariaDB scenario_versions.python_code 다. SCENARIO_CODE_DIR 의 파일은 캐시다.

## 설계 원칙 (원본과 같음)
- 탐지 로직을 코드에 넣지 않는다. 포트 번호, 임계치, 탐지명은 단일룰 정의와 리스트에만 둔다.
- 순서도 평가에서 v_events 를 직접 조회하지 않는다. 집계는 ClickHouse 가 한다. 단일룰 실행은 INSERT ... SELECT 한 문장이다.
- 서버는 메모리 상태를 갖지 않는다. 중간 결과는 rule_hits, 진행 상태는 MariaDB 에 둔다.
- 생성된 evaluate(hits, asset_tags) 는 입출력만 있는 순수 함수다. 실시간, 백테스트, 화면 시뮬레이션이 같은 생성 코드를 쓴다.
- 모든 히트와 경보는 org_id + entity 단위다.

## 코드 생성 규칙
- GraphValidator 를 통과한 그래프만 생성한다. 사용자 문자열은 ScenarioCodeGenerator.py() 로 이스케이프한 리터럴로만 넣는다.
  주석에는 검증된 노드 ID 와 노드 유형만 쓴다.
- Python 은 -I(격리 모드)로 띄우고, worker 는 sha256 이 다른 파일을 실행하지 않는다.

## SQL 생성 규칙 (원본과 같음)
- 사용자가 입력한 문자열을 SQL 에 직접 잇지 않는다. 필드명은 허용 목록(meta/Fields), 값은 서버 측 파라미터 {pN:Type}.
- 컴파일러 출력은 src/test/resources/snapshots 로 고정한다 (Python 원본 스냅샷과 같아야 한다).
- 모든 탐지 쿼리는 mgr_time 범위와 data_tp 조건을 먼저 건다. 건수는 sum(event_count).

## 코드 규칙
- Java 21, Spring Boot 3.3. 시간에 의존하는 코드는 AppClock 을 주입받는다. 시각은 KST LocalDateTime.
- MariaDB 변경은 Flyway(src/main/resources/db/migration)로만, ClickHouse 변경은 clickhouse/ 아래 번호 붙은 SQL 파일로만 한다.
- Python 런타임은 표준 라이브러리만 쓴다 (폐쇄망).
- 실제 기관명, 담당자명, 실제 IP 를 코드, 테스트, 문서에 넣지 않는다. 접속 정보는 환경 변수로만 받는다.

## 명령
- Java 단위 테스트: mvn test
- 전체 (Python + Java 단위 + 통합): docker compose up -d mariadb clickhouse && docker compose --profile test run --rm --no-deps --build tester
- 실행: docker compose up -d --build  (관리 화면 :8080, API :8000, 모의 사고처리 :8090)
- 데이터 초기화: docker compose run --rm -e APP_MODE=reset-data init
