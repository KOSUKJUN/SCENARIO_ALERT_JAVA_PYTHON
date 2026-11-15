#!/bin/sh
# 컨테이너(tester) 안에서 전체 테스트: Python 런타임 → Java 단위(생성 코드 실행 포함) → 통합(실제 ClickHouse·MariaDB).
# 사용: docker compose --profile test run --rm --no-deps tester
#       docker compose --profile test run --rm --no-deps tester sh scripts/run-tests.sh unit   (DB 없이 단위만)
set -e
cd /app
STAGE="${1:-all}"

echo "== [1/3] Python 런타임 테스트 (python3 $(python3 -c 'import sys;print(sys.version.split()[0])'))"
python3 -I -m unittest discover -s /app/python/tests -t /app/python -v

echo "== [2/3] Java 단위 테스트 (컴파일러 스냅샷, 검증, 코드 생성, 생성 코드 실행)"
mvn -B -q test || { mkdir -p test-reports && cp -r target/surefire-reports test-reports/unit 2>/dev/null; exit 1; }

if [ "$STAGE" = "unit" ]; then
  exit 0
fi

echo "== [3/3] 통합 테스트 (기본 순서도 7개 수용 기준, 서버 2대, 따라잡기, 백테스트 일치, API) — 개발 DB 를 초기화합니다"
rc=0
mvn -B test -Pintegration || rc=$?
mkdir -p test-reports && rm -rf test-reports/integration && cp -r target/surefire-reports test-reports/integration 2>/dev/null || true
exit $rc
