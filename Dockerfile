# 탐지 서버 이미지: Java(Spring Boot) + 시나리오 평가용 Python 3 런타임.
#   build   : Maven 으로 jar 빌드
#   runtime : JRE + python3 (시나리오별 생성 코드를 실행하는 상주 프로세스용)
#   tester  : Maven + python3 (단위·Python·통합 테스트를 컨테이너 안에서 실행)

FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM maven:3.9.9-eclipse-temurin-21 AS tester
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pom.xml .
RUN mvn -B -q dependency:go-offline && mvn -B -q dependency:resolve-plugins \
    && mvn -B -q org.apache.maven.plugins:maven-surefire-plugin:3.2.5:help >/dev/null 2>&1 || true
ENV TZ=Asia/Seoul PYTHON_EXECUTABLE=python3
CMD ["sh", "scripts/run-tests.sh"]

FROM eclipse-temurin:21-jre-noble AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -d /app app
ENV TZ=Asia/Seoul \
    APP_ROOT_DIR=/app \
    PYTHON_EXECUTABLE=python3 \
    PYTHON_RUNTIME_DIR=/app/python \
    SCENARIO_CODE_DIR=/app/data/scenarios
WORKDIR /app
COPY --from=build /src/target/scenario-alert-engine.jar /app/app.jar
COPY python ./python
COPY clickhouse ./clickhouse
COPY rules ./rules
RUN mkdir -p /app/data/scenarios /app/data/attack /app/data/d3fend && chown -R app /app/data
USER app
EXPOSE 8000
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-Dfile.encoding=UTF-8", "-jar", "/app/app.jar"]
