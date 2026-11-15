# 사고처리 시스템 모의 서버 (테스트용). 의존성 없는 단일 파일 Java.
FROM eclipse-temurin:21-jdk-noble AS build
WORKDIR /src
COPY MockCase.java .
RUN javac -encoding UTF-8 -d /out MockCase.java

FROM eclipse-temurin:21-jre-noble
ENV TZ=Asia/Seoul
WORKDIR /app
COPY --from=build /out /app
EXPOSE 8090
USER 10001
CMD ["java", "-cp", "/app", "MockCase"]
