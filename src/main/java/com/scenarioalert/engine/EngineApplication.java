package com.scenarioalert.engine;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.util.TimeZone;

/**
 * 시나리오 탐지 서버.
 *
 * <pre>
 * APP_MODE=server       API(:8000) + (RUN_SCHEDULER=true 면) 스케줄러·백테스트 작업자
 * APP_MODE=worker       스케줄러만 (API 없는 탐지 서버 2호기 — 무상태 다중 실행 확인용)
 * APP_MODE=init         ClickHouse SQL 적용, 기준 데이터, 기본 룰·순서도(→ Python 코드 생성), 샘플 데이터 후 종료
 * APP_MODE=reset-data   이벤트·히트·경보 초기화 후 종료 (개발 환경 전용)
 * APP_MODE=load-sample  과거 SAMPLE_HOURS 시간 샘플 이벤트 추가 후 종료
 * </pre>
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class EngineApplication {
    public static void main(String[] args) {
        TimeZone.setDefault(TimeZone.getTimeZone("Asia/Seoul"));
        String mode = System.getenv().getOrDefault("APP_MODE", System.getProperty("app.mode", "server"));
        SpringApplication app = new SpringApplication(EngineApplication.class);
        if (!mode.equals("server") && !mode.equals("api")) {
            app.setWebApplicationType(WebApplicationType.NONE);
        }
        app.run(args);
    }
}
