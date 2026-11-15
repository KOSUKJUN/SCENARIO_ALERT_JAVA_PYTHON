package com.scenarioalert.engine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 환경 설정 (application.yml ← 환경 변수). 접속 정보는 환경 변수로만 받는다.
 *
 * @param mode           server(API+스케줄러) | worker(스케줄러만) | init(마이그레이션·기준 데이터 후 종료) | api(API만)
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(
        String mode,
        String instanceId,
        boolean runScheduler,
        boolean enableDevTools,
        double schedulerTickSec,
        int maxConcurrentRules,
        int evalDelaySec,
        int catchupMaxHours,
        int catchupStepsPerClaim,
        int sessionHours,
        String publicBaseUrl,
        String rootDir,
        ClickHouse clickhouse,
        Case caseSystem,
        Python python,
        Init init) {

    public record ClickHouse(String url, String user, String password, String btUser, String btPassword,
                             String adminUser, String adminPassword) {
    }

    public record Case(String webhookUrl, String serviceToken) {
    }

    /**
     * 시나리오 평가용 Python.
     *
     * @param executable    python 실행 파일
     * @param runtimeDir    scenario_runtime 패키지가 있는 디렉터리 (python/)
     * @param codeDir       시나리오별로 생성된 Python 코드를 두는 디렉터리
     * @param workers       상주 Python 평가 프로세스 수
     * @param timeoutSec    요청 한 건의 응답 제한 시간
     */
    public record Python(String executable, String runtimeDir, String codeDir, int workers, int timeoutSec) {
    }

    public record Init(boolean seedSample, double sampleHours, String builtinStatus) {
    }
}
