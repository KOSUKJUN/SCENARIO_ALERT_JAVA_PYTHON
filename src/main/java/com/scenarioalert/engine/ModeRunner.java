package com.scenarioalert.engine;

import com.scenarioalert.engine.alerting.AlertService;
import com.scenarioalert.engine.backtest.BacktestService;
import com.scenarioalert.engine.common.AppClock;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.config.AppProperties;
import com.scenarioalert.engine.detection.DetectionService;
import com.scenarioalert.engine.detection.Scheduler;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.singlerule.RuleRunner;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;

/** APP_MODE 에 따라 스케줄러를 띄우거나 초기화 작업을 하고 끝낸다. */
@Component
public class ModeRunner implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(ModeRunner.class);

    private final AppProperties props;
    private final InitService init;
    private final Db db;
    private final Repo repo;
    private final RuleRunner runner;
    private final DetectionService detection;
    private final AlertService alerts;
    private final BacktestService backtests;
    private final MeterRegistry meters;
    private final ConfigurableApplicationContext ctx;
    private final com.scenarioalert.engine.scenario.ScenarioCodeStore codeStore;
    private Scheduler scheduler;
    private volatile boolean stop;

    public ModeRunner(AppProperties props, InitService init, Db db, Repo repo, RuleRunner runner, DetectionService detection,
                      AlertService alerts, BacktestService backtests, MeterRegistry meters, ConfigurableApplicationContext ctx,
                      com.scenarioalert.engine.scenario.ScenarioCodeStore codeStore) {
        this.codeStore = codeStore;
        this.props = props;
        this.init = init;
        this.db = db;
        this.repo = repo;
        this.runner = runner;
        this.detection = detection;
        this.alerts = alerts;
        this.backtests = backtests;
        this.meters = meters;
        this.ctx = ctx;
    }

    /** 테스트에서 고정 시계로 스케줄러를 만든다. */
    public Scheduler newScheduler(AppClock clock, String instanceId) {
        return new Scheduler(clock, props, db, repo, runner, detection, alerts, meters, instanceId);
    }

    @Override
    public void run(ApplicationArguments args) {
        String mode = props.mode();
        switch (mode) {
            case "init" -> exitAfter(init::init);
            case "reset-data" -> exitAfter(init::resetData);
            case "load-sample" -> exitAfter(() -> init.loadSample(props.init().sampleHours()));
            case "worker" -> startScheduler(true);
            case "server" -> {
                if (props.runScheduler()) {
                    startScheduler(false);
                }
            }
            default -> log.info("mode {}: no background work", mode);
        }
    }

    private void exitAfter(Runnable r) {
        int code = 0;
        try {
            r.run();
        } catch (RuntimeException e) {
            log.error("{} failed", props.mode(), e);
            code = 1;
        }
        int fc = code;
        System.exit(SpringApplication.exit(ctx, () -> fc));
    }

    /** 현재 버전 순서도의 생성 코드를 파일로 꺼내 둔다 (원본은 DB. 파일은 평가 때도 없으면 다시 만든다). */
    private void materializeScenarioCode() {
        try {
            repo.listScenarios().forEach(s -> codeStore.ensure(s.program()));
            log.info("scenario code materialized under {}", codeStore.root());
        } catch (RuntimeException e) {
            log.warn("scenario code materialize failed: {}", e.getMessage());
        }
    }

    private void startScheduler(boolean blocking) {
        init.waitReady(120);
        materializeScenarioCode();
        scheduler = newScheduler(AppClock.SYSTEM, props.instanceId());
        Thread bt = new Thread(this::backtestLoop, "backtest");
        bt.setDaemon(true);
        bt.start();
        if (blocking) {
            scheduler.runForever();
        } else {
            Thread t = new Thread(scheduler::runForever, "scheduler");
            t.setDaemon(true);
            t.start();
        }
    }

    private void backtestLoop() {
        while (!stop) {
            try {
                if (!backtests.runQueued(AppClock.SYSTEM)) {
                    Thread.sleep(3000);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (RuntimeException e) {
                log.error("backtest loop failed", e);
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    @PreDestroy
    public void shutdown() {
        stop = true;
        if (scheduler != null) {
            scheduler.stop();
        }
    }
}
