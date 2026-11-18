package com.scenarioalert.engine.detection;

import com.scenarioalert.engine.alerting.AlertService;
import com.scenarioalert.engine.common.AppClock;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.config.AppProperties;
import com.scenarioalert.engine.repo.Records.RuleRecord;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.singlerule.ParsedRule;
import com.scenarioalert.engine.singlerule.RuleRunner;
import com.scenarioalert.engine.singlerule.RuleValidator;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.PessimisticLockingFailureException;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 주기 실행, 잠금, 따라잡기 (설계안 7장).
 *
 * <ul>
 * <li>평가 구간의 끝(win_to)은 평가 주기 경계에 맞춘다: floor(현재 − 15초, 주기).</li>
 * <li>룰 선택은 SELECT ... FOR UPDATE SKIP LOCKED 로 하고, 고른 룰의 next_run_at 을 임대 시각으로 미뤄 두고 커밋한다.
 * 서버가 여러 대여도 한 룰은 한 서버만 실행한다. 실행 중 서버가 죽으면 임대가 끝난 뒤 다른 서버가 이어서 한다.</li>
 * <li>last_evaluated_to 부터 따라잡는다 (최대 24시간, 한 번에 최대 catchupStepsPerClaim 구간).</li>
 * <li>실패하면 rule_runs 에 실패로 남기고 다음 주기에 같은 구간을 다시 시도한다.</li>
 * </ul>
 * 상태는 모두 MariaDB 에 있다 (서버는 메모리 상태를 갖지 않는다). 시계를 주입받아 테스트에서 고정 시각으로 돌린다.
 */
public class Scheduler {
    private static final Logger log = LoggerFactory.getLogger(Scheduler.class);
    static final int LEASE_SEC = 300;

    private final AppClock clock;
    private final AppProperties s;
    private final Db db;
    private final Repo repo;
    private final RuleRunner runner;
    private final DetectionService detection;
    private final AlertService alerts;
    private final MeterRegistry meters;
    private final ExecutorService pool;
    private final String instanceId;
    private volatile boolean stop;

    public Scheduler(AppClock clock, AppProperties s, Db db, Repo repo, RuleRunner runner, DetectionService detection,
                     AlertService alerts, MeterRegistry meters, String instanceId) {
        this.clock = clock;
        this.s = s;
        this.db = db;
        this.repo = repo;
        this.runner = runner;
        this.detection = detection;
        this.alerts = alerts;
        this.meters = meters;
        this.instanceId = instanceId;
        AtomicInteger n = new AtomicInteger();
        this.pool = Executors.newFixedThreadPool(Math.max(1, s.maxConcurrentRules()), r -> {
            Thread t = new Thread(r, "rule-" + instanceId + "-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
    }

    // ---------------------------------------------------------------- 룰 선택
    /**
     * 실행할 룰을 임대한다. 서버 여러 대가 동시에 임대하면 next_run_at(인덱스 idx_due) 갱신이 교착될 수 있다.
     * 교착 시 MariaDB 가 트랜잭션을 되돌리므로(아무것도 임대되지 않음) 잠깐 쉬고 다시 시도한다.
     */
    public List<String> claimDueRules() {
        for (int attempt = 1; ; attempt++) {
            try {
                return claimOnce();
            } catch (PessimisticLockingFailureException e) {
                if (attempt >= CLAIM_RETRIES) {
                    throw e;
                }
                try {
                    Thread.sleep(20L * attempt + java.util.concurrent.ThreadLocalRandom.current().nextLong(30));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
    }

    static final int CLAIM_RETRIES = 5;

    private List<String> claimOnce() {
        LocalDateTime now = clock.now();
        return db.tx(() -> {
            List<String> ids = db.rows("SELECT rule_id FROM single_rules WHERE status IN ('silent','active') AND "
                            + "(next_run_at IS NULL OR next_run_at <= :now) ORDER BY next_run_at LIMIT :n FOR UPDATE SKIP LOCKED",
                    p("now", now, "n", s.maxConcurrentRules())).stream().map(r -> Db.str(r, "rule_id")).toList();
            if (!ids.isEmpty()) {
                db.execute("UPDATE single_rules SET next_run_at=:lease WHERE rule_id IN (:ids)",
                        p("lease", now.plusSeconds(LEASE_SEC), "ids", ids));
            }
            return ids;
        });
    }

    public List<LocalDateTime> pendingEnds(LocalDateTime lastTo, int schedule, LocalDateTime now) {
        LocalDateTime target = Kst.floor(now.minusSeconds(s.evalDelaySec()), schedule);
        LocalDateTime oldest = target.minusHours(s.catchupMaxHours());
        LocalDateTime start = lastTo != null ? lastTo : target.minusSeconds(schedule);
        start = Kst.floor(start, schedule);
        if (start.isBefore(oldest)) {
            start = oldest;
        }
        List<LocalDateTime> ends = new ArrayList<>();
        LocalDateTime t = start.plusSeconds(schedule);
        while (!t.isAfter(target) && ends.size() < s.catchupStepsPerClaim()) {
            ends.add(t);
            t = t.plusSeconds(schedule);
        }
        return ends;
    }

    // ---------------------------------------------------------------- 룰 처리
    /** 주기가 된 룰 하나를 처리한다. 반환: 처리한 구간 수. */
    public int processRule(String ruleId) {
        RuleRecord rule = db.tx(() -> repo.getRule(ruleId));
        ParsedRule parsed = RuleValidator.parse(rule.definition(), null);
        LocalDateTime now = clock.now();
        List<LocalDateTime> ends = pendingEnds(rule.lastEvaluatedTo(), parsed.scheduleSec(), now);
        int done = 0;
        int failures = rule.consecutiveFailures();
        LocalDateTime lastTo = rule.lastEvaluatedTo();
        for (LocalDateTime end : ends) {
            RuleRunner.RunResult res = runner.runWindow(parsed, rule.version(), end, instanceId);
            meters.timer("rule_run_seconds", "rule", ruleId).record(Duration.ofMillis(res.durationMs()));
            if (!res.ok()) {
                failures++;
                meters.counter("rule_failures_total", "rule", ruleId).increment();
                log.warn("rule {} window {} failed: {}", ruleId, end, res.error());
                break;
            }
            meters.counter("rule_hits_total", "rule", ruleId).increment(res.hitCount());
            try {
                detection.postProcess(rule, parsed, res.newHits(), end);
            } catch (RuntimeException e) {  // 후처리 실패도 같은 구간을 다시 시도
                log.error("post-process failed for {} at {}: {}", ruleId, end, e.toString(), e);
                failures++;
                break;
            }
            failures = 0;
            lastTo = end;
            done++;
        }
        LocalDateTime target = Kst.floor(now.minusSeconds(s.evalDelaySec()), parsed.scheduleSec());
        boolean behind = lastTo == null || lastTo.isBefore(target);
        LocalDateTime nextRun;
        if (behind && done > 0) {
            nextRun = now;  // 따라잡기 계속
        } else if (behind) {
            nextRun = now.plusSeconds(Math.min(parsed.scheduleSec(), 60));  // 실패 후 재시도
        } else {
            nextRun = target.plusSeconds(parsed.scheduleSec() + s.evalDelaySec());
        }
        LocalDateTime fLast = lastTo;
        int fFail = failures;
        db.txRun(() -> db.execute("UPDATE single_rules SET last_evaluated_to=:l, next_run_at=:n, consecutive_failures=:f "
                + "WHERE rule_id=:id", p("l", fLast, "n", nextRun, "f", fFail, "id", ruleId)));
        return done;
    }

    public int tick() {
        List<String> ids = claimDueRules();
        List<Future<Integer>> futures = new ArrayList<>();
        for (String rid : ids) {
            futures.add(pool.submit(() -> safeProcess(rid)));
        }
        int total = 0;
        for (Future<Integer> f : futures) {
            try {
                total += f.get();
            } catch (Exception e) {
                log.error("rule future failed", e);
            }
        }
        try {
            alerts.deliverPending(clock, 20);
        } catch (RuntimeException e) {
            log.error("delivery failed", e);
        }
        return total;
    }

    private int safeProcess(String ruleId) {
        try {
            return processRule(ruleId);
        } catch (RuntimeException e) {
            log.error("rule {} processing error", ruleId, e);
            db.txRun(() -> db.execute("UPDATE single_rules SET consecutive_failures=consecutive_failures+1, next_run_at=:n "
                    + "WHERE rule_id=:id", p("n", clock.now().plusSeconds(60), "id", ruleId)));
            return 0;
        }
    }

    /** 테스트·초기 적재용: 처리할 구간이 없을 때까지 반복. */
    public void runUntilCaughtUp(int maxTicks) {
        for (int i = 0; i < maxTicks; i++) {
            if (tick() == 0 && !anyDue()) {
                break;
            }
        }
    }

    boolean anyDue() {
        Map<String, Object> r = db.row("SELECT COUNT(*) AS n FROM single_rules WHERE status IN ('silent','active') "
                + "AND (next_run_at IS NULL OR next_run_at <= :now)", p("now", clock.now()));
        return r != null && Db.lng(r, "n") > 0;
    }

    // ---------------------------------------------------------------- 루프
    public void runForever() {
        log.info("scheduler started ({})", instanceId);
        while (!stop) {
            long t0 = System.nanoTime();
            try {
                tick();
            } catch (RuntimeException e) {
                log.error("tick failed", e);
            }
            long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
            long wait = Math.max(500, (long) (s.schedulerTickSec() * 1000) - elapsedMs);
            try {
                Thread.sleep(wait);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    public void stop() {
        stop = true;
        pool.shutdownNow();
    }
}
