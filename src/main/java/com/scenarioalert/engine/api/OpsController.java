package com.scenarioalert.engine.api;

import com.scenarioalert.engine.InitService;
import com.scenarioalert.engine.auth.AuthService;
import com.scenarioalert.engine.auth.AuthService.User;
import com.scenarioalert.engine.auth.RequireRole;
import com.scenarioalert.engine.backtest.BacktestService;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.ch.ClickHouse.Purpose;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.config.AppProperties;
import com.scenarioalert.engine.sample.SampleDataService;
import com.scenarioalert.engine.scenario.PythonScenarioEngine;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.scenarioalert.engine.common.Db.p;

/** 로그인, 백테스트, 현황 지표, 상태 점검, Prometheus, 개발용 샘플 데이터. */
@RestController
@RequestMapping("/api/v1")
public class OpsController {
    private final Db db;
    private final AuthService auth;
    private final BacktestService backtests;
    private final ClickHouse ch;
    private final AppProperties props;
    private final PythonScenarioEngine engine;
    private final SampleDataService samples;
    private final ObjectProvider<PrometheusMeterRegistry> prometheus;

    public OpsController(Db db, AuthService auth, BacktestService backtests, ClickHouse ch, AppProperties props,
                         PythonScenarioEngine engine, SampleDataService samples,
                         ObjectProvider<PrometheusMeterRegistry> prometheus) {
        this.db = db;
        this.auth = auth;
        this.backtests = backtests;
        this.ch = ch;
        this.props = props;
        this.engine = engine;
        this.samples = samples;
        this.prometheus = prometheus;
    }

    // ---------------------------------------------------------------- 인증
    @PostMapping("/auth/login")
    @RequireRole("none")
    public Map<String, Object> login(@RequestBody Map<String, Object> body) {
        return db.tx(() -> auth.login(Body.str(body, "username"), Body.str(body, "password")));
    }

    @PostMapping("/auth/logout")
    @RequireRole("any")
    public Map<String, Object> logout(User user) {
        db.execute("DELETE FROM sessions WHERE username=:u AND expires_at < NOW()", p("u", user.username()));
        return Map.of("ok", true);
    }

    @GetMapping("/auth/me")
    @RequireRole("any")
    public Map<String, Object> me(User user) {
        return Json.obj("username", user.username(), "role", user.role(), "dev_tools", props.enableDevTools(),
                "ui", uiSettings());
    }

    // ---------------------------------------------------------------- 화면 설정 (표시 옵션만)
    private static final List<String> UI_BOOL_KEYS = List.of("show_incident");

    private Map<String, Object> uiSettings() {
        Map<String, Object> out = new LinkedHashMap<>();
        UI_BOOL_KEYS.forEach(k -> out.put(k, false));
        for (Map<String, Object> r : db.rows("SELECT setting_key, setting_value FROM ui_settings")) {
            String k = Db.str(r, "setting_key");
            if (UI_BOOL_KEYS.contains(k)) {
                out.put(k, "true".equals(Db.str(r, "setting_value")));
            }
        }
        return out;
    }

    @GetMapping("/ui-settings")
    @RequireRole("any")
    public Map<String, Object> getUiSettings() {
        return uiSettings();
    }

    @PutMapping("/ui-settings")
    @RequireRole("admin")
    public Map<String, Object> putUiSettings(@RequestBody Map<String, Object> body, User user) {
        db.txRun(() -> {
            for (Map.Entry<String, Object> e : body.entrySet()) {
                if (!UI_BOOL_KEYS.contains(e.getKey())) {
                    throw ApiException.badRequest("알 수 없는 화면 설정: " + e.getKey());
                }
                if (!(e.getValue() instanceof Boolean b)) {
                    throw ApiException.badRequest("화면 설정 값은 true/false 여야 합니다: " + e.getKey());
                }
                db.execute("INSERT INTO ui_settings (setting_key, setting_value, updated_by) VALUES (:k, :v, :u) "
                        + "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value), updated_by=VALUES(updated_by)",
                        p("k", e.getKey(), "v", b.toString(), "u", user.username()));
            }
            db.audit(user.username(), "ui_settings.update", "ui_settings", body);
        });
        return uiSettings();
    }

    // ---------------------------------------------------------------- 백테스트
    @PostMapping("/backtests")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @RequireRole("author")
    public Map<String, Object> startBacktest(@RequestBody Map<String, Object> body, User user) {
        LocalDateTime tf = Kst.parse(Body.str(body, "time_from"));
        LocalDateTime tt = Kst.parse(Body.str(body, "time_to"));
        String jobId = backtests.createJob(Body.str(body, "target_type"), Body.str(body, "target_id"),
                Body.optMap(body, "definition"), Body.strings(body, "org_ids"), tf, tt, user.username());
        return Json.obj("job_id", jobId, "status", "queued");
    }

    @GetMapping("/backtests")
    @RequireRole("author")
    public List<Map<String, Object>> listBacktests(@RequestParam(name = "target_id", required = false) String targetId) {
        return db.rows("SELECT job_id, target_type, target_id, time_from, time_to, status, created_by, created_at, finished_at, "
                + "error FROM backtest_jobs" + (targetId != null ? " WHERE target_id=:t" : "")
                + " ORDER BY created_at DESC LIMIT 100", p("t", targetId));
    }

    @GetMapping("/backtests/{jobId}")
    @RequireRole("author")
    public Map<String, Object> getBacktest(@PathVariable String jobId) {
        Map<String, Object> j = db.row("SELECT * FROM backtest_jobs WHERE job_id=:id", p("id", jobId));
        if (j == null) {
            throw new ApiException(404, "백테스트가 없습니다");
        }
        for (String k : List.of("definition", "org_ids", "result")) {
            j.put(k, j.get(k) == null ? null : Json.load(Db.str(j, k)));
        }
        return j;
    }

    // ---------------------------------------------------------------- 현황
    /** 룰·순서도별 경보 수, 정탐률, 실행 시간, 실패. 정탐률이 20% 아래면 조정 필요 표시 (자동 비활성화 안 함). */
    @GetMapping("/metrics/rules")
    @RequireRole("viewer")
    public Map<String, Object> ruleMetrics(@RequestParam(defaultValue = "30") int days) {
        return db.tx(() -> {
            Map<String, Object> d = p("d", days);
            Map<String, Map<String, Object>> am = new HashMap<>();
            db.rows("SELECT source_type, source_id, COUNT(*) AS alerts, SUM(verdict='true_positive') AS tp, "
                    + "SUM(verdict='false_positive') AS fp, SUM(verdict='benign') AS benign, SUM(verdict IS NOT NULL) AS judged, "
                    + "SUM(delivery_status='failed') AS delivery_failed FROM alerts WHERE created_at >= NOW() - INTERVAL :d DAY "
                    + "GROUP BY source_type, source_id", d).forEach(a -> am.put(a.get("source_type") + "\u0000" + a.get("source_id"), a));
            Map<String, Map<String, Object>> runs = new HashMap<>();
            db.rows("SELECT rule_id, COUNT(*) AS runs, AVG(duration_ms) AS avg_ms, MAX(duration_ms) AS max_ms, "
                    + "SUM(status!='ok') AS failed, SUM(hit_count) AS hits FROM rule_runs WHERE started_at >= NOW() - INTERVAL 1 DAY "
                    + "GROUP BY rule_id").forEach(r -> runs.put(Db.str(r, "rule_id"), r));
            List<Map<String, Object>> rules = db.rows("SELECT rule_id, name, status, last_evaluated_to, consecutive_failures "
                    + "FROM single_rules");
            List<Map<String, Object>> scs = db.rows("SELECT scenario_id, name, status FROM scenarios");
            List<Map<String, Object>> fpKeys = db.rows("SELECT source_id, entity, COUNT(*) AS n FROM alerts WHERE "
                    + "verdict='false_positive' AND created_at >= NOW() - INTERVAL :d DAY GROUP BY source_id, entity "
                    + "ORDER BY n DESC LIMIT 200", d);
            List<Map<String, Object>> failedRuns = db.rows("SELECT rule_id, win_to, status, error, started_at FROM rule_runs "
                    + "WHERE status != 'ok' ORDER BY started_at DESC LIMIT 50");
            List<Map<String, Object>> undelivered = db.rows("SELECT alert_id, source_id, org_id, entity, severity, "
                    + "delivery_attempts, delivery_error, created_at FROM alerts WHERE delivery_status='failed' "
                    + "ORDER BY created_at DESC LIMIT 50");
            LocalDateTime now = Kst.now();

            java.util.function.BiFunction<String, String, Map<String, Object>> stat = (st, sid) -> {
                Map<String, Object> a = am.getOrDefault(st + "\u0000" + sid, Map.of());
                long judged = Db.lng(a, "judged");
                long tp = Db.lng(a, "tp");
                Double rate = judged > 0 ? (double) tp / judged : null;
                return Json.obj("alerts", Db.lng(a, "alerts"), "true_positive", tp, "false_positive", Db.lng(a, "fp"),
                        "benign", Db.lng(a, "benign"), "judged", judged, "tp_rate", rate,
                        "needs_tuning", rate != null && rate < 0.2, "delivery_failed", Db.lng(a, "delivery_failed"),
                        "top_fp_entities", fpKeys.stream().filter(k -> sid.equals(k.get("source_id"))).limit(5)
                                .map(k -> Json.obj("entity", k.get("entity"), "count", Db.lng(k, "n"))).toList());
            };
            List<Map<String, Object>> outRules = new ArrayList<>();
            for (Map<String, Object> r : rules) {
                Map<String, Object> rr = runs.getOrDefault(Db.str(r, "rule_id"), Map.of());
                LocalDateTime le = Db.time(r, "last_evaluated_to");
                Map<String, Object> m = Json.obj("rule_id", r.get("rule_id"), "name", r.get("name"), "status", r.get("status"),
                        "runs_24h", Db.lng(rr, "runs"), "avg_run_ms", Db.dbl(rr, "avg_ms"), "max_run_ms", Db.lng(rr, "max_ms"),
                        "failed_runs_24h", Db.lng(rr, "failed"), "hits_24h", Db.lng(rr, "hits"),
                        "eval_lag_sec", le == null ? null : (double) Duration.between(le, now).toMillis() / 1000.0,
                        "consecutive_failures", Db.lng(r, "consecutive_failures"),
                        "warning", Db.lng(r, "consecutive_failures") >= 3);
                m.putAll(stat.apply("single_rule", Db.str(r, "rule_id")));
                outRules.add(m);
            }
            List<Map<String, Object>> outSc = new ArrayList<>();
            for (Map<String, Object> s : scs) {
                Map<String, Object> m = Json.obj("scenario_id", s.get("scenario_id"), "name", s.get("name"), "status", s.get("status"));
                m.putAll(stat.apply("scenario", Db.str(s, "scenario_id")));
                outSc.add(m);
            }
            return Json.obj("days", days, "rules", outRules, "scenarios", outSc, "failed_runs", failedRuns,
                    "undelivered_alerts", undelivered);
        });
    }

    @GetMapping("/health")
    @RequireRole("none")
    public Map<String, Object> health() {
        Map<String, Object> st = new LinkedHashMap<>();
        st.put("instance", props.instanceId());
        try {
            db.row("SELECT 1 AS x", Map.of());
            st.put("mariadb", "ok");
        } catch (RuntimeException e) {
            st.put("mariadb", "error: " + e.getMessage());
        }
        try {
            ch.query("SELECT 1 AS x", Map.of());
            st.put("clickhouse", "ok");
        } catch (RuntimeException e) {
            st.put("clickhouse", "error: " + e.getMessage());
        }
        try {
            Map<String, Object> pong = engine.ping();
            st.put("python", "ok (" + pong.get("python") + ")");
        } catch (RuntimeException e) {
            st.put("python", "error: " + e.getMessage());
        }
        boolean ok = st.values().stream().skip(1).allMatch(v -> String.valueOf(v).startsWith("ok"));
        st.put("status", ok ? "ok" : "degraded");
        return st;
    }

    @GetMapping(value = "/metrics", produces = MediaType.TEXT_PLAIN_VALUE)
    @RequireRole("none")
    public ResponseEntity<String> prometheus() {
        PrometheusMeterRegistry reg = prometheus.getIfAvailable();
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("text/plain; version=0.0.4; charset=utf-8"))
                .body(reg == null ? "" : reg.scrape());
    }

    /** 유형별 필드 채움 비율 (clickhouse/queries/fill_ratio.sql). */
    @GetMapping("/fill-ratio")
    @RequireRole("viewer")
    public List<Map<String, Object>> fillRatio() throws IOException {
        Path f = Path.of(props.rootDir(), "clickhouse", "queries", "fill_ratio.sql");
        String sql = Files.readAllLines(f, StandardCharsets.UTF_8).stream().filter(l -> !l.strip().startsWith("--"))
                .collect(Collectors.joining("\n")).strip();
        if (sql.endsWith(";")) {
            sql = sql.substring(0, sql.length() - 1);
        }
        return ch.query(sql, Map.of());
    }

    // ---------------------------------------------------------------- 개발용 샘플 데이터
    private void devEnabled() {
        if (!props.enableDevTools()) {
            throw new ApiException(404, "개발 도구가 꺼져 있습니다 (ENABLE_DEV_TOOLS)");
        }
    }

    @GetMapping("/dev/sample-data")
    @RequireRole("viewer")
    public Map<String, Object> sampleCatalog() {
        devEnabled();
        List<Map<String, Object>> rs = ch.query("SELECT _data_type AS data_tp, count() AS rows, min(_collect_time) AS first, "
                + "max(_collect_time) AS last FROM " + InitService.SOURCE + " WHERE _collect_time >= now() - INTERVAL 30 DAY "
                + "GROUP BY data_tp ORDER BY data_tp", Map.of(), Purpose.ADMIN);
        rs.forEach(r -> {
            r.put("first", ClickHouse.time(r, "first"));
            r.put("last", ClickHouse.time(r, "last"));
        });
        return Json.obj("scenarios", SampleDataService.catalog(), "event_counts", rs);
    }

    /** 지금 시각으로 공격 패턴 이벤트를 넣는다. 1~2분 안에 히트·경보가 생긴다. */
    @PostMapping("/dev/sample-data/inject")
    @RequireRole("author")
    public Map<String, Object> sampleInject(@RequestBody Map<String, Object> body, User user) {
        devEnabled();
        String scenario = body.getOrDefault("scenario", "all").toString();
        String org = body.getOrDefault("org_id", "ORG001").toString();
        Map<String, Object> res = samples.injectNow(scenario, org, Kst.now());
        db.audit(user.username(), "dev.inject", scenario, res);
        return res;
    }

    /** 최근 N분 정상 트래픽을 넣는다 (오탐 확인용). */
    @PostMapping("/dev/sample-data/background")
    @RequireRole("author")
    public Map<String, Object> sampleBackground(@RequestParam(defaultValue = "5") int minutes) {
        devEnabled();
        LocalDateTime now = Kst.now();
        int n = samples.insertBackground(now.minusMinutes(Math.min(Math.max(minutes, 1), 240)), now, null);
        return Map.of("inserted", n);
    }
}
