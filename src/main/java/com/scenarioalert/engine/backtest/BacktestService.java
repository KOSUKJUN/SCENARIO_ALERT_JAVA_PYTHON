package com.scenarioalert.engine.backtest;

import com.scenarioalert.engine.alerting.AlertService;
import com.scenarioalert.engine.alerting.AlertService.Decision;
import com.scenarioalert.engine.alerting.AlertService.ExistingAlert;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.ch.ClickHouse.Purpose;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.AppClock;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.repo.Records.RuleRecord;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.scenario.EvalModels.Chosen;
import com.scenarioalert.engine.scenario.EvalModels.EvalCase;
import com.scenarioalert.engine.scenario.EvalModels.EvalOutcome;
import com.scenarioalert.engine.scenario.EvalModels.Hit;
import com.scenarioalert.engine.scenario.EvalModels.HitKey;
import com.scenarioalert.engine.scenario.EvalModels.ScenarioProgram;
import com.scenarioalert.engine.scenario.GraphValidation;
import com.scenarioalert.engine.scenario.PythonScenarioEngine;
import com.scenarioalert.engine.singlerule.ParsedRule;
import com.scenarioalert.engine.singlerule.RuleCompiler;
import com.scenarioalert.engine.singlerule.RuleRunner;
import com.scenarioalert.engine.singlerule.RuleValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 백테스트 (설계안 11장).
 * <ul>
 * <li>단일룰: 변환된 SQL 을 과거 기간의 모든 창 끝에 대해 한 번에 실행해 rule_hits_backtest 에 쓴다.</li>
 * <li>순서도: 참조 단일룰을 먼저 백테스트한 뒤, 그 히트에 실시간과 같은 시나리오 생성 코드(Python)와 decide 를 적용한다.
 * 실시간처럼 히트가 처음 보였을 시각(first_win_to) 순서로 훑으며 새 히트가 생긴 대상만 평가한다.
 * 평가는 모두 한 번에 Python 으로 보내고(배치), 억제 정책(decide)은 그 결과에 차례로 적용한다.</li>
 * <li>결과: 총 히트·경보 수, 일별 분포, 상위 대상 20개, 임계치 민감도(0.5배·1배·2배), 과거 사고 재현율.</li>
 * <li>백테스트 쿼리는 detect_bt 사용자(낮은 우선순위, 메모리 상한)로 실행한다.</li>
 * </ul>
 */
@Component
public class BacktestService {
    private static final Logger log = LoggerFactory.getLogger(BacktestService.class);
    static final Duration MAX_RANGE = Duration.ofDays(30);
    static final Duration RECALL_MARGIN = Duration.ofHours(24);

    private final Db db;
    private final ClickHouse ch;
    private final Repo repo;
    private final PythonScenarioEngine engine;

    public BacktestService(Db db, ClickHouse ch, Repo repo, PythonScenarioEngine engine) {
        this.db = db;
        this.ch = ch;
        this.repo = repo;
        this.engine = engine;
    }

    public String createJob(String targetType, String targetId, Map<String, Object> definition, List<String> orgIds,
                            LocalDateTime from, LocalDateTime to, String actor) {
        if (!"single_rule".equals(targetType) && !"scenario".equals(targetType)) {
            throw ApiException.badRequest("target_type 은 single_rule 또는 scenario 입니다");
        }
        if (!to.isAfter(from)) {
            throw ApiException.badRequest("기간의 끝이 시작보다 뒤여야 합니다");
        }
        if (Duration.between(from, to).compareTo(MAX_RANGE) > 0) {
            throw ApiException.badRequest("백테스트 기간은 원본 보관 기간인 30일 이하입니다");
        }
        return db.tx(() -> {
            Map<String, Object> defn = definition;
            if (defn == null) {
                defn = "single_rule".equals(targetType) ? repo.getRule(targetId).definition() : repo.getScenario(targetId).graph();
            }
            String jobId = UUID.randomUUID().toString();
            db.execute("INSERT INTO backtest_jobs (job_id, target_type, target_id, definition, org_ids, time_from, time_to, "
                            + "status, created_by) VALUES (:id, :tt, :ti, :d, :o, :f, :t, 'queued', :by)",
                    p("id", jobId, "tt", targetType, "ti", targetId, "d", Json.dump(defn),
                            "o", orgIds == null || orgIds.isEmpty() ? null : Json.dump(orgIds), "f", from, "t", to, "by", actor));
            return jobId;
        });
    }

    public boolean runQueued(AppClock clock) {
        String jobId = db.tx(() -> {
            Map<String, Object> job = db.row("SELECT job_id FROM backtest_jobs WHERE status='queued' ORDER BY created_at "
                    + "LIMIT 1 FOR UPDATE SKIP LOCKED", Map.of());
            if (job == null) {
                return null;
            }
            db.execute("UPDATE backtest_jobs SET status='running' WHERE job_id=:id", p("id", Db.str(job, "job_id")));
            return Db.str(job, "job_id");
        });
        if (jobId == null) {
            return false;
        }
        runJob(jobId, clock);
        return true;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> runJob(String jobId, AppClock clock) {
        Map<String, Object> job = db.row("SELECT * FROM backtest_jobs WHERE job_id=:id", p("id", jobId));
        if (job == null) {
            throw ApiException.notFound(jobId);
        }
        Map<String, Object> result = null;
        String status;
        String err = null;
        try {
            Map<String, Object> defn = Json.loadMap(Db.str(job, "definition"));
            Object orgsRaw = job.get("org_ids") == null ? null : Json.load(Db.str(job, "org_ids"));
            List<String> orgs = orgsRaw == null ? null : Json.strings(orgsRaw);
            if (orgs != null && orgs.isEmpty()) {
                orgs = null;
            }
            LocalDateTime from = Db.time(job, "time_from");
            LocalDateTime to = Db.time(job, "time_to");
            result = "single_rule".equals(Db.str(job, "target_type"))
                    ? backtestRule(jobId, defn, from, to, orgs)
                    : backtestScenario(jobId, defn, from, to, orgs);
            status = "done";
        } catch (RuntimeException e) {
            log.error("backtest {} failed", jobId, e);
            status = "failed";
            String m = String.valueOf(e.getMessage());
            err = m.length() > 4000 ? m.substring(0, 4000) : m;
        }
        Map<String, Object> fr = result;
        String fs = status;
        String fe = err;
        db.txRun(() -> db.execute("UPDATE backtest_jobs SET status=:s, result=:r, error=:e, finished_at=:f WHERE job_id=:id",
                p("s", fs, "r", fr == null ? null : Json.dump(fr), "e", fe, "f", clock.now(), "id", jobId)));
        return result == null ? Map.of() : result;
    }

    // ---------------------------------------------------------------- 단일룰
    private int ruleVersion(String ruleId) {
        Map<String, Object> r = db.row("SELECT current_version FROM single_rules WHERE rule_id=:id", p("id", ruleId));
        return r == null ? 0 : Db.integer(r, "current_version");
    }

    private void runRuleBacktest(String jobId, ParsedRule parsed, int version, LocalDateTime from, LocalDateTime to) {
        RuleCompiler.CompiledRule c = db.tx(() -> RuleCompiler.compileBacktest(parsed, repo.listLoader()));
        Map<String, Object> params = new LinkedHashMap<>(c.params());
        params.put("job_id", jobId);
        params.put("rule_version", version);
        params.put("time_from", Kst.fmt(from));
        params.put("time_to", Kst.fmt(to));
        ch.command(c.sql(), params, Purpose.BACKTEST);
    }

    /** (히트, 처음 보였을 평가 시각). */
    public record VisibleHit(Hit hit, LocalDateTime visibleAt) {
    }

    private List<VisibleHit> jobHits(String jobId, List<String> orgs, Map<String, Integer> windows) {
        List<Map<String, Object>> rs = ch.query("SELECT rule_id, rule_version, org_id, entity, hit_bucket, first_seen, last_seen, "
                        + "value, threshold, sample_event_ids, win_to, first_win_to FROM detect.rule_hits_backtest "
                        + "WHERE job_id = {job:UUID} ORDER BY first_win_to", p("job", jobId), Purpose.BACKTEST,
                Map.of("max_result_rows", 1_000_000));
        List<VisibleHit> out = new ArrayList<>();
        for (Map<String, Object> r : rs) {
            if (orgs != null && !orgs.contains(ClickHouse.str(r, "org_id"))) {
                continue;
            }
            Hit h = RuleRunner.hitFromRow(r, windows.getOrDefault(ClickHouse.str(r, "rule_id"), 0));
            out.add(new VisibleHit(h, ClickHouse.time(r, "first_win_to")));
        }
        return out;
    }

    private List<Map<String, Object>> knownIncidents(LocalDateTime from, LocalDateTime to, List<String> orgs) {
        List<Map<String, Object>> inc = db.rows("SELECT * FROM known_incidents WHERE occurred_at BETWEEN :f AND :t "
                + "ORDER BY occurred_at", p("f", from.minus(RECALL_MARGIN), "t", to.plus(RECALL_MARGIN)));
        return inc.stream().filter(i -> orgs == null || orgs.contains(Db.str(i, "org_id"))).toList();
    }

    private record Caught(String org, String entity, LocalDateTime at) {
    }

    private List<Map<String, Object>> recall(List<Map<String, Object>> incidents, List<Caught> caught) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> i : incidents) {
            LocalDateTime occ = Db.time(i, "occurred_at");
            boolean hit = caught.stream().anyMatch(c -> c.org().equals(Db.str(i, "org_id")) && c.entity().equals(Db.str(i, "entity"))
                    && Duration.between(c.at(), occ).abs().compareTo(RECALL_MARGIN) <= 0);
            out.add(Json.obj("incident_id", i.get("incident_id"), "org_id", i.get("org_id"), "entity", i.get("entity"),
                    "occurred_at", Kst.iso(occ), "summary", i.get("summary"), "detected", hit));
        }
        return out;
    }

    private static <K> List<Map.Entry<K, Integer>> topN(Map<K, Integer> counts, int n) {
        return counts.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(n).toList();
    }

    public Map<String, Object> backtestRule(String jobId, Map<String, Object> defn, LocalDateTime from, LocalDateTime to,
                                            List<String> orgs) {
        ParsedRule parsed = db.tx(() -> RuleValidator.parse(defn, repo.listExists()));
        int version = ruleVersion(parsed.id());
        runRuleBacktest(jobId, parsed, version, from, to);
        List<VisibleHit> hits = jobHits(jobId, orgs, Map.of(parsed.id(), parsed.windowSec()));
        Map<String, Integer> daily = new TreeMap<>();
        Map<List<String>, Integer> top = new LinkedHashMap<>();
        for (VisibleHit vh : hits) {
            daily.merge(vh.hit().hitBucket().toLocalDate().toString(), 1, Integer::sum);
            top.merge(List.of(vh.hit().orgId(), vh.hit().entity()), 1, Integer::sum);
        }
        Map<String, Object> sens = new LinkedHashMap<>();
        for (double mult : new double[]{0.5, 1.0, 2.0}) {
            RuleCompiler.CompiledRule c = db.tx(() -> RuleCompiler.compileBucketCount(parsed, repo.listLoader(), mult));
            Map<String, Object> params = new LinkedHashMap<>(c.params());
            params.put("time_from", Kst.fmt(from));
            params.put("time_to", Kst.fmt(to));
            List<Map<String, Object>> r = ch.query(c.sql(), params, Purpose.BACKTEST);
            sens.put("x" + (mult == Math.rint(mult) ? String.valueOf((int) mult) : String.valueOf(mult)),
                    r.isEmpty() ? 0 : (int) ClickHouse.num(r.get(0), "hits"));
        }
        // 단독 경보(alert_on_hit) 모의
        List<Map<String, Object>> alertsOut = new ArrayList<>();
        if (parsed.alertOnHit()) {
            Map<List<String>, ExistingAlert> store = new HashMap<>();
            for (VisibleHit vh : hits) {
                Hit h = vh.hit();
                List<String> k = List.of(h.orgId(), h.entity());
                ExistingAlert ex = store.get(k);
                Decision d = AlertService.decide(ex, parsed.severity(), vh.visibleAt(), parsed.suppressSec());
                if (d == Decision.CREATE) {
                    alertsOut.add(Json.obj("org_id", h.orgId(), "entity", h.entity(), "severity", parsed.severity(),
                            "at", Kst.iso(vh.visibleAt())));
                    store.put(k, new ExistingAlert("bt", parsed.severity(), h.lastSeen()));
                } else {
                    LocalDateTime ls = ex.lastSeen().isAfter(h.lastSeen()) ? ex.lastSeen() : h.lastSeen();
                    store.put(k, new ExistingAlert("bt", ex.severity(), ls));
                }
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("target_type", "single_rule");
        out.put("target_id", parsed.id());
        out.put("version", version);
        out.put("time_from", Kst.iso(from));
        out.put("time_to", Kst.iso(to));
        out.put("total_hits", hits.size());
        out.put("total_alerts", alertsOut.size());
        out.put("daily", daily.entrySet().stream().map(e -> Json.obj("date", e.getKey(), "hits", e.getValue())).toList());
        out.put("top_entities", topN(top, 20).stream()
                .map(e -> Json.obj("org_id", e.getKey().get(0), "entity", e.getKey().get(1), "hits", e.getValue())).toList());
        out.put("threshold_sensitivity", sens);
        out.put("alerts", alertsOut.size() > 500 ? alertsOut.subList(0, 500) : alertsOut);
        out.put("recall", recall(knownIncidents(from, to, orgs),
                hits.stream().map(v -> new Caught(v.hit().orgId(), v.hit().entity(), v.hit().hitBucket())).toList()));
        return out;
    }

    // ---------------------------------------------------------------- 순서도
    /**
     * 히트가 처음 보인 시각 순서로 훑으며 실시간과 같은 규칙으로 경보를 만든다.
     * 평가(시나리오 코드)는 한 번에 모아 Python 으로 보내고, 억제 정책은 결과에 차례로 적용한다.
     */
    public List<Map<String, Object>> simulateScenarioAlerts(ScenarioProgram program, String scenarioId, List<VisibleHit> hits,
                                                            int suppressSec, Map<List<String>, Set<String>> tags) {
        Map<List<String>, List<VisibleHit>> byEntity = new LinkedHashMap<>();
        for (VisibleHit vh : hits) {
            byEntity.computeIfAbsent(List.of(vh.hit().orgId(), vh.hit().entity()), k -> new ArrayList<>()).add(vh);
        }
        record Step(List<String> key, LocalDateTime cycle) {
        }
        List<Step> steps = new ArrayList<>();
        List<EvalCase> cases = new ArrayList<>();
        for (Map.Entry<List<String>, List<VisibleHit>> en : byEntity.entrySet()) {
            List<String> k = en.getKey();
            TreeSet<LocalDateTime> cycles = en.getValue().stream().map(VisibleHit::visibleAt)
                    .collect(Collectors.toCollection(TreeSet::new));
            for (LocalDateTime c : cycles) {
                List<Hit> visible = new ArrayList<>();
                Set<HitKey> fresh = new HashSet<>();
                for (VisibleHit vh : en.getValue()) {
                    if (!vh.visibleAt().isAfter(c)) {
                        visible.add(vh.hit());
                    }
                    if (vh.visibleAt().equals(c)) {
                        fresh.add(vh.hit().key());
                    }
                }
                // 자산 태그는 평가 시점의 현재 값 (실시간과 같다)
                cases.add(new EvalCase(k.get(0), k.get(1), visible, tags.getOrDefault(k, Set.of()), fresh));
                steps.add(new Step(k, c));
            }
        }
        List<EvalOutcome> outs = engine.evaluate(program, cases);

        Map<List<String>, Map<String, Object>> alerts = new LinkedHashMap<>();
        List<Map<String, Object>> history = new ArrayList<>();
        for (int i = 0; i < steps.size(); i++) {
            Chosen chosen = outs.get(i).chosen();
            if (chosen == null) {
                continue;
            }
            List<String> k = steps.get(i).key();
            LocalDateTime c = steps.get(i).cycle();
            LocalDateTime last = chosen.lastSeen() != null ? chosen.lastSeen() : c;
            Map<String, Object> cur = alerts.get(k);
            ExistingAlert ex = cur == null ? null
                    : new ExistingAlert("bt", (String) cur.get("severity"), (LocalDateTime) cur.get("_last_seen"));
            Decision d = AlertService.decide(ex, chosen.severity(), c, suppressSec);
            if (d == Decision.CREATE) {
                if (cur != null) {
                    history.add(cur);
                }
                Map<String, Object> a = new LinkedHashMap<>();
                a.put("scenario_id", scenarioId);
                a.put("org_id", k.get(0));
                a.put("entity", k.get(1));
                a.put("severity", chosen.severity());
                a.put("alert_node", chosen.node());
                a.put("at", Kst.iso(c));
                a.put("first_seen", Kst.iso(chosen.firstSeen()));
                a.put("hit_count", 1);
                a.put("upgraded", false);
                a.put("path", chosen.path());
                a.put("_last_seen", last);
                alerts.put(k, a);
            } else if (d == Decision.UPGRADE) {
                cur.put("severity", chosen.severity());
                cur.put("alert_node", chosen.node());
                cur.put("upgraded", true);
                cur.put("path", chosen.path());
                cur.put("hit_count", (int) cur.get("hit_count") + 1);
                cur.put("_last_seen", max((LocalDateTime) cur.get("_last_seen"), last));
            } else {
                cur.put("hit_count", (int) cur.get("hit_count") + 1);
                cur.put("_last_seen", max((LocalDateTime) cur.get("_last_seen"), last));
            }
        }
        List<Map<String, Object>> out = new ArrayList<>(history);
        out.addAll(alerts.values());
        for (Map<String, Object> a : out) {
            a.put("last_seen", Kst.iso((LocalDateTime) a.remove("_last_seen")));
        }
        out.sort(Comparator.comparing(a -> String.valueOf(a.get("at"))));
        return out;
    }

    private static LocalDateTime max(LocalDateTime a, LocalDateTime b) {
        return a.isAfter(b) ? a : b;
    }

    public Map<String, Object> backtestScenario(String jobId, Map<String, Object> graph, LocalDateTime from,
                                                LocalDateTime to, List<String> orgs) {
        GraphValidation res = db.tx(() -> repo.checkGraph(graph));
        if (!res.ok()) {
            throw new GraphValidation.GraphValidationException(res);
        }
        Map<String, RuleRecord> rules = db.tx(() -> {
            Map<String, RuleRecord> m = new LinkedHashMap<>();
            for (String rid : res.ruleRefs) {
                m.put(rid, repo.getRule(rid));
            }
            return m;
        });
        Map<String, Integer> windows = new HashMap<>();
        for (Map.Entry<String, RuleRecord> en : rules.entrySet()) {
            ParsedRule parsed = RuleValidator.parse(en.getValue().definition(), null);
            windows.put(en.getKey(), parsed.windowSec());
            runRuleBacktest(jobId, parsed, en.getValue().version(), from.minusSeconds(res.maxSpanSec), to);
        }
        List<VisibleHit> hits = jobHits(jobId, orgs, windows);
        Map<String, Object> ruleStats = new LinkedHashMap<>();
        for (String rid : rules.keySet()) {
            ruleStats.put(rid, hits.stream().filter(h -> h.hit().ruleId().equals(rid)).count());
        }
        // 자산 태그 미리 읽기 (평가 코드는 DB 를 보지 않는다)
        Map<List<String>, Set<String>> tags = new HashMap<>();
        db.rows("SELECT org_id, ip, tag FROM asset_tags").forEach(r -> tags.computeIfAbsent(
                List.of(Db.str(r, "org_id"), Db.str(r, "ip")), k -> new TreeSet<>()).add(Db.str(r, "tag")));
        // 백테스트도 저장된 버전과 같은 생성기로 만든 코드를 쓴다 (초안이면 _drafts)
        ScenarioProgram program = repo.draftProgram(graph, res);
        List<Map<String, Object>> alerts = simulateScenarioAlerts(program, (String) graph.get("id"), hits,
                Kst.parseDuration(graph.getOrDefault("suppress_for", "6h")), tags);

        Map<String, Integer> daily = new TreeMap<>();
        Map<List<String>, Integer> top = new LinkedHashMap<>();
        Map<String, Integer> sev = new LinkedHashMap<>();
        List<Caught> caught = new ArrayList<>();
        for (Map<String, Object> a : alerts) {
            String at = String.valueOf(a.get("at"));
            daily.merge(at.substring(0, Math.min(10, at.length())), 1, Integer::sum);
            top.merge(List.of((String) a.get("org_id"), (String) a.get("entity")), 1, Integer::sum);
            sev.merge((String) a.get("severity"), 1, Integer::sum);
            caught.add(new Caught((String) a.get("org_id"), (String) a.get("entity"), Kst.parse(at)));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("target_type", "scenario");
        out.put("target_id", graph.get("id"));
        out.put("time_from", Kst.iso(from));
        out.put("time_to", Kst.iso(to));
        out.put("total_hits", hits.size());
        out.put("hits_by_rule", ruleStats);
        out.put("total_alerts", alerts.size());
        out.put("alerts_by_severity", sev);
        out.put("daily", daily.entrySet().stream().map(e -> Json.obj("date", e.getKey(), "alerts", e.getValue())).toList());
        out.put("top_entities", topN(top, 20).stream()
                .map(e -> Json.obj("org_id", e.getKey().get(0), "entity", e.getKey().get(1), "alerts", e.getValue())).toList());
        out.put("alerts", alerts.size() > 500 ? alerts.subList(0, 500) : alerts);
        out.put("recall", recall(knownIncidents(from, to, orgs), caught));
        out.put("code_sha256", program.sha256());
        return out;
    }
}
