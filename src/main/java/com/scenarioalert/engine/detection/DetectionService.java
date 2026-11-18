package com.scenarioalert.engine.detection;

import com.scenarioalert.engine.alerting.AlertService;
import com.scenarioalert.engine.alerting.AlertService.AlertCandidate;
import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.d3fend.D3fendService;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.repo.Records.RuleRecord;
import com.scenarioalert.engine.repo.Records.ScenarioRecord;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.scenario.EvalModels.Chosen;
import com.scenarioalert.engine.scenario.EvalModels.EvalCase;
import com.scenarioalert.engine.scenario.EvalModels.EvalOutcome;
import com.scenarioalert.engine.scenario.EvalModels.Hit;
import com.scenarioalert.engine.scenario.EvalModels.HitKey;
import com.scenarioalert.engine.scenario.PythonScenarioEngine;
import com.scenarioalert.engine.singlerule.ParsedRule;
import com.scenarioalert.engine.singlerule.RuleRunner;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 한 평가 구간의 후처리: 새 히트 → 단독 경보 / 순서도 평가 → 경보 (설계안 7장 3~7단계).
 * 순서도 평가는 시나리오 버전마다 생성된 Python 코드가 한다 ({@link PythonScenarioEngine}).
 * Java 는 히트 조회(ClickHouse), 자산 태그 조회(MariaDB), 경보 기록(억제·상향)을 맡는다.
 */
@Component
public class DetectionService {
    static final int EXTRA_LOOKBACK_SEC = 86400;  // 순서도 최대 기간 + 집계 창 여유

    private final ClickHouse ch;
    private final Db db;
    private final Repo repo;
    private final AlertService alerts;
    private final PythonScenarioEngine engine;
    private final MeterRegistry meters;

    public DetectionService(ClickHouse ch, Db db, Repo repo, AlertService alerts, PythonScenarioEngine engine,
                            MeterRegistry meters) {
        this.ch = ch;
        this.db = db;
        this.repo = repo;
        this.alerts = alerts;
        this.engine = engine;
        this.meters = meters;
    }

    public AlertCandidate singleRuleCandidate(RuleRecord rule, ParsedRule parsed, Hit h) {
        Map<String, Object> step = new LinkedHashMap<>();
        step.put("node", rule.ruleId());
        step.put("type", "rule");
        step.put("rule_id", rule.ruleId());
        step.put("at", Kst.naiveIso(h.hitBucket()));
        step.put("value", h.value());
        step.put("threshold", h.threshold());
        step.put("first_seen", Kst.naiveIso(h.firstSeen()));
        step.put("last_seen", Kst.naiveIso(h.lastSeen()));
        step.put("sample_event_ids", h.sampleEventIds());
        String title = parsed.name() + ": " + h.entity();
        Object desc = parsed.raw().get("description");
        return new AlertCandidate("single_rule", rule.ruleId(), rule.version(), h.orgId(), parsed.entityType(), h.entity(),
                parsed.severity(), title.length() > 300 ? title.substring(0, 300) : title, null,
                desc == null ? "" : String.valueOf(desc), List.of(step), h.firstSeen(), h.lastSeen(),
                !"active".equals(rule.status()), parsed.suppressSec(), AttackService.ids(parsed.raw().get("attack")),
                D3fendService.ids(parsed.raw().get("d3fend")));
    }

    /** 참조 룰의 (현재 버전, 집계 창 초, ATT&CK 기법, 지정 대응방책 D3FEND 기법). */
    public record RuleMeta(int version, int windowSec, List<String> attack, List<String> d3fend) {
        public RuleMeta(int version, int windowSec, List<String> attack) {
            this(version, windowSec, attack, List.of());
        }
    }

    public Map<String, RuleMeta> ruleMeta(Set<String> ruleIds) {
        Map<String, RuleMeta> out = new HashMap<>();
        if (ruleIds.isEmpty()) {
            return out;
        }
        db.rows("SELECT r.rule_id, r.current_version, v.definition FROM single_rules r JOIN single_rule_versions v "
                + "ON v.rule_id=r.rule_id AND v.version=r.current_version WHERE r.rule_id IN (:ids)", p("ids", List.copyOf(ruleIds)))
                .forEach(r -> {
                    Map<String, Object> d = Json.loadMap(Db.str(r, "definition"));
                    out.put(Db.str(r, "rule_id"), new RuleMeta(Db.integer(r, "current_version"),
                            Kst.parseDurationOr(d.getOrDefault("window", "1m"), 0), AttackService.ids(d.get("attack")),
                            D3fendService.ids(d.get("d3fend"))));
                });
        return out;
    }

    /**
     * until=null 이면 위쪽 경계 없이 읽는다. 따라잡기 중에는 룰마다 진행 위치가 달라
     * 다른 룰이 이미 만든 "뒤 시각" 히트도 함께 봐야 순서도가 성립한다.
     */
    public List<Hit> fetchHits(String orgId, List<String> entities, Map<String, RuleMeta> meta, LocalDateTime since,
                               LocalDateTime until) {
        if (entities.isEmpty() || meta.isEmpty()) {
            return List.of();
        }
        Map<String, Object> params = p("o", orgId, "ents", entities, "rules", new ArrayList<>(meta.keySet()),
                "since", Kst.fmt(since));
        String upper = "";
        if (until != null) {
            upper = "AND win_to <= {until:DateTime64(3)}";
            params.put("until", Kst.fmt(until));
        }
        List<Map<String, Object>> rs = ch.query("SELECT " + RuleRunner.HIT_COLUMNS + " FROM detect.rule_hits FINAL "
                + "WHERE org_id = {o:String} AND has({ents:Array(String)}, entity) AND has({rules:Array(String)}, rule_id) "
                + "AND hit_bucket >= {since:DateTime64(3)} " + upper, params);
        List<Hit> out = new ArrayList<>();
        for (Map<String, Object> r : rs) {
            String rid = ClickHouse.str(r, "rule_id");
            RuleMeta m = meta.get(rid);
            Hit h = RuleRunner.hitFromRow(r, m == null ? 0 : m.windowSec());
            if (m != null && m.version() == h.ruleVersion()) {
                out.add(h);
            }
        }
        return out;
    }

    public static Set<String> scenarioRuleIds(Map<String, Object> graph) {
        Set<String> out = new TreeSet<>();
        for (Object o : Json.asList(graph.get("nodes"))) {
            Map<String, Object> n = Json.asMap(o);
            if ("rule".equals(n.get("type"))) {
                out.add((String) n.get("rule_id"));
            } else if ("check".equals(n.get("type"))) {
                out.addAll(Json.strings(n.get("rule_ids")));
            }
        }
        return out;
    }

    /**
     * 순서도 경보 후보. ATT&CK 기법 = 고른 경보 노드의 attack + 그 경로에서 실제로 성립한 룰(rule 노드, check 의 yes)의 attack
     * + 이번 평가에서 함께 성립한 다른 경보 노드의 attack (경보는 하나만 고르지만, 성립한 단계는 모두 관측된 것이다.
     * 예: 따라잡기에서 공격 히트가 늦게 들어오면 실행·도구 반입 결론이 한 번의 평가에서 함께 성립한다).
     */
    public AlertCandidate scenarioCandidate(ScenarioRecord sc, String orgId, String entity, Chosen chosen,
                                            LocalDateTime now, Map<String, RuleMeta> meta) {
        return scenarioCandidate(sc, orgId, entity, chosen, List.of(), now, meta);
    }

    public AlertCandidate scenarioCandidate(ScenarioRecord sc, String orgId, String entity, Chosen chosen, List<String> reached,
                                            LocalDateTime now, Map<String, RuleMeta> meta) {
        if (chosen == null) {
            return null;
        }
        LocalDateTime t = chosen.time() != null ? chosen.time() : now;
        return new AlertCandidate("scenario", sc.scenarioId(), sc.version(), orgId, sc.entityType(), entity,
                chosen.severity(), chosen.title(), chosen.node(), chosen.playbook(), chosen.path(),
                chosen.firstSeen() != null ? chosen.firstSeen() : t, chosen.lastSeen() != null ? chosen.lastSeen() : t,
                !"active".equals(sc.status()), sc.suppressSec(), scenarioAttack(sc.graph(), chosen, reached, meta),
                scenarioD3fend(sc.graph(), chosen, reached, meta));
    }

    static List<String> scenarioAttack(Map<String, Object> graph, Chosen chosen, List<String> reached, Map<String, RuleMeta> meta) {
        return scenarioTags(graph, chosen, reached, meta, "attack");
    }

    /** 지정 대응방책도 ATT&CK 기법과 같은 범위(고른·함께 성립한 경보 노드 + 경로의 룰)에서 모은다. */
    static List<String> scenarioD3fend(Map<String, Object> graph, Chosen chosen, List<String> reached, Map<String, RuleMeta> meta) {
        return scenarioTags(graph, chosen, reached, meta, "d3fend");
    }

    private static List<String> scenarioTags(Map<String, Object> graph, Chosen chosen, List<String> reached, Map<String, RuleMeta> meta,
                                             String key) {
        Set<String> out = new TreeSet<>();
        for (Object o : Json.asList(graph.get("nodes"))) {
            Map<String, Object> n = Json.asMap(o);
            String nid = String.valueOf(n.get("id"));
            if ("alert".equals(n.get("type")) && (nid.equals(chosen.node()) || reached.contains(nid))) {
                out.addAll(key.equals("attack") ? AttackService.ids(n.get(key)) : D3fendService.ids(n.get(key)));
            }
        }
        for (Map<String, Object> step : chosen.path()) {
            for (String k : List.of("rule_id", "matched_rule_id")) {
                RuleMeta m = step.get(k) == null ? null : meta.get(String.valueOf(step.get(k)));
                if (m != null) {
                    out.addAll(key.equals("attack") ? m.attack() : m.d3fend());
                }
            }
        }
        return List.copyOf(out);
    }

    public List<AlertService.Recorded> evaluateScenario(ScenarioRecord sc, Set<List<String>> targets, Set<HitKey> newKeys,
                                                        LocalDateTime now) {
        Map<String, RuleMeta> meta = ruleMeta(scenarioRuleIds(sc.graph()));
        LocalDateTime since = now.minusSeconds(sc.maxSpanSec() + EXTRA_LOOKBACK_SEC);
        Map<String, List<String>> byOrg = new LinkedHashMap<>();
        for (List<String> t : targets) {
            byOrg.computeIfAbsent(t.get(0), k -> new ArrayList<>()).add(t.get(1));
        }
        List<EvalCase> cases = new ArrayList<>();
        for (Map.Entry<String, List<String>> en : byOrg.entrySet()) {
            String org = en.getKey();
            Map<String, List<Hit>> perEntity = new HashMap<>();
            for (Hit h : fetchHits(org, en.getValue(), meta, since, null)) {
                perEntity.computeIfAbsent(h.entity(), k -> new ArrayList<>()).add(h);
            }
            for (String ent : en.getValue()) {
                meters.counter("scenario_evaluations_total", "scenario", sc.scenarioId()).increment();
                Set<String> tags = db.tx(() -> repo.assetTags(org, ent));
                cases.add(new EvalCase(org, ent, perEntity.getOrDefault(ent, List.of()), tags, newKeys));
            }
        }
        List<EvalOutcome> outs = engine.evaluate(sc.program(), cases);
        List<AlertService.Recorded> rec = new ArrayList<>();
        for (int i = 0; i < cases.size(); i++) {
            EvalCase c = cases.get(i);
            AlertCandidate cand = scenarioCandidate(sc, c.orgId(), c.entity(), outs.get(i).chosen(), outs.get(i).reachedAlerts(), now, meta);
            if (cand != null) {
                rec.add(alerts.recordAlert(cand, now));
            }
        }
        return rec;
    }

    public void postProcess(RuleRecord rule, ParsedRule parsed, List<Hit> newHits, LocalDateTime now) {
        if (newHits.isEmpty()) {
            return;
        }
        if (parsed.alertOnHit()) {
            for (Hit h : newHits) {
                alerts.recordAlert(singleRuleCandidate(rule, parsed, h), now);
            }
        }
        List<ScenarioRecord> scenarios = db.tx(() -> repo.scenariosForRule(rule.ruleId()));
        Set<List<String>> targets = new LinkedHashSet<>();
        Set<HitKey> newKeys = new LinkedHashSet<>();
        for (Hit h : newHits) {
            targets.add(List.of(h.orgId(), h.entity()));
            newKeys.add(h.key());
        }
        for (ScenarioRecord sc : scenarios) {
            if (!sc.entityType().equals(parsed.entityType())) {
                continue;
            }
            evaluateScenario(sc, targets, newKeys, now);
        }
    }
}
