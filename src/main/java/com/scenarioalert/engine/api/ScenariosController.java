package com.scenarioalert.engine.api;

import com.scenarioalert.engine.auth.AuthService.User;
import com.scenarioalert.engine.auth.RequireRole;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.detection.DetectionService;
import com.scenarioalert.engine.detection.DetectionService.RuleMeta;
import com.scenarioalert.engine.lifecycle.LifecycleService;
import com.scenarioalert.engine.repo.Records.ScenarioRecord;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.scenario.EvalModels.Chosen;
import com.scenarioalert.engine.scenario.EvalModels.EvalCase;
import com.scenarioalert.engine.scenario.EvalModels.EvalOutcome;
import com.scenarioalert.engine.scenario.EvalModels.Hit;
import com.scenarioalert.engine.scenario.EvalModels.ScenarioProgram;
import com.scenarioalert.engine.scenario.GraphValidation;
import com.scenarioalert.engine.scenario.PythonScenarioEngine;
import com.scenarioalert.engine.scenario.ScenarioCodeGenerator;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 시나리오(순서도) API (설계안 9장).
 * 저장하면 버전마다 Python 평가 코드가 생성되고, 시뮬레이션·백테스트·실시간 평가가 모두 그 코드를 실행한다.
 */
@RestController
@RequestMapping("/api/v1")
public class ScenariosController {
    private final Db db;
    private final Repo repo;
    private final DetectionService detection;
    private final LifecycleService lifecycle;
    private final PythonScenarioEngine engine;

    public ScenariosController(Db db, Repo repo, DetectionService detection, LifecycleService lifecycle,
                               PythonScenarioEngine engine) {
        this.db = db;
        this.repo = repo;
        this.detection = detection;
        this.lifecycle = lifecycle;
        this.engine = engine;
    }

    static Map<String, Object> summary(ScenarioRecord s) {
        Map<String, Object> g = s.graph();
        Set<String> sev = new TreeSet<>();
        int nodeCount = 0;
        for (Object o : Objects.requireNonNullElse(Json.asList(g.get("nodes")), List.of())) {
            nodeCount++;
            Map<String, Object> n = Json.asMap(o);
            if ("alert".equals(n.get("type")) && n.get("severity") != null) {
                sev.add(String.valueOf(n.get("severity")));
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("scenario_id", s.scenarioId());
        m.put("name", s.name());
        m.put("version", s.version());
        m.put("status", s.status());
        m.put("entity_type", s.entityType());
        m.put("max_span_sec", s.maxSpanSec());
        m.put("suppress_for", g.getOrDefault("suppress_for", "6h"));
        m.put("rule_ids", new ArrayList<>(DetectionService.scenarioRuleIds(g)));
        m.put("node_count", nodeCount);
        m.put("severities", new ArrayList<>(sev));
        m.put("code_sha256", s.codeSha256());
        m.put("generator_version", s.generatorVersion());
        m.put("updated_at", s.updatedAt());
        return m;
    }

    /** 화면 분류용 그룹 (V6, 그래프 JSON 밖) 을 요약에 더한다. */
    private Map<String, Object> withGroup(Map<String, Object> m) {
        Map<String, Object> r = db.row("SELECT group_id FROM scenarios WHERE scenario_id=:s", p("s", m.get("scenario_id")));
        m.put("group_id", r == null ? null : r.get("group_id"));
        return m;
    }

    @GetMapping("/scenarios")
    @RequireRole("viewer")
    public List<Map<String, Object>> list() {
        return db.tx(() -> {
            List<ScenarioRecord> scs = repo.listScenarios();
            Map<String, Long> counts = new HashMap<>();
            db.rows("SELECT source_id, COUNT(*) AS n FROM alert_state WHERE source_type='scenario' AND created_at >= NOW() - "
                    + "INTERVAL 1 DAY GROUP BY source_id").forEach(r -> counts.put(Db.str(r, "source_id"), Db.lng(r, "n")));
            // 화면 분류용 그룹 (그래프 JSON 밖, V6)
            Map<String, Object> groups = new HashMap<>();
            db.rows("SELECT scenario_id, group_id FROM scenarios").forEach(r -> groups.put(Db.str(r, "scenario_id"), r.get("group_id")));
            List<Map<String, Object>> out = new ArrayList<>();
            for (ScenarioRecord s : scs) {
                Map<String, Object> m = summary(s);
                m.put("alerts_24h", counts.getOrDefault(s.scenarioId(), 0L));
                m.put("group_id", groups.get(s.scenarioId()));
                out.add(m);
            }
            return out;
        });
    }

    @PostMapping("/scenarios")
    @ResponseStatus(HttpStatus.CREATED)
    @RequireRole("author")
    public Map<String, Object> create(@RequestBody Map<String, Object> body, User user) {
        Repo.SavedScenario s = db.tx(() -> repo.saveScenario(Body.map(body, "graph"), user.username(),
                Body.optStr(body, "change_note"), true, null));
        return Json.obj("scenario", withGroup(summary(s.scenario())), "graph", s.scenario().graph(),
                "warnings", s.validation().warningMaps());
    }

    @PostMapping("/scenarios/validate")
    @RequireRole("author")
    public Map<String, Object> validate(@RequestBody Map<String, Object> body) {
        GraphValidation res = db.tx(() -> repo.checkGraph(Body.map(body, "graph")));
        return Json.obj("ok", res.ok(), "errors", res.errorMaps(), "warnings", res.warningMaps(),
                "max_span_sec", res.maxSpanSec, "rule_refs", new ArrayList<>(res.ruleRefs));
    }

    /** 저장 전 초안이 어떤 Python 코드로 생성되는지 미리 본다. */
    @PostMapping("/scenarios/codegen")
    @RequireRole("author")
    public Map<String, Object> codegen(@RequestBody Map<String, Object> body) {
        Map<String, Object> graph = Body.map(body, "graph");
        GraphValidation res = db.tx(() -> repo.checkGraph(graph));
        if (!res.ok()) {
            return Json.obj("ok", false, "errors", res.errorMaps());
        }
        ScenarioProgram prog = repo.draftProgram(graph, res);
        return Json.obj("ok", true, "generator_version", ScenarioCodeGenerator.GENERATOR, "code_sha256", prog.sha256(),
                "python_code", prog.code());
    }

    /** 초안 순서도를 지정한 대상·기간의 실제 히트(rule_hits)에 대입해 노드별 성립 여부와 경로를 돌려준다. */
    @PostMapping("/scenarios/simulate")
    @RequireRole("author")
    public Map<String, Object> simulate(@RequestBody Map<String, Object> body) {
        Map<String, Object> graph = Body.map(body, "graph");
        String orgId = Body.str(body, "org_id");
        String entity = Body.str(body, "entity");
        GraphValidation res = db.tx(() -> repo.checkGraph(graph));
        if (!res.ok()) {
            return Json.obj("ok", false, "errors", res.errorMaps());
        }
        Set<String> tags = db.tx(() -> repo.assetTags(orgId, entity));
        LocalDateTime tTo = Kst.parse(Body.optStr(body, "time_to"));
        if (tTo == null) {
            tTo = Kst.now();
        }
        LocalDateTime tFrom = Kst.parse(Body.optStr(body, "time_from"));
        if (tFrom == null) {
            tFrom = tTo.minusHours(24);
        }
        Map<String, RuleMeta> meta = db.tx(() -> detection.ruleMeta(res.ruleRefs));
        List<Hit> hits = detection.fetchHits(orgId, List.of(entity), meta, tFrom.minusSeconds(res.maxSpanSec), tTo);
        ScenarioProgram prog = repo.draftProgram(graph, res);
        EvalOutcome out = engine.evaluateOne(prog, new EvalCase(orgId, entity, hits, tags, null));
        Chosen c = out.chosen();
        return Json.obj("ok", true, "node_status", out.nodeStatus(), "asset_tags", new ArrayList<>(new TreeSet<>(tags)),
                "hits", hits.stream().map(h -> Json.obj("rule_id", h.ruleId(), "at", h.hitBucket(), "value", h.value(),
                        "threshold", h.threshold())).toList(),
                "alert", c == null ? null : Json.obj("node", c.node(), "severity", c.severity(), "title", c.title(),
                        "path", c.path()),
                "reached_alerts", out.reachedAlerts(), "code_sha256", prog.sha256());
    }

    @GetMapping("/scenarios/{sid}")
    @RequireRole("viewer")
    public Map<String, Object> get(@PathVariable String sid) {
        return db.tx(() -> {
            ScenarioRecord s = repo.getScenario(sid);
            Map<String, Object> g = new LinkedHashMap<>(s.graph());
            g.put("status", s.status());
            return Json.obj("scenario", withGroup(summary(s)), "graph", g, "operation", lifecycle.operationStats("scenario", sid),
                    "warnings", repo.checkGraph(s.graph()).warningMaps());
        });
    }

    @PutMapping("/scenarios/{sid}")
    @RequireRole("author")
    public Map<String, Object> update(@PathVariable String sid, @RequestBody Map<String, Object> body, User user) {
        Map<String, Object> g = new LinkedHashMap<>(Body.map(body, "graph"));
        g.put("id", sid);
        Repo.SavedScenario s = db.tx(() -> repo.saveScenario(g, user.username(), Body.optStr(body, "change_note"), false, null));
        return Json.obj("scenario", withGroup(summary(s.scenario())), "graph", s.scenario().graph(),
                "warnings", s.validation().warningMaps());
    }

    @PostMapping("/scenarios/{sid}/status")
    @RequireRole("author")
    public Map<String, Object> status(@PathVariable String sid, @RequestBody Map<String, Object> body, User user) {
        String target = Body.str(body, "status");
        return db.tx(() -> {
            String cur = repo.getScenario(sid).status();
            if (!user.has(LifecycleService.requiredRole(cur, target))) {
                throw new ApiException(403, "active 전환은 관리자만 할 수 있습니다");
            }
            lifecycle.changeScenarioStatus(sid, target, user.username(), false);
            return Json.obj("scenario", withGroup(summary(repo.getScenario(sid))));
        });
    }

    /** 버전별로 생성된 Python 코드 (version 을 빼면 현재 버전). */
    @GetMapping("/scenarios/{sid}/code")
    @RequireRole("viewer")
    public Map<String, Object> code(@PathVariable String sid, @RequestParam(required = false) Integer version) {
        Map<String, Object> r = version == null
                ? db.row("SELECT v.scenario_id, v.version, v.python_code, v.code_sha256, v.generator_version, v.created_at "
                + "FROM scenarios s JOIN scenario_versions v ON v.scenario_id=s.scenario_id AND v.version=s.current_version "
                + "WHERE s.scenario_id=:s", p("s", sid))
                : db.row("SELECT scenario_id, version, python_code, code_sha256, generator_version, created_at "
                + "FROM scenario_versions WHERE scenario_id=:s AND version=:v", p("s", sid, "v", version));
        if (r == null) {
            throw ApiException.notFound("scenario " + sid + (version == null ? "" : " v" + version));
        }
        return r;
    }

    @GetMapping("/scenarios/{sid}/versions")
    @RequireRole("viewer")
    public List<Map<String, Object>> versions(@PathVariable String sid) {
        List<Map<String, Object>> vs = db.rows("SELECT version, graph, max_span_sec, code_sha256, generator_version, "
                + "change_note, created_by, created_at FROM scenario_versions WHERE scenario_id=:s ORDER BY version DESC",
                p("s", sid));
        Map<String, Object> prev = null;
        for (int i = vs.size() - 1; i >= 0; i--) {
            Map<String, Object> v = vs.get(i);
            Map<String, Object> g = Json.loadMap(Db.str(v, "graph"));
            v.put("graph", g);
            v.put("diff", prev == null ? null : diff(prev, g));
            prev = g;
        }
        return vs;
    }

    private static Map<String, Map<String, Object>> byId(Object nodes) {
        Map<String, Map<String, Object>> m = new LinkedHashMap<>();
        for (Object o : Objects.requireNonNullElse(Json.asList(nodes), List.of())) {
            Map<String, Object> n = Json.asMap(o);
            m.put(String.valueOf(n.get("id")), n);
        }
        return m;
    }

    private static Map<String, Map<String, Object>> edgesById(Object edges) {
        Map<String, Map<String, Object>> m = new java.util.TreeMap<>();
        for (Object o : Objects.requireNonNullElse(Json.asList(edges), List.of())) {
            Map<String, Object> e = Json.asMap(o);
            m.put(e.get("from") + "->" + e.get("to"), e);
        }
        return m;
    }

    static Map<String, Object> diff(Map<String, Object> a, Map<String, Object> b) {
        Map<String, Map<String, Object>> an = byId(a.get("nodes"));
        Map<String, Map<String, Object>> bn = byId(b.get("nodes"));
        Map<String, Map<String, Object>> ae = edgesById(a.get("edges"));
        Map<String, Map<String, Object>> be = edgesById(b.get("edges"));
        TreeSet<String> added = new TreeSet<>(bn.keySet());
        added.removeAll(an.keySet());
        TreeSet<String> removed = new TreeSet<>(an.keySet());
        removed.removeAll(bn.keySet());
        TreeSet<String> changed = new TreeSet<>();
        for (String k : an.keySet()) {
            if (bn.containsKey(k)) {
                Map<String, Object> x = new HashMap<>(an.get(k));
                Map<String, Object> y = new HashMap<>(bn.get(k));
                x.remove("pos");
                y.remove("pos");
                if (!x.equals(y)) {
                    changed.add(k);
                }
            }
        }
        List<String> eAdded = be.keySet().stream().filter(k -> !ae.containsKey(k)).toList();
        List<String> eRemoved = ae.keySet().stream().filter(k -> !be.containsKey(k)).toList();
        List<String> eChanged = ae.keySet().stream().filter(k -> be.containsKey(k) && !ae.get(k).equals(be.get(k))).toList();
        List<String> settings = new ArrayList<>();
        for (String k : List.of("description", "entity_type", "name", "suppress_for")) {
            if (!Objects.equals(a.get(k), b.get(k))) {
                settings.add(k);
            }
        }
        return Json.obj("nodes_added", new ArrayList<>(added), "nodes_removed", new ArrayList<>(removed),
                "nodes_changed", new ArrayList<>(changed), "edges_added", eAdded, "edges_removed", eRemoved,
                "edges_changed", eChanged, "settings_changed", settings);
    }
}
