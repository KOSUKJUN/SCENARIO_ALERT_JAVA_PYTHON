package com.scenarioalert.engine.api;

import com.scenarioalert.engine.auth.AuthService.User;
import com.scenarioalert.engine.auth.RequireRole;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.ch.ClickHouse.Purpose;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.lifecycle.LifecycleService;
import com.scenarioalert.engine.meta.Fields;
import com.scenarioalert.engine.repo.Records.RuleRecord;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.singlerule.RuleCompiler;
import com.scenarioalert.engine.singlerule.RuleValidator.RuleValidationException;
import com.scenarioalert.engine.singlerule.SnortImporter;
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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import static com.scenarioalert.engine.common.Db.p;

/** 단일룰 API (설계안 9장). 단일룰 탐지는 전부 Java(ClickHouse SQL 변환·실행)다. */
@RestController
@RequestMapping("/api/v1")
public class RulesController {
    private final Db db;
    private final Repo repo;
    private final ClickHouse ch;
    private final LifecycleService lifecycle;

    public RulesController(Db db, Repo repo, ClickHouse ch, LifecycleService lifecycle) {
        this.db = db;
        this.repo = repo;
        this.ch = ch;
        this.lifecycle = lifecycle;
    }

    @GetMapping("/meta/fields")
    @RequireRole("viewer")
    public Map<String, Object> metaFields() {
        Map<String, Object> m = Fields.metaPayload();
        m.put("lists", db.rows("SELECT list_id, kind, scope_org_id, description FROM lists ORDER BY list_id"));
        m.put("asset_tags", db.rows("SELECT DISTINCT tag FROM asset_tags ORDER BY tag").stream()
                .map(r -> Db.str(r, "tag")).toList());
        return m;
    }

    static Map<String, Object> summary(RuleRecord r, Map<String, Object> stats) {
        Map<String, Object> d = r.definition();
        Map<String, Object> entity = Json.asMap(d.get("entity"));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("rule_id", r.ruleId());
        m.put("name", r.name());
        m.put("version", r.version());
        m.put("status", r.status());
        m.put("type", r.type());
        m.put("entity_type", r.entityType());
        m.put("entity_field", entity == null ? null : entity.get("field"));
        m.put("data_tp", d.get("data_tp"));
        m.put("window", d.get("window"));
        m.put("severity", d.getOrDefault("severity", "medium"));
        m.put("alert_on_hit", d.getOrDefault("alert_on_hit", false));
        m.put("schedule_sec", r.scheduleSec());
        m.put("last_evaluated_to", r.lastEvaluatedTo());
        m.put("consecutive_failures", r.consecutiveFailures());
        m.put("warning", r.consecutiveFailures() >= 3);
        m.put("updated_at", r.updatedAt());
        if (stats != null) {
            m.putAll(stats);
        }
        return m;
    }

    @GetMapping("/single-rules")
    @RequireRole("viewer")
    public List<Map<String, Object>> list() {
        return db.tx(() -> {
            List<RuleRecord> rules = repo.listRules();
            Map<String, Map<String, Object>> hits = new HashMap<>();
            db.rows("SELECT rule_id, SUM(hit_count) AS hits_24h, AVG(duration_ms) AS avg_ms, SUM(status!='ok') AS failures_24h "
                    + "FROM rule_runs WHERE started_at >= NOW() - INTERVAL 1 DAY GROUP BY rule_id")
                    .forEach(r -> hits.put(Db.str(r, "rule_id"), r));
            Map<String, Set<String>> used = new HashMap<>();
            db.rows("SELECT f.rule_id, f.scenario_id FROM scenario_rule_refs f JOIN scenarios s ON s.scenario_id=f.scenario_id "
                    + "AND s.current_version=f.version").forEach(f -> used.computeIfAbsent(Db.str(f, "rule_id"),
                    k -> new TreeSet<>()).add(Db.str(f, "scenario_id")));
            List<Map<String, Object>> res = new ArrayList<>();
            for (RuleRecord r : rules) {
                Map<String, Object> h = hits.getOrDefault(r.ruleId(), Map.of());
                res.add(summary(r, Json.obj("hits_24h", Db.lng(h, "hits_24h"), "avg_run_ms", Db.dbl(h, "avg_ms"),
                        "failures_24h", Db.lng(h, "failures_24h"),
                        "used_by", new ArrayList<>(used.getOrDefault(r.ruleId(), Set.of())))));
            }
            return res;
        });
    }

    @PostMapping("/single-rules")
    @ResponseStatus(HttpStatus.CREATED)
    @RequireRole("author")
    public Map<String, Object> create(@RequestBody Map<String, Object> body, User user) {
        Repo.SavedRule s = db.tx(() -> repo.saveRule(Body.map(body, "definition"), user.username(),
                Body.optStr(body, "change_note"), true, null));
        return Json.obj("rule", summary(s.rule(), null), "definition", s.rule().definition(),
                "warnings", s.validation().warningMaps());
    }

    @PostMapping("/single-rules/compile")
    @RequireRole("author")
    public Map<String, Object> compile(@RequestBody Map<String, Object> body) {
        Repo.RuleCheck c = db.tx(() -> repo.checkRule(Body.map(body, "definition")));
        return Json.obj("ok", c.validation().ok(), "errors", c.validation().errorMaps(),
                "warnings", c.validation().warningMaps(), "sql", c.sql());
    }

    /**
     * Snort 룰 텍스트를 단일룰 정의로 바꾸고 각각 검증·SQL 변환까지 해서 돌려준다 (저장 안 함).
     * 화면에서 확인한 뒤 고른 것만 POST /single-rules 로 draft 생성한다.
     */
    @PostMapping("/single-rules/import/snort")
    @RequireRole("author")
    public Map<String, Object> importSnort(@RequestBody Map<String, Object> body) {
        String text = Body.str(body, "text");
        if (text.length() > 1_000_000) {
            throw ApiException.badRequest("한 번에 1MB 까지 가져올 수 있습니다");
        }
        List<String> dtp = body.containsKey("data_tp") ? Body.strings(body, "data_tp") : List.of();
        for (String d : dtp) {
            if (!Fields.ALL.contains(d)) {
                throw ApiException.badRequest("알 수 없는 데이터 유형: " + d);
            }
        }
        String idPrefix = Body.optStr(body, "id_prefix");
        if (idPrefix != null && !idPrefix.isBlank() && !idPrefix.matches("^[A-Z][A-Z0-9_]{0,40}$")) {
            throw ApiException.badRequest("ID 접두어는 대문자로 시작하고 대문자·숫자·_ 만 쓸 수 있습니다 (예: SR_SNORT_)");
        }
        return db.tx(() -> {
            List<String> excl = body.containsKey("exclude_lists") ? Body.strings(body, "exclude_lists")
                    : repo.listExists().test("false_positive_hosts") ? List.of("false_positive_hosts") : List.of();
            SnortImporter.Options opt = new SnortImporter.Options(dtp, Body.optStr(body, "match"), idPrefix, excl);
            List<SnortImporter.Item> items = SnortImporter.convert(text, opt);
            if (items.size() > 2000) {
                throw ApiException.badRequest("한 번에 룰 2,000개까지 가져올 수 있습니다 (현재 " + items.size() + "개)");
            }
            Set<String> existing = new HashSet<>();
            db.rows("SELECT rule_id FROM single_rules").forEach(r -> existing.add(Db.str(r, "rule_id")));
            List<Map<String, Object>> out = new ArrayList<>();
            int ok = 0;
            for (SnortImporter.Item it : items) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("line", it.line());
                m.put("source", it.source());
                m.put("sid", it.sid());
                m.put("notes", it.notes());
                m.put("skipped", it.skipped());
                if (it.definition() != null) {
                    Repo.RuleCheck c = repo.checkRule(it.definition());
                    m.put("definition", it.definition());
                    m.put("ok", c.validation().ok());
                    m.put("errors", c.validation().errorMaps());
                    m.put("warnings", c.validation().warningMaps());
                    m.put("sql", c.sql());
                    m.put("exists", existing.contains(String.valueOf(it.definition().get("id"))));
                    if (c.validation().ok()) {
                        ok++;
                    }
                }
                out.add(m);
            }
            return Json.obj("total", items.size(), "convertible", ok, "items", out);
        });
    }

    /** 초안을 최근 구간(기본 24시간)에 실행해 히트 수, 상위 대상, 시간대별 분포를 돌려준다 (저장 안 함). */
    @PostMapping("/single-rules/preview")
    @RequireRole("author")
    public Map<String, Object> preview(@RequestBody Map<String, Object> body) {
        Map<String, Object> defn = Body.map(body, "definition");
        Object[] holder = new Object[2];
        Repo.RuleCheck c = db.tx(() -> {
            Repo.RuleCheck chk = repo.checkRule(defn);
            if (chk.parsed() == null) {
                throw new RuleValidationException(chk.validation());
            }
            holder[0] = RuleCompiler.compilePreview(chk.parsed(), repo.listLoader());
            return chk;
        });
        RuleCompiler.CompiledRule compiled = (RuleCompiler.CompiledRule) holder[0];
        int hours = Math.max(1, Math.min(Body.intOr(body, "hours", 24), 24 * 7));
        LocalDateTime tTo = Kst.now();
        LocalDateTime tFrom = tTo.minusHours(hours);
        Map<String, Object> params = new LinkedHashMap<>(compiled.params());
        params.put("time_from", Kst.fmt(tFrom));
        params.put("time_to", Kst.fmt(tTo));
        List<Map<String, Object>> hits = ch.query(compiled.sql(), params, Purpose.BACKTEST);
        Map<String, Integer> hourly = new TreeMap<>();
        Map<List<String>, Integer> top = new LinkedHashMap<>();
        Set<List<String>> distinct = new HashSet<>();
        for (Map<String, Object> h : hits) {
            LocalDateTime hb = ClickHouse.time(h, "hit_bucket");
            hourly.merge(String.format("%tF %<tH:00", hb), 1, Integer::sum);
            List<String> k = List.of(ClickHouse.str(h, "org_id"), ClickHouse.str(h, "entity"));
            top.merge(k, 1, Integer::sum);
            distinct.add(k);
            h.put("hit_bucket", hb);
            h.put("first_seen", ClickHouse.time(h, "first_seen"));
            h.put("last_seen", ClickHouse.time(h, "last_seen"));
            h.put("first_win_to", ClickHouse.time(h, "first_win_to"));
        }
        List<Map<String, Object>> topList = top.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(20)
                .map(e -> Json.obj("org_id", e.getKey().get(0), "entity", e.getKey().get(1), "hits", e.getValue())).toList();
        return Json.obj("time_from", tFrom, "time_to", tTo, "total_hits", hits.size(), "distinct_entities", distinct.size(),
                "hourly", hourly.entrySet().stream().map(e -> Json.obj("hour", e.getKey(), "hits", e.getValue())).toList(),
                "top_entities", topList, "samples", hits.subList(Math.max(0, hits.size() - 50), hits.size()),
                "warnings", c.validation().warningMaps(), "sql", c.sql());
    }

    @GetMapping("/single-rules/{ruleId}")
    @RequireRole("viewer")
    public Map<String, Object> get(@PathVariable String ruleId) {
        return db.tx(() -> {
            RuleRecord rec = repo.getRule(ruleId);
            Map<String, Object> sql = db.row("SELECT compiled_sql FROM single_rule_versions WHERE rule_id=:r AND version=:v",
                    p("r", ruleId, "v", rec.version()));
            return Json.obj("rule", summary(rec, null), "definition", rec.definition(),
                    "compiled_sql", sql == null ? "" : sql.get("compiled_sql"),
                    "operation", lifecycle.operationStats("single_rule", ruleId));
        });
    }

    @PutMapping("/single-rules/{ruleId}")
    @RequireRole("author")
    public Map<String, Object> update(@PathVariable String ruleId, @RequestBody Map<String, Object> body, User user) {
        Map<String, Object> defn = new LinkedHashMap<>(Body.map(body, "definition"));
        defn.put("id", ruleId);
        Repo.SavedRule s = db.tx(() -> repo.saveRule(defn, user.username(), Body.optStr(body, "change_note"), false, null));
        return Json.obj("rule", summary(s.rule(), null), "definition", s.rule().definition(),
                "warnings", s.validation().warningMaps());
    }

    @PostMapping("/single-rules/{ruleId}/status")
    @RequireRole("author")
    public Map<String, Object> status(@PathVariable String ruleId, @RequestBody Map<String, Object> body, User user) {
        String target = Body.str(body, "status");
        return db.tx(() -> {
            String cur = repo.getRule(ruleId).status();
            if (!user.has(LifecycleService.requiredRole(cur, target))) {
                throw new ApiException(403, "active 전환은 관리자만 할 수 있습니다");
            }
            lifecycle.changeRuleStatus(ruleId, target, user.username(), false);
            return Json.obj("rule", summary(repo.getRule(ruleId), null));
        });
    }

    @GetMapping("/single-rules/{ruleId}/versions")
    @RequireRole("viewer")
    public List<Map<String, Object>> versions(@PathVariable String ruleId) {
        List<Map<String, Object>> vs = db.rows("SELECT version, definition, change_note, created_by, created_at "
                + "FROM single_rule_versions WHERE rule_id=:r ORDER BY version DESC", p("r", ruleId));
        vs.forEach(v -> v.put("definition", Json.load(Db.str(v, "definition"))));
        return vs;
    }

    @GetMapping("/single-rules/{ruleId}/runs")
    @RequireRole("viewer")
    public List<Map<String, Object>> runs(@PathVariable String ruleId, @RequestParam(defaultValue = "100") int limit) {
        return db.rows("SELECT run_id, version, win_from, win_to, status, hit_count, new_hit_count, duration_ms, error, "
                        + "instance_id, started_at FROM rule_runs WHERE rule_id=:r ORDER BY started_at DESC LIMIT :n",
                p("r", ruleId, "n", Math.min(Math.max(limit, 1), 1000)));
    }

    @GetMapping("/single-rules/{ruleId}/hits")
    @RequireRole("analyst")
    public List<Map<String, Object>> hits(@PathVariable String ruleId, @RequestParam(defaultValue = "24") int hours,
                                          @RequestParam(name = "org_id", required = false) String orgId) {
        LocalDateTime since = Kst.now().minusHours(Math.min(Math.max(hours, 1), 24 * 90));
        Map<String, Object> params = p("r", ruleId, "since", Kst.fmt(since));
        String org = "";
        if (orgId != null && !orgId.isEmpty()) {
            org = "AND org_id = {o:String}";
            params.put("o", orgId);
        }
        List<Map<String, Object>> hs = ch.query("SELECT hit_bucket, rule_version, org_id, entity_type, entity, first_seen, "
                + "last_seen, value, threshold, sample_event_ids, win_to FROM detect.rule_hits FINAL "
                + "WHERE rule_id = {r:String} AND hit_bucket >= {since:DateTime64(3)} " + org
                + " ORDER BY hit_bucket DESC LIMIT 1000", params);
        for (Map<String, Object> h : hs) {
            for (String k : List.of("hit_bucket", "first_seen", "last_seen", "win_to")) {
                h.put(k, ClickHouse.time(h, k));
            }
        }
        return hs;
    }
}
