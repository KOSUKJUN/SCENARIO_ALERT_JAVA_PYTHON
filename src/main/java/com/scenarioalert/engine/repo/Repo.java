package com.scenarioalert.engine.repo;

import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.d3fend.D3fendService;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.repo.Records.RuleRecord;
import com.scenarioalert.engine.repo.Records.ScenarioRecord;
import com.scenarioalert.engine.scenario.EvalModels.ScenarioProgram;
import com.scenarioalert.engine.scenario.GraphValidation;
import com.scenarioalert.engine.scenario.GraphValidator;
import com.scenarioalert.engine.scenario.GraphValidator.RuleRef;
import com.scenarioalert.engine.scenario.ScenarioCodeGenerator;
import com.scenarioalert.engine.scenario.ScenarioCodeGenerator.GeneratedCode;
import com.scenarioalert.engine.scenario.ScenarioCodeStore;
import com.scenarioalert.engine.singlerule.ParsedRule;
import com.scenarioalert.engine.singlerule.RuleCompiler;
import com.scenarioalert.engine.singlerule.RuleCompiler.ListInfo;
import com.scenarioalert.engine.singlerule.RuleValidation;
import com.scenarioalert.engine.singlerule.RuleValidator;
import com.scenarioalert.engine.singlerule.RuleValidator.RuleValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.function.Predicate;

import static com.scenarioalert.engine.common.Db.p;

/**
 * MariaDB 저장소 (룰·순서도·리스트·자산). 트랜잭션은 호출자가 연다 ({@link Db#tx}).
 * 순서도를 저장하면 버전마다 Python 평가 코드를 생성해 scenario_versions 에 함께 저장한다.
 */
@Component
public class Repo {
    private static final Logger log = LoggerFactory.getLogger(Repo.class);
    private final Db db;
    private final ScenarioCodeStore codeStore;
    private final AttackService attack;
    private final D3fendService d3fend;

    public Repo(Db db, ScenarioCodeStore codeStore, AttackService attack, D3fendService d3fend) {
        this.db = db;
        this.codeStore = codeStore;
        this.attack = attack;
        this.d3fend = d3fend;
    }

    // ---------------------------------------------------------------- 리스트
    public Predicate<String> listExists() {
        Set<String> ids = new HashSet<>();
        db.rows("SELECT list_id FROM lists").forEach(r -> ids.add(Db.str(r, "list_id")));
        return ids::contains;
    }

    public Function<String, ListInfo> listLoader() {
        Map<String, ListInfo> cache = new HashMap<>();
        return lid -> cache.computeIfAbsent(lid, id -> {
            Map<String, Object> meta = db.row("SELECT list_id, kind, scope_org_id FROM lists WHERE list_id=:l", p("l", id));
            if (meta == null) {
                throw ApiException.notFound("list " + id);
            }
            List<String> items = db.rows("SELECT value FROM list_items WHERE list_id=:l AND (expires_at IS NULL OR "
                    + "expires_at > NOW()) ORDER BY value", p("l", id)).stream().map(r -> Db.str(r, "value")).toList();
            return new ListInfo(id, Db.str(meta, "kind"), Db.str(meta, "scope_org_id"), items);
        });
    }

    // ---------------------------------------------------------------- 단일룰
    private static final String RULE_SELECT = "SELECT r.*, v.definition FROM single_rules r "
            + "JOIN single_rule_versions v ON v.rule_id = r.rule_id AND v.version = r.current_version";

    private static RuleRecord ruleFromRow(Map<String, Object> r) {
        return new RuleRecord(Db.str(r, "rule_id"), Db.str(r, "name"), Db.integer(r, "current_version"),
                Db.str(r, "status"), Db.str(r, "type"), Db.str(r, "entity_type"), Db.integer(r, "schedule_sec"),
                Json.loadMap(Db.str(r, "definition")), Db.time(r, "last_evaluated_to"), Db.time(r, "next_run_at"),
                Db.integer(r, "consecutive_failures"), Db.time(r, "updated_at"));
    }

    public RuleRecord getRule(String ruleId, boolean forUpdate) {
        Map<String, Object> r = db.row(RULE_SELECT + " WHERE r.rule_id=:id" + (forUpdate ? " FOR UPDATE" : ""),
                p("id", ruleId));
        if (r == null) {
            throw ApiException.notFound("rule " + ruleId);
        }
        return ruleFromRow(r);
    }

    public RuleRecord getRule(String ruleId) {
        return getRule(ruleId, false);
    }

    public List<RuleRecord> listRules() {
        return db.rows(RULE_SELECT + " ORDER BY r.rule_id").stream().map(Repo::ruleFromRow).toList();
    }

    public record RuleCheck(RuleValidation validation, ParsedRule parsed, String sql) {
    }

    /** 검증 + 컴파일 (저장하지 않음). 반환: (검증 결과, 파싱 결과, 화면용 SQL). */
    public RuleCheck checkRule(Object defn) {
        RuleValidator.Result vr = RuleValidator.validate(defn, listExists());
        if (vr.parsed() == null) {
            return new RuleCheck(vr.validation(), null, null);
        }
        // ATT&CK 기법이 활성 버전에 있는지 (없거나 폐기면 오류, 사용 중단이면 경고)
        attack.checkRefs(vr.parsed().raw().get("attack"), (isErr, msg) -> {
            if (isErr) {
                vr.validation().err("attack", msg);
            } else {
                vr.validation().warn("attack", msg);
            }
        });
        // 지정 대응방책(D3FEND 기법)이 활성 버전에 있는지
        d3fend.checkRefs(vr.parsed().raw().get("d3fend"), (isErr, msg) -> {
            if (isErr) {
                vr.validation().err("d3fend", msg);
            } else {
                vr.validation().warn("d3fend", msg);
            }
        });
        if (!vr.validation().ok()) {
            return new RuleCheck(vr.validation(), null, null);
        }
        try {
            RuleCompiler.CompiledRule c = RuleCompiler.compileRealtime(vr.parsed(), listLoader());
            return new RuleCheck(vr.validation(), vr.parsed(), RuleCompiler.renderForDisplay(c));
        } catch (ApiException e) {
            vr.validation().err("filter", "리스트를 찾을 수 없습니다: " + e.getMessage());
            return new RuleCheck(vr.validation(), null, null);
        }
    }

    public record SavedRule(RuleRecord rule, RuleValidation validation) {
    }

    /** 생성 또는 새 버전. 정의의 status 는 무시하고 상태는 별도 전환 API 로만 바꾼다. */
    public SavedRule saveRule(Map<String, Object> defnIn, String actor, String changeNote, Boolean create, String status) {
        Map<String, Object> defn = Json.copy(defnIn);
        defn.remove("status");
        RuleCheck chk = checkRule(defn);
        if (chk.parsed() == null) {
            throw new RuleValidationException(chk.validation());
        }
        ParsedRule parsed = chk.parsed();
        Map<String, Object> existing = db.row("SELECT rule_id, current_version, status, entity_type FROM single_rules "
                + "WHERE rule_id=:id FOR UPDATE", p("id", parsed.id()));
        if (Boolean.TRUE.equals(create) && existing != null) {
            throw ApiException.conflict("이미 있는 룰입니다: " + parsed.id());
        }
        if (Boolean.FALSE.equals(create) && existing == null) {
            throw ApiException.notFound("rule " + parsed.id());
        }
        if (existing != null) {
            if ("active".equals(Db.str(existing, "status")) && !parsed.entityType().equals(Db.str(existing, "entity_type"))) {
                throw ApiException.conflict("운영 중인 룰의 대상 유형은 바꿀 수 없습니다");
            }
            int ver = Db.integer(existing, "current_version") + 1;
            db.execute("INSERT INTO single_rule_versions (rule_id, version, definition, compiled_sql, change_note, created_by) "
                            + "VALUES (:id, :v, :d, :sql, :note, :by)",
                    p("id", parsed.id(), "v", ver, "d", Json.dump(defn), "sql", chk.sql(), "note", changeNote, "by", actor));
            db.execute("UPDATE single_rules SET current_version=:v, name=:n, type=:t, entity_type=:e, schedule_sec=:s "
                            + "WHERE rule_id=:id",
                    p("id", parsed.id(), "v", ver, "n", parsed.name(), "t", parsed.type(), "e", parsed.entityType(),
                            "s", parsed.scheduleSec()));
            db.audit(actor, "single_rule.update", parsed.id(), Json.obj("version", ver, "note", changeNote));
        } else {
            db.execute("INSERT INTO single_rules (rule_id, name, current_version, type, entity_type, status, schedule_sec, "
                            + "created_by) VALUES (:id, :n, 1, :t, :e, :st, :s, :by)",
                    p("id", parsed.id(), "n", parsed.name(), "t", parsed.type(), "e", parsed.entityType(),
                            "st", status == null ? "draft" : status, "s", parsed.scheduleSec(), "by", actor));
            db.execute("INSERT INTO single_rule_versions (rule_id, version, definition, compiled_sql, change_note, created_by) "
                            + "VALUES (:id, 1, :d, :sql, :note, :by)",
                    p("id", parsed.id(), "d", Json.dump(defn), "sql", chk.sql(),
                            "note", changeNote == null ? "생성" : changeNote, "by", actor));
            db.audit(actor, "single_rule.create", parsed.id(), Json.obj("name", parsed.name()));
        }
        return new SavedRule(getRule(parsed.id()), chk.validation());
    }

    public Function<String, RuleRef> ruleRefLookup() {
        Map<String, RuleRef> refs = new HashMap<>();
        db.rows("SELECT rule_id, entity_type, status FROM single_rules").forEach(r -> refs.put(Db.str(r, "rule_id"),
                new RuleRef(Db.str(r, "rule_id"), Db.str(r, "entity_type"), Db.str(r, "status"))));
        return refs::get;
    }

    // ---------------------------------------------------------------- 시나리오
    private static final String SC_SELECT = "SELECT s.*, v.graph, v.max_span_sec, v.python_code, v.code_sha256, "
            + "v.generator_version FROM scenarios s "
            + "JOIN scenario_versions v ON v.scenario_id = s.scenario_id AND v.version = s.current_version";

    private static ScenarioRecord scFromRow(Map<String, Object> r) {
        return new ScenarioRecord(Db.str(r, "scenario_id"), Db.str(r, "name"), Db.integer(r, "current_version"),
                Db.str(r, "status"), Db.str(r, "entity_type"), Json.loadMap(Db.str(r, "graph")),
                Db.integer(r, "max_span_sec"), Db.str(r, "python_code"), Db.str(r, "code_sha256"),
                Db.str(r, "generator_version"), Db.time(r, "updated_at"));
    }

    public ScenarioRecord getScenario(String sid) {
        Map<String, Object> r = db.row(SC_SELECT + " WHERE s.scenario_id=:id", p("id", sid));
        if (r == null) {
            throw ApiException.notFound("scenario " + sid);
        }
        return scFromRow(r);
    }

    public List<ScenarioRecord> listScenarios() {
        return db.rows(SC_SELECT + " ORDER BY s.scenario_id").stream().map(Repo::scFromRow).toList();
    }

    public List<ScenarioRecord> scenariosForRule(String ruleId) {
        return db.rows(SC_SELECT + " JOIN scenario_rule_refs f ON f.scenario_id = s.scenario_id AND f.version = s.current_version"
                + " WHERE f.rule_id = :r AND s.status IN ('silent','active')", p("r", ruleId)).stream()
                .map(Repo::scFromRow).toList();
    }

    public GraphValidation checkGraph(Object graph, List<String> requireStatus) {
        GraphValidation res = GraphValidator.validate(graph, ruleRefLookup(), requireStatus);
        // 경보 노드의 ATT&CK 기법이 활성 버전에 있는지
        Map<String, Object> g = Json.asMap(graph);
        if (g != null) {
            for (Object o : Json.asList(g.get("nodes"))) {
                Map<String, Object> n = Json.asMap(o);
                if (n != null && "alert".equals(n.get("type")) && AttackService.formatError(n.get("attack")) == null) {
                    String nid = String.valueOf(n.get("id"));
                    attack.checkRefs(n.get("attack"), (isErr, msg) -> {
                        if (isErr) {
                            res.err("node", nid, msg);
                        } else {
                            res.warn("node", nid, msg);
                        }
                    });
                }
                if (n != null && "alert".equals(n.get("type")) && D3fendService.formatError(n.get("d3fend")) == null) {
                    String nid = String.valueOf(n.get("id"));
                    d3fend.checkRefs(n.get("d3fend"), (isErr, msg) -> {
                        if (isErr) {
                            res.err("node", nid, msg);
                        } else {
                            res.warn("node", nid, msg);
                        }
                    });
                }
            }
        }
        return res;
    }

    public GraphValidation checkGraph(Object graph) {
        return checkGraph(graph, null);
    }

    /** 저장 전 초안을 시뮬레이션하기 위한 코드 (같은 생성기, 파일은 _drafts/). */
    public ScenarioProgram draftProgram(Map<String, Object> graph, GraphValidation res) {
        GeneratedCode gc = ScenarioCodeGenerator.generate(graph, 0, res.maxSpanSec);
        String sid = graph.get("id") instanceof String s ? s : "DRAFT";
        return new ScenarioProgram(sid, 0, gc.code(), gc.sha256(), true);
    }

    public record SavedScenario(ScenarioRecord scenario, GraphValidation validation) {
    }

    public SavedScenario saveScenario(Map<String, Object> graphIn, String actor, String changeNote, Boolean create,
                                      String status) {
        Map<String, Object> graph = Json.copy(graphIn);
        graph.remove("status");
        GraphValidation res = checkGraph(graph);
        if (!res.ok()) {
            throw new GraphValidation.GraphValidationException(res);
        }
        String sid = (String) graph.get("id");
        Map<String, Object> existing = db.row("SELECT current_version FROM scenarios WHERE scenario_id=:id FOR UPDATE",
                p("id", sid));
        if (Boolean.TRUE.equals(create) && existing != null) {
            throw ApiException.conflict("이미 있는 순서도입니다: " + sid);
        }
        if (Boolean.FALSE.equals(create) && existing == null) {
            throw ApiException.notFound("scenario " + sid);
        }
        int ver = existing != null ? Db.integer(existing, "current_version") + 1 : 1;
        // 시나리오 버전마다 Python 평가 코드를 생성한다
        GeneratedCode gc = ScenarioCodeGenerator.generate(graph, ver, res.maxSpanSec);
        if (existing != null) {
            db.execute("UPDATE scenarios SET current_version=:v, name=:n, entity_type=:e WHERE scenario_id=:id",
                    p("v", ver, "n", graph.get("name"), "e", graph.get("entity_type"), "id", sid));
        } else {
            db.execute("INSERT INTO scenarios (scenario_id, name, current_version, entity_type, status, created_by) "
                            + "VALUES (:id, :n, 1, :e, :st, :by)",
                    p("id", sid, "n", graph.get("name"), "e", graph.get("entity_type"),
                            "st", status == null ? "draft" : status, "by", actor));
        }
        db.execute("INSERT INTO scenario_versions (scenario_id, version, graph, max_span_sec, python_code, code_sha256, "
                        + "generator_version, change_note, created_by) VALUES (:id, :v, :g, :span, :code, :sha, :gen, :note, :by)",
                p("id", sid, "v", ver, "g", Json.dump(graph), "span", res.maxSpanSec, "code", gc.code(), "sha", gc.sha256(),
                        "gen", ScenarioCodeGenerator.GENERATOR, "note", changeNote, "by", actor));
        for (String rid : new TreeSet<>(res.ruleRefs)) {
            db.execute("INSERT INTO scenario_rule_refs (scenario_id, version, rule_id) VALUES (:s, :v, :r)",
                    p("s", sid, "v", ver, "r", rid));
        }
        db.audit(actor, existing != null ? "scenario.update" : "scenario.create", sid,
                Json.obj("version", ver, "note", changeNote, "code_sha256", gc.sha256()));
        ScenarioRecord rec = getScenario(sid);
        try {
            codeStore.ensure(rec.program());  // 파일은 캐시: 실패해도 평가 때 다시 만든다
        } catch (RuntimeException e) {
            log.warn("scenario code file write failed for {} v{}: {}", sid, ver, e.getMessage());
        }
        return new SavedScenario(rec, res);
    }

    // ---------------------------------------------------------------- 자산
    public Set<String> assetTags(String orgId, String ip) {
        Set<String> out = new LinkedHashSet<>();
        db.rows("SELECT tag FROM asset_tags WHERE org_id=:o AND ip=:ip ORDER BY tag", p("o", orgId, "ip", ip))
                .forEach(r -> out.add(Db.str(r, "tag")));
        return out;
    }

    public Map<String, Object> assetInfo(String orgId, String ip) {
        Map<String, Object> a = db.row("SELECT purpose, os, holds_sensitive FROM assets WHERE org_id=:o AND ip=:ip",
                p("o", orgId, "ip", ip));
        if (a == null) {
            return null;
        }
        a.put("tags", new TreeSet<>(assetTags(orgId, ip)));
        return a;
    }
}
