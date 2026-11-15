package com.scenarioalert.engine.api;

import com.scenarioalert.engine.auth.AuthService.User;
import com.scenarioalert.engine.auth.RequireRole;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.repo.Repo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import static com.scenarioalert.engine.common.Db.p;

/** 경보 조회·판정, 근거 이벤트, 사고처리 시스템 판정 수신. */
@RestController
@RequestMapping("/api/v1")
public class AlertsController {
    static final List<String> VERDICTS = List.of("true_positive", "false_positive", "benign");
    static final String EVENT_COLUMNS = "event_id, mgr_time, event_time, org_id, data_tp, product, src_ip, src_port, dst_ip, "
            + "dst_port, protocol, action, net_direction, signature_name, signature_category, attack, risk, event_count, uri, "
            + "payload, src_asset_tags, dst_asset_tags, src_ti_hit, dst_ti_hit";

    private final Db db;
    private final Repo repo;
    private final ClickHouse ch;

    public AlertsController(Db db, Repo repo, ClickHouse ch) {
        this.db = db;
        this.repo = repo;
        this.ch = ch;
    }

    @GetMapping("/alerts")
    @RequireRole("analyst")
    public Map<String, Object> list(@RequestParam(name = "org_id", required = false) String orgId,
                                    @RequestParam(required = false) String severity,
                                    @RequestParam(name = "source_id", required = false) String sourceId,
                                    @RequestParam(name = "source_type", required = false) String sourceType,
                                    @RequestParam(required = false) String verdict,
                                    @RequestParam(required = false) String entity,
                                    @RequestParam(name = "delivery_status", required = false) String deliveryStatus,
                                    @RequestParam(name = "time_from", required = false) String timeFrom,
                                    @RequestParam(name = "time_to", required = false) String timeTo,
                                    @RequestParam(defaultValue = "100") int limit,
                                    @RequestParam(defaultValue = "0") int offset) {
        List<String> where = new ArrayList<>(List.of("1=1"));
        Map<String, Object> pr = p("n", Math.min(Math.max(limit, 1), 1000), "off", Math.max(offset, 0));
        Object[][] eq = {{"org_id", orgId}, {"source_id", sourceId}, {"source_type", sourceType},
                {"delivery_status", deliveryStatus}};
        for (Object[] c : eq) {
            if (c[1] != null && !((String) c[1]).isEmpty()) {
                where.add(c[0] + " = :" + c[0]);
                pr.put((String) c[0], c[1]);
            }
        }
        if (severity != null && !severity.isEmpty()) {
            List<String> sev = Arrays.stream(severity.split(",")).filter(s -> !s.isEmpty()).toList();
            if (!sev.isEmpty()) {
                where.add("severity IN (:sev)");
                pr.put("sev", sev);
            }
        }
        if (entity != null && !entity.isEmpty()) {
            where.add("entity LIKE :ent");
            pr.put("ent", "%" + entity + "%");
        }
        if ("none".equals(verdict)) {
            where.add("verdict IS NULL");
        } else if (verdict != null && !verdict.isEmpty()) {
            where.add("verdict = :verdict");
            pr.put("verdict", verdict);
        }
        if (timeFrom != null && !timeFrom.isEmpty()) {
            where.add("last_seen >= :tf");
            pr.put("tf", Kst.parse(timeFrom));
        }
        if (timeTo != null && !timeTo.isEmpty()) {
            where.add("first_seen <= :tt");
            pr.put("tt", Kst.parse(timeTo));
        }
        String w = String.join(" AND ", where);
        List<Map<String, Object>> items = db.rows("SELECT alert_id, source_type, source_id, source_version, org_id, entity_type, "
                + "entity, severity, title, alert_node, first_seen, last_seen, hit_count, silent, delivery_status, "
                + "delivery_attempts, case_ref, verdict, created_at, upgraded_at FROM alerts WHERE " + w
                + " ORDER BY created_at DESC LIMIT :n OFFSET :off", pr);
        Map<String, Object> total = db.row("SELECT COUNT(*) AS n FROM alerts WHERE " + w, pr);
        return Json.obj("total", total == null ? 0 : Db.lng(total, "n"), "items", items);
    }

    private Map<String, Object> getAlert(String alertId) {
        Map<String, Object> a = db.row("SELECT * FROM alerts WHERE alert_id=:id", p("id", alertId));
        if (a == null) {
            throw new ApiException(404, "경보가 없습니다");
        }
        a.put("path", Json.load(Db.str(a, "path")));
        return a;
    }

    @GetMapping("/alerts/{alertId}")
    @RequireRole("analyst")
    public Map<String, Object> get(@PathVariable String alertId) {
        return db.tx(() -> {
            Map<String, Object> a = getAlert(alertId);
            a.put("asset", repo.assetInfo(Db.str(a, "org_id"), Db.str(a, "entity")));
            Object graph = null;
            if ("scenario".equals(a.get("source_type"))) {
                Map<String, Object> g = db.row("SELECT graph FROM scenario_versions WHERE scenario_id=:s AND version=:v",
                        p("s", a.get("source_id"), "v", a.get("source_version")));
                graph = g == null ? null : Json.load(Db.str(g, "graph"));
            }
            a.put("graph", graph);
            a.put("exception_lists", db.rows("SELECT list_id, kind, description FROM lists WHERE kind IN ('ip','cidr') "
                    + "ORDER BY list_id"));
            return a;
        });
    }

    /** 경로에 남은 근거 이벤트 ID 를 ClickHouse 에서 조회 (mgr_time 범위를 먼저 건다). */
    @GetMapping("/alerts/{alertId}/events")
    @RequireRole("analyst")
    public Map<String, Object> events(@PathVariable String alertId) {
        Map<String, Object> a = getAlert(alertId);
        Map<String, List<String>> byNode = new LinkedHashMap<>();
        for (Object o : Json.asList(a.get("path"))) {
            Map<String, Object> s = Json.asMap(o);
            List<String> ids = Json.strings(s.get("sample_event_ids"));
            if (!ids.isEmpty()) {
                byNode.computeIfAbsent(String.valueOf(s.getOrDefault("node", "")), k -> new ArrayList<>()).addAll(ids);
            }
        }
        TreeSet<String> all = new TreeSet<>();
        byNode.values().forEach(all::addAll);
        if (all.isEmpty()) {
            return Json.obj("events", List.of(), "by_node", Map.of());
        }
        List<Map<String, Object>> evs = ch.query("SELECT " + EVENT_COLUMNS + " FROM detect.v_events "
                        + "WHERE mgr_time >= {f:DateTime64(3)} AND mgr_time <= {t:DateTime64(3)} AND has({ids:Array(String)}, event_id) "
                        + "ORDER BY mgr_time LIMIT 1000",
                p("f", Kst.fmt(Db.time(a, "first_seen").minusDays(1)), "t", Kst.fmt(Db.time(a, "last_seen").plusDays(1)),
                        "ids", new ArrayList<>(all)));
        for (Map<String, Object> e : evs) {
            e.put("mgr_time", ClickHouse.time(e, "mgr_time"));
            e.put("event_time", ClickHouse.time(e, "event_time"));
        }
        return Json.obj("events", evs, "by_node", byNode);
    }

    private void addException(Map<String, Object> a, String listId, String actor, String note) {
        Map<String, Object> meta = db.row("SELECT kind, scope_org_id FROM lists WHERE list_id=:l", p("l", listId));
        if (meta == null) {
            throw new ApiException(404, "리스트가 없습니다");
        }
        String kind = Db.str(meta, "kind");
        if (!List.of("ip", "cidr", "string").contains(kind)) {
            throw new ApiException(400, "예외 리스트는 ip, cidr, string 종류여야 합니다");
        }
        String value = "cidr".equals(kind) ? a.get("entity") + "/32" : Db.str(a, "entity");
        String n = note != null ? note : "경보 " + a.get("alert_id") + " 오탐 처리";
        db.execute("INSERT INTO list_items (list_id, value, note) VALUES (:l, :v, :n) ON DUPLICATE KEY UPDATE note=VALUES(note)",
                p("l", listId, "v", value, "n", n.length() > 500 ? n.substring(0, 500) : n));
        db.audit(actor, "list.item.add", listId, Json.obj("value", value, "from_alert", Db.str(a, "alert_id")));
    }

    @PostMapping("/alerts/{alertId}/verdict")
    @RequireRole("analyst")
    public Map<String, Object> verdict(@PathVariable String alertId, @RequestBody Map<String, Object> body, User user) {
        String v = Body.str(body, "verdict");
        if (!VERDICTS.contains(v)) {
            throw new ApiException(400, "판정은 " + String.join(", ", VERDICTS) + " 중 하나입니다");
        }
        String note = Body.optStr(body, "note");
        String exList = Body.optStr(body, "exception_list");
        db.txRun(() -> {
            Map<String, Object> a = getAlert(alertId);
            db.execute("UPDATE alerts SET verdict=:v, verdict_note=:n, verdict_at=NOW(3) WHERE alert_id=:id",
                    p("v", v, "n", note, "id", alertId));
            if (exList != null && !exList.isEmpty()) {
                addException(a, exList, user.username(), note);
            }
            db.audit(user.username(), "alert.verdict", alertId, body);
        });
        if (exList != null && !exList.isEmpty()) {
            ch.reloadDictionaries(List.of("dict_list_items"));
        }
        return Map.of("ok", true);
    }

    @PostMapping("/alerts/{alertId}/exception")
    @RequireRole("analyst")
    public Map<String, Object> exception(@PathVariable String alertId, @RequestBody Map<String, Object> body, User user) {
        String listId = Body.str(body, "list_id");
        db.txRun(() -> addException(getAlert(alertId), listId, user.username(), Body.optStr(body, "note")));
        ch.reloadDictionaries(List.of("dict_list_items"));
        return Map.of("ok", true);
    }

    @PostMapping("/alerts/{alertId}/redeliver")
    @RequireRole("analyst")
    public Map<String, Object> redeliver(@PathVariable String alertId, User user) {
        db.txRun(() -> {
            Map<String, Object> a = getAlert(alertId);
            if (Db.bool(a, "silent")) {
                throw new ApiException(400, "silent 경보는 전달하지 않습니다");
            }
            db.execute("UPDATE alerts SET delivery_status='pending', delivery_attempts=0, next_delivery_at=NULL "
                    + "WHERE alert_id=:id", p("id", alertId));
            db.audit(user.username(), "alert.redeliver", alertId, null);
        });
        return Map.of("ok", true);
    }

    /** 사고처리 시스템이 종결 판정을 돌려주는 수신점 (서비스 토큰). */
    @PostMapping("/hooks/case-verdict")
    @RequireRole("service")
    public Map<String, Object> caseVerdict(@RequestBody Map<String, Object> body) {
        String v = Body.str(body, "verdict");
        if (!VERDICTS.contains(v)) {
            throw new ApiException(400, "판정은 " + String.join(", ", VERDICTS) + " 중 하나입니다");
        }
        String alertId = Body.optStr(body, "alert_id");
        String caseRef = Body.optStr(body, "case_ref");
        db.txRun(() -> {
            Map<String, Object> a;
            if (alertId != null && !alertId.isEmpty()) {
                a = db.row("SELECT alert_id FROM alerts WHERE alert_id=:id", p("id", alertId));
            } else if (caseRef != null && !caseRef.isEmpty()) {
                a = db.row("SELECT alert_id FROM alerts WHERE case_ref=:c", p("c", caseRef));
            } else {
                throw new ApiException(400, "alert_id 또는 case_ref 가 필요합니다");
            }
            if (a == null) {
                throw new ApiException(404, "경보가 없습니다");
            }
            db.execute("UPDATE alerts SET verdict=:v, verdict_note=:n, verdict_at=NOW(3), case_ref=COALESCE(:c, case_ref) "
                    + "WHERE alert_id=:id", p("v", v, "n", Body.optStr(body, "note"), "c", caseRef, "id", Db.str(a, "alert_id")));
            db.audit("case-system", "alert.verdict", Db.str(a, "alert_id"), body);
        });
        return Map.of("ok", true);
    }
}
