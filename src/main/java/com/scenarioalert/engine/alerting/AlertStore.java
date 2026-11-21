package com.scenarioalert.engine.alerting;

import com.scenarioalert.engine.InitService;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.ch.ClickHouse.Purpose;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 경보 본문 저장소: ClickHouse codlog.alert_integrated_all (2026-11-21).
 *
 * <p>이 시스템의 경보 본문(제목, 등급, 최초·최종 시각, 횟수, IP·포트·장비, 그룹 코드)은 이 테이블에만 있다.
 * MariaDB alert_state 에는 같은 ID 로 억제 상태·경로·판정·전달 상태·ATT&CK·D3FEND 만 둔다.</p>
 *
 * <ul>
 *   <li>_data_type: 시나리오 경보 'SCENARIO', 이벤트 탐지모듈 단독 경보 'EVENT_MODULE' (장비 유형 경보와 섞이지 않는다)</li>
 *   <li>정렬 키(= 중복 정리 키)가 (window_ms, _data_type, attack, risk) 다. window_ms 는 최초 시각의 1시간 구간 시작으로 고정해
 *       같은 경보를 다시 넣으면(_collect_time 이 늦은 행) 그 행이 남는다. 등급이 오르면 키가 바뀌므로 이전 행을 지우고 넣는다.</li>
 *   <li>같은 키에 다른 경보가 이미 있으면(같은 시간·같은 제목·같은 등급, 다른 기관) 제목 뒤에 기관을 붙여 덮어쓰지 않게 한다.</li>
 *   <li>포트·국가·장비·조치·에이전트는 경로의 첫 근거 이벤트에서 가져온다. 대상 IP 는 첫 모듈의 대상 필드(src_ip/dst_ip) 칸에 넣는다.</li>
 *   <li>rull_grp_cd = 시나리오 그룹 코드(만들 때의 값), group_cd / group_nm = 대상 기관 코드 / 기관명.</li>
 * </ul>
 */
@Component
public class AlertStore {
    private static final Logger log = LoggerFactory.getLogger(AlertStore.class);
    public static final String TABLE = "codlog.alert_integrated_all";
    public static final String DT_SCENARIO = "SCENARIO";
    public static final String DT_MODULE = "EVENT_MODULE";
    static final List<String> COLUMNS = List.of("_alert_cd", "_collect_time", "_data_type", "event_time", "event_sdt", "event_edt",
            "window_ms", "attack", "risk", "max_lvl", "rull_grp_cd", "group_cd", "group_nm", "count", "src_ip", "src_port", "src_iso",
            "src_lat", "src_lng", "city",
            "dst_ip", "dst_port", "action", "product", "origin_ip", "origin_id", "distance", "tmuser", "set_id", "fields");
    static final String SELECT = String.join(", ", COLUMNS);

    /** 경보 본문 (ClickHouse 한 행이 되는 값). */
    public record Content(String alertId, String sourceType, String sourceId, int sourceVersion, String orgId, String entityType,
                          String entity, String severity, String title, String alertNode, String playbook,
                          List<Map<String, Object>> path, LocalDateTime firstSeen, LocalDateTime lastSeen, long count,
                          boolean silent, List<String> attackIds) {
    }

    private final ClickHouse ch;
    private final Db db;

    public AlertStore(ClickHouse ch, Db db) {
        this.ch = ch;
        this.db = db;
    }

    // ---------------------------------------------------------------- 값 변환
    /** 최초 시각의 1시간 구간 시작 (epoch ms, KST). */
    public static long windowMs(LocalDateTime firstSeen) {
        return firstSeen.truncatedTo(ChronoUnit.HOURS).atOffset(Kst.OFFSET).toInstant().toEpochMilli();
    }

    public static String risk(String severity) {
        return severity == null ? "" : severity.toUpperCase(Locale.ROOT);
    }

    public static Integer level(String severity) {
        return switch (severity == null ? "" : severity) {
            case "low" -> 1;
            case "medium" -> 2;
            case "high" -> 3;
            case "critical" -> 4;
            default -> null;
        };
    }

    public static String dataType(String sourceType) {
        return "scenario".equals(sourceType) ? DT_SCENARIO : DT_MODULE;
    }

    static String ipv6(String ip) {
        if (ip == null || ip.isBlank()) {
            return null;
        }
        return ip.contains(":") ? ip : "::ffff:" + ip;
    }

    static String ipv4(Object v) {
        return v == null ? null : String.valueOf(v).replaceFirst("^::ffff:", "");
    }

    // ---------------------------------------------------------------- 쓰기
    /** 새 경보 (또는 등급 상향으로 키가 바뀐 경보) 를 넣는다. */
    public void put(Content c, long windowMs, LocalDateTime now) {
        Map<String, Object> row = new LinkedHashMap<>();
        String dt = dataType(c.sourceType());
        String title = uniqueTitle(c, windowMs, dt);
        row.put("_alert_cd", c.alertId());
        row.put("_collect_time", Kst.fmt(now));
        row.put("_data_type", dt);
        row.put("event_time", Kst.fmt(c.lastSeen()));
        row.put("event_sdt", Kst.fmt(c.firstSeen()));
        row.put("event_edt", Kst.fmt(c.lastSeen()));
        row.put("window_ms", windowMs);
        row.put("attack", title);
        row.put("risk", risk(c.severity()));
        row.put("max_lvl", level(c.severity()));
        // 룰 그룹 코드 = 시나리오 그룹 코드, CODPRO 그룹 = 경보 대상 기관 (코드·이름)
        row.put("rull_grp_cd", groupCode(c.sourceType(), c.sourceId()));
        row.put("group_cd", c.orgId() == null ? "" : c.orgId());
        row.put("group_nm", orgName(c.orgId()));
        row.put("count", Math.max(1, c.count()));
        row.put("tmuser", author(c.sourceType(), c.sourceId()));
        row.put("set_id", null);
        row.put("distance", null);
        row.put("city", null);
        enrich(row, c);
        row.put("fields", fields(c));
        ch.insert(TABLE, COLUMNS, List.of(row), Purpose.REALTIME);
    }

    /** 같은 키로 다시 넣어 횟수·최종 시각(과 ATT&CK)을 갱신한다. 행이 없으면 false. */
    public boolean touch(String alertId, long windowMs, LocalDateTime lastSeen, List<String> attackIds, LocalDateTime now) {
        Map<String, Object> row = find(alertId, windowMs);
        if (row == null) {
            return false;
        }
        LocalDateTime edt = ClickHouse.time(row, "event_edt");
        LocalDateTime ls = edt == null || lastSeen.isAfter(edt) ? lastSeen : edt;
        row.put("_collect_time", Kst.fmt(now));
        row.put("event_time", Kst.fmt(ls));
        row.put("event_edt", Kst.fmt(ls));
        row.put("event_sdt", Kst.fmt(Objects.requireNonNull(ClickHouse.time(row, "event_sdt"))));
        row.put("count", (long) ClickHouse.num(row, "count") + 1);
        // group_cd·group_nm 이 생기기 전에 넣은 행이면 대상 기관으로 채운다
        Object org = Json.asMap(row.get("fields")) == null ? null : Json.asMap(row.get("fields")).get("org_id");
        if ((row.get("group_cd") == null || String.valueOf(row.get("group_cd")).isEmpty()) && org != null) {
            row.put("group_cd", String.valueOf(org));
            row.put("group_nm", orgName(String.valueOf(org)));
        }
        if (attackIds != null) {
            Map<String, Object> f = new LinkedHashMap<>(Json.asMap(row.get("fields")));
            f.put("attack", attackIds);
            row.put("fields", f);
        }
        ch.insert(TABLE, COLUMNS, List.of(row), Purpose.REALTIME);
        return true;
    }

    public void delete(String alertId, long windowMs) {
        ch.command("DELETE FROM " + TABLE + " WHERE window_ms = {w:UInt64} AND _alert_cd = {id:String}",
                p("w", windowMs, "id", alertId), Purpose.REALTIME);
    }

    /** 개발 환경 초기화: 이 시스템이 넣은 경보만 지운다 (장비 유형 경보는 그대로). */
    public void deleteAllOurs() {
        try {
            ch.command("DELETE FROM " + TABLE + " WHERE _data_type IN ('" + DT_SCENARIO + "', '" + DT_MODULE + "')", Map.of(), Purpose.ADMIN);
        } catch (RuntimeException e) {
            log.warn("alert table cleanup failed: {}", e.getMessage());
        }
    }

    // ---------------------------------------------------------------- 읽기
    public Map<String, Object> find(String alertId, long windowMs) {
        List<Map<String, Object>> r = ch.query("SELECT " + SELECT + " FROM " + TABLE + " FINAL WHERE window_ms = {w:UInt64} "
                + "AND _alert_cd = {id:String} ORDER BY _collect_time DESC LIMIT 1", p("w", windowMs, "id", alertId));
        return r.isEmpty() ? null : r.get(0);
    }

    /** 여러 경보를 한 번에 (ID → 행). windows 는 alert_state.ch_window_ms 들. */
    public Map<String, Map<String, Object>> findMany(List<String> alertIds, List<Long> windows) {
        Map<String, Map<String, Object>> out = new HashMap<>();
        if (alertIds.isEmpty()) {
            return out;
        }
        for (Map<String, Object> r : ch.query("SELECT " + SELECT + " FROM " + TABLE + " FINAL WHERE window_ms IN {ws:Array(UInt64)} "
                        + "AND _alert_cd IN {ids:Array(String)}",
                p("ws", new ArrayList<>(new TreeSet<>(windows)), "ids", alertIds))) {
            Map<String, Object> prev = out.get(ClickHouse.str(r, "_alert_cd"));
            if (prev == null || String.valueOf(r.get("_collect_time")).compareTo(String.valueOf(prev.get("_collect_time"))) > 0) {
                out.put(ClickHouse.str(r, "_alert_cd"), r);
            }
        }
        return out;
    }

    /** ClickHouse 행 → API 가 쓰던 경보 필드 이름 (title, first_seen, hit_count, playbook ...). */
    public static Map<String, Object> toApi(Map<String, Object> row) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (row == null) {
            m.put("title", "(경보 본문 없음)");
            return m;
        }
        Map<String, Object> f = Json.asMap(row.get("fields"));
        m.put("title", row.get("attack"));
        m.put("first_seen", Kst.iso(ClickHouse.time(row, "event_sdt")));
        m.put("ch_last_seen", Kst.iso(ClickHouse.time(row, "event_edt")));
        m.put("hit_count", (long) ClickHouse.num(row, "count"));
        m.put("playbook", f == null ? null : f.get("playbook"));
        m.put("rull_grp_cd", row.get("rull_grp_cd"));
        m.put("group_cd", row.get("group_cd"));
        m.put("group_nm", row.get("group_nm"));
        m.put("risk", row.get("risk"));
        m.put("data_type", row.get("_data_type"));
        m.put("src_ip", ipv4(row.get("src_ip")));
        m.put("src_port", row.get("src_port"));
        m.put("src_iso", row.get("src_iso"));
        m.put("dst_ip", ipv4(row.get("dst_ip")));
        m.put("dst_port", row.get("dst_port"));
        m.put("action", row.get("action"));
        m.put("product", row.get("product"));
        m.put("origin_id", row.get("origin_id"));
        return m;
    }

    // ---------------------------------------------------------------- 이전 경보 옮기기
    /**
     * Flyway V7 이 남긴 alerts_legacy(이전 MariaDB 경보) 를 ClickHouse 로 옮기고, 옮긴 행을 지운다. 표가 없으면 0.
     * 상태 부분은 V7 이 alert_state 로 이미 옮겼다.
     */
    public int migrateLegacy(LocalDateTime now) {
        if (db.row("SELECT 1 AS x FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'alerts_legacy'",
                Map.of()) == null) {
            return 0;
        }
        int n = 0;
        for (Map<String, Object> a : db.rows("SELECT * FROM alerts_legacy ORDER BY created_at LIMIT 5000")) {
            LocalDateTime fs = Db.time(a, "first_seen");
            Content c = new Content(Db.str(a, "alert_id"), Db.str(a, "source_type"), Db.str(a, "source_id"),
                    Db.integer(a, "source_version"), Db.str(a, "org_id"), Db.str(a, "entity_type"), Db.str(a, "entity"),
                    Db.str(a, "severity"), Db.str(a, "title"), Db.str(a, "alert_node"), Db.str(a, "playbook"),
                    pathOf(a.get("path")), fs, Db.time(a, "last_seen"), Db.lng(a, "hit_count"), Db.bool(a, "silent"),
                    List.copyOf(AlertService.attackIds(a.get("attack"))));
            try {
                put(c, windowMs(fs), now);
                db.execute("DELETE FROM alerts_legacy WHERE alert_id=:id", p("id", c.alertId()));
                n++;
            } catch (RuntimeException e) {
                log.warn("legacy alert {} not migrated: {}", c.alertId(), e.getMessage());
            }
        }
        return n;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> pathOf(Object v) {
        Object o = v instanceof String s ? Json.load(s) : v;
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object x : Json.asList(o)) {
            out.add((Map<String, Object>) x);
        }
        return out;
    }

    // ---------------------------------------------------------------- 행 만들기
    private Map<String, Object> fields(Content c) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("org_id", c.orgId());
        f.put("entity_type", c.entityType());
        f.put("entity", c.entity());
        f.put("source_type", c.sourceType());
        f.put("source_id", c.sourceId());
        f.put("source_version", c.sourceVersion());
        f.put("alert_node", c.alertNode());
        f.put("severity", c.severity());
        f.put("silent", c.silent());
        f.put("playbook", c.playbook() == null ? "" : c.playbook());
        f.put("rule_ids", ruleIds(c.path()));
        f.put("attack", c.attackIds() == null ? List.of() : c.attackIds());
        return f;
    }

    private static List<String> ruleIds(List<Map<String, Object>> path) {
        TreeSet<String> ids = new TreeSet<>();
        for (Map<String, Object> s : path == null ? List.<Map<String, Object>>of() : path) {
            Object r = s.get("rule_id") != null ? s.get("rule_id") : s.get("matched_rule_id");
            if (r != null) {
                ids.add(String.valueOf(r));
            }
        }
        return new ArrayList<>(ids);
    }

    /** 같은 키(시간·유형·제목·등급)에 다른 경보가 있으면 제목 뒤에 기관을 붙인다. */
    private String uniqueTitle(Content c, long windowMs, String dt) {
        String t = c.title() == null || c.title().isBlank() ? c.sourceId() : c.title();
        List<Map<String, Object>> r = ch.query("SELECT _alert_cd FROM " + TABLE + " FINAL WHERE window_ms = {w:UInt64} "
                        + "AND _data_type = {dt:String} AND attack = {a:String} AND risk = {r:String} LIMIT 1",
                p("w", windowMs, "dt", dt, "a", t, "r", risk(c.severity())));
        if (!r.isEmpty() && !c.alertId().equals(ClickHouse.str(r.get(0), "_alert_cd"))) {
            return t + " [" + c.orgId() + "]";
        }
        return t;
    }

    private String groupCode(String sourceType, String sourceId) {
        if (!"scenario".equals(sourceType)) {
            return "";
        }
        Map<String, Object> g = db.row("SELECT g.grp_cd FROM scenarios s JOIN scenario_groups g ON g.group_id = s.group_id "
                + "WHERE s.scenario_id = :s", p("s", sourceId));
        return g == null ? "" : Db.str(g, "grp_cd");
    }

    private String orgName(String orgId) {
        if (orgId == null) {
            return "";
        }
        Map<String, Object> r = db.row("SELECT name FROM orgs WHERE org_id = :o", p("o", orgId));
        return r == null || r.get("name") == null ? "" : Db.str(r, "name");
    }

    private String author(String sourceType, String sourceId) {
        Map<String, Object> r = "scenario".equals(sourceType)
                ? db.row("SELECT created_by FROM scenarios WHERE scenario_id = :s", p("s", sourceId))
                : db.row("SELECT created_by FROM single_rules WHERE rule_id = :s", p("s", sourceId));
        return r == null ? null : Db.str(r, "created_by");
    }

    /** 첫 모듈의 대상 필드 (src_ip / dst_ip ...). */
    private String entityField(Content c) {
        String rule = "single_rule".equals(c.sourceType()) ? c.sourceId() : null;
        if (rule == null) {
            for (Map<String, Object> s : c.path() == null ? List.<Map<String, Object>>of() : c.path()) {
                if ("rule".equals(s.get("type")) && s.get("rule_id") != null) {
                    rule = String.valueOf(s.get("rule_id"));
                    break;
                }
            }
        }
        if (rule == null) {
            return null;
        }
        Map<String, Object> r = db.row("SELECT JSON_VALUE(v.definition, '$.entity.field') AS f FROM single_rules s "
                + "JOIN single_rule_versions v ON v.rule_id = s.rule_id AND v.version = s.current_version WHERE s.rule_id = :r",
                p("r", rule));
        return r == null ? null : Db.str(r, "f");
    }

    /** 포트·국가·장비·조치·에이전트는 첫 근거 이벤트에서, 대상 IP 는 대상 필드 칸에. */
    private void enrich(Map<String, Object> row, Content c) {
        for (String k : List.of("src_ip", "src_port", "src_iso", "src_lat", "src_lng", "dst_ip", "dst_port", "origin_ip", "origin_id")) {
            row.put(k, null);
        }
        row.put("action", "");
        row.put("product", "");
        List<String> ids = new ArrayList<>();
        for (Map<String, Object> s : c.path() == null ? List.<Map<String, Object>>of() : c.path()) {
            ids.addAll(Json.strings(s.get("sample_event_ids")));
            if (!ids.isEmpty()) {
                break;
            }
        }
        if (!ids.isEmpty()) {
            try {
                List<Map<String, Object>> ev = ch.query("SELECT src_ip, src_port, src_iso, src_lat, src_lng, dst_ip, dst_port, origin_ip, "
                                + "origin_id, ifNull(toString(fields.action), '') AS action, ifNull(toString(fields.product), '') AS product FROM "
                                + InitService.SOURCE + " WHERE _collect_time >= {f:DateTime64(3)} AND _collect_time <= {t:DateTime64(3)} "
                                + "AND _event_cd IN {ids:Array(String)} LIMIT 1",
                        p("f", Kst.fmt(c.firstSeen().minusDays(1)), "t", Kst.fmt(c.lastSeen().plusDays(1)), "ids", ids));
                if (!ev.isEmpty()) {
                    Map<String, Object> e = ev.get(0);
                    for (String k : List.of("src_ip", "src_port", "src_iso", "src_lat", "src_lng", "dst_ip", "dst_port", "origin_ip", "origin_id")) {
                        row.put(k, e.get(k));
                    }
                    row.put("action", e.get("action") == null ? "" : e.get("action"));
                    row.put("product", e.get("product") == null ? "" : e.get("product"));
                }
            } catch (RuntimeException ex) {
                log.debug("alert enrich failed: {}", ex.getMessage());
            }
        }
        if ("host".equals(c.entityType())) {
            String f = entityField(c);
            row.put("dst_ip".equals(f) ? "dst_ip" : "src_ip", ipv6(c.entity()));
        }
    }
}
