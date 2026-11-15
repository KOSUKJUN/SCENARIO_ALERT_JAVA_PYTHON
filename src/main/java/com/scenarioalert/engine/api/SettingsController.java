package com.scenarioalert.engine.api;

import com.scenarioalert.engine.auth.AuthService;
import com.scenarioalert.engine.auth.AuthService.User;
import com.scenarioalert.engine.auth.RequireRole;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Ip;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

import static com.scenarioalert.engine.common.Db.p;

/** 설정 API: 기관, 기관별 룰 파라미터, 리스트, 자산·태그, 과거 사고, 사용자, 감사 로그. */
@RestController
@RequestMapping("/api/v1")
public class SettingsController {
    static final Pattern LIST_ID_RE = Pattern.compile("^[a-z0-9][a-z0-9_\\-]{0,63}$");
    static final Pattern TAG_RE = Pattern.compile("^[a-z0-9][a-z0-9_\\-]{0,63}$");
    static final Pattern ORG_RE = Pattern.compile("^[A-Za-z0-9_\\-]{1,64}$");
    static final List<String> LIST_DICTS = List.of("dict_list_items", "dict_threat_ip", "dict_signature_map");
    static final List<String> LIST_KINDS = List.of("ip", "cidr", "domain", "string", "signature_map");

    private final Db db;
    private final ClickHouse ch;

    public SettingsController(Db db, ClickHouse ch) {
        this.db = db;
        this.ch = ch;
    }

    private static String ip(String v) {
        String n = Ip.normalize(v == null ? null : v.trim());
        if (n == null) {
            throw new ApiException(400, "IP 형식이 아닙니다: " + v);
        }
        return n;
    }

    // ---------------------------------------------------------------- 기관
    @GetMapping("/orgs")
    @RequireRole("viewer")
    public List<Map<String, Object>> orgs() {
        List<Map<String, Object>> orgs = db.rows("SELECT org_id, name, enabled FROM orgs ORDER BY org_id");
        List<Map<String, Object>> cidrs = db.rows("SELECT org_id, cidr FROM org_cidrs ORDER BY org_id, cidr");
        for (Map<String, Object> o : orgs) {
            o.put("cidrs", cidrs.stream().filter(c -> c.get("org_id").equals(o.get("org_id"))).map(c -> c.get("cidr")).toList());
        }
        return orgs;
    }

    private Map<String, Object> saveOrg(String orgId, Map<String, Object> body, User user, boolean create) {
        if (!ORG_RE.matcher(orgId).matches()) {
            throw new ApiException(400, "기관 ID 형식이 아닙니다");
        }
        String name = Body.str(body, "name");
        boolean enabled = Body.bool(body, "enabled", true);
        TreeSet<String> nets = new TreeSet<>();
        for (String c : Json.strings(body.getOrDefault("cidrs", List.of()))) {
            String n = Ip.normalizeCidr(c.trim());
            if (n == null) {
                throw new ApiException(400, "CIDR 형식이 아닙니다: " + c);
            }
            nets.add(n);
        }
        db.txRun(() -> {
            Map<String, Object> ex = db.row("SELECT org_id FROM orgs WHERE org_id=:o", p("o", orgId));
            if (create && ex != null) {
                throw new ApiException(409, "이미 있는 기관입니다");
            }
            if (!create && ex == null) {
                throw new ApiException(404, "기관이 없습니다");
            }
            if (ex != null) {
                db.execute("UPDATE orgs SET name=:n, enabled=:e WHERE org_id=:o", p("o", orgId, "n", name, "e", enabled));
            } else {
                db.execute("INSERT INTO orgs (org_id, name, enabled) VALUES (:o, :n, :e)", p("o", orgId, "n", name, "e", enabled));
            }
            db.execute("DELETE FROM org_cidrs WHERE org_id=:o", p("o", orgId));
            for (String n : nets) {
                db.execute("INSERT INTO org_cidrs (org_id, cidr) VALUES (:o, :c)", p("o", orgId, "c", n));
            }
            db.audit(user.username(), "org.save", orgId, Json.obj("name", name, "cidrs", new ArrayList<>(nets)));
        });
        ch.reloadDictionaries(List.of("dict_orgs"));
        return Json.obj("org_id", orgId, "name", name, "enabled", enabled, "cidrs", new ArrayList<>(nets));
    }

    @PostMapping("/orgs")
    @ResponseStatus(HttpStatus.CREATED)
    @RequireRole("admin")
    public Map<String, Object> createOrg(@RequestBody Map<String, Object> body, User user) {
        String id = Body.optStr(body, "org_id");
        if (id == null || id.isEmpty()) {
            throw new ApiException(400, "org_id 가 필요합니다");
        }
        return saveOrg(id, body, user, true);
    }

    @PutMapping("/orgs/{orgId}")
    @RequireRole("admin")
    public Map<String, Object> updateOrg(@PathVariable String orgId, @RequestBody Map<String, Object> body, User user) {
        return saveOrg(orgId, body, user, false);
    }

    // ---------------------------------------------------------------- 기관별 룰 파라미터
    @GetMapping("/orgs/{orgId}/rule-params")
    @RequireRole("viewer")
    public List<Map<String, Object>> ruleParams(@PathVariable String orgId) {
        return db.rows("SELECT org_id, rule_id, enabled, threshold FROM org_rule_params WHERE org_id=:o ORDER BY rule_id",
                p("o", orgId));
    }

    @GetMapping("/orgs/{orgId}/rule-params/{ruleId}")
    @RequireRole("author")
    public Map<String, Object> ruleParam(@PathVariable String orgId, @PathVariable String ruleId) {
        Map<String, Object> r = db.row("SELECT org_id, rule_id, enabled, threshold FROM org_rule_params WHERE org_id=:o "
                + "AND rule_id=:r", p("o", orgId, "r", ruleId));
        return r != null ? r : Json.obj("org_id", orgId, "rule_id", ruleId, "enabled", true, "threshold", null);
    }

    @PutMapping("/orgs/{orgId}/rule-params/{ruleId}")
    @RequireRole("author")
    public Map<String, Object> putRuleParam(@PathVariable String orgId, @PathVariable String ruleId,
                                            @RequestBody Map<String, Object> body, User user) {
        boolean enabled = Body.bool(body, "enabled", true);
        Double thr = Body.optDouble(body, "threshold");
        if (thr != null && thr <= 0) {
            throw new ApiException(400, "임계치는 0보다 커야 합니다");
        }
        db.txRun(() -> {
            if (db.row("SELECT 1 AS x FROM orgs WHERE org_id=:o", p("o", orgId)) == null) {
                throw new ApiException(404, "기관이 없습니다");
            }
            if (db.row("SELECT 1 AS x FROM single_rules WHERE rule_id=:r", p("r", ruleId)) == null) {
                throw new ApiException(404, "룰이 없습니다");
            }
            db.execute("INSERT INTO org_rule_params (org_id, rule_id, enabled, threshold) VALUES (:o, :r, :e, :t) "
                            + "ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), threshold=VALUES(threshold)",
                    p("o", orgId, "r", ruleId, "e", enabled, "t", thr));
            db.audit(user.username(), "org_rule_param.save", orgId + "/" + ruleId, Json.obj("enabled", enabled, "threshold", thr));
        });
        ch.reloadDictionaries(List.of("dict_org_rule_params"));
        return Json.obj("org_id", orgId, "rule_id", ruleId, "enabled", enabled, "threshold", thr);
    }

    @DeleteMapping("/orgs/{orgId}/rule-params/{ruleId}")
    @RequireRole("author")
    public Map<String, Object> deleteRuleParam(@PathVariable String orgId, @PathVariable String ruleId, User user) {
        db.txRun(() -> {
            db.execute("DELETE FROM org_rule_params WHERE org_id=:o AND rule_id=:r", p("o", orgId, "r", ruleId));
            db.audit(user.username(), "org_rule_param.delete", orgId + "/" + ruleId, null);
        });
        ch.reloadDictionaries(List.of("dict_org_rule_params"));
        return Map.of("ok", true);
    }

    // ---------------------------------------------------------------- 리스트
    private static String normItem(String kind, String v) {
        String s = v == null ? "" : v.trim();
        if (s.isEmpty()) {
            throw new ApiException(400, "빈 값은 넣을 수 없습니다");
        }
        switch (kind) {
            case "ip" -> {
                return ip(s);
            }
            case "cidr" -> {
                String n = Ip.normalizeCidr(s);
                if (n == null) {
                    throw new ApiException(400, "CIDR 형식이 아닙니다: " + s);
                }
                return n;
            }
            case "domain" -> {
                return s.toLowerCase(Locale.ROOT);
            }
            case "signature_map" -> {
                if (!s.contains("|")) {
                    throw new ApiException(400, "시그니처 매핑 값은 '데이터유형|시그니처명' 형식입니다 (모든 유형은 '*|이름')");
                }
                return s.length() > 255 ? s.substring(0, 255) : s;
            }
            default -> {
                return s.length() > 255 ? s.substring(0, 255) : s;
            }
        }
    }

    @GetMapping("/lists")
    @RequireRole("viewer")
    public List<Map<String, Object>> lists() {
        return db.rows("SELECT l.list_id, l.kind, l.scope_org_id, l.description, COUNT(i.value) AS item_count FROM lists l "
                + "LEFT JOIN list_items i ON i.list_id = l.list_id GROUP BY l.list_id, l.kind, l.scope_org_id, l.description "
                + "ORDER BY l.list_id");
    }

    @PostMapping("/lists")
    @ResponseStatus(HttpStatus.CREATED)
    @RequireRole("author")
    public Map<String, Object> createList(@RequestBody Map<String, Object> body, User user) {
        String id = Body.optStr(body, "list_id");
        String kind = Body.optStr(body, "kind");
        if (id == null || !LIST_ID_RE.matcher(id).matches()) {
            throw new ApiException(400, "리스트 ID 는 소문자, 숫자, _, - 로 1~64자입니다");
        }
        if (!LIST_KINDS.contains(kind)) {
            throw new ApiException(400, "kind 는 ip, cidr, domain, string, signature_map 중 하나입니다");
        }
        String scope = Body.optStr(body, "scope_org_id");
        db.txRun(() -> {
            if (db.row("SELECT 1 AS x FROM lists WHERE list_id=:l", p("l", id)) != null) {
                throw new ApiException(409, "이미 있는 리스트입니다");
            }
            db.execute("INSERT INTO lists (list_id, kind, scope_org_id, description) VALUES (:l, :k, :s, :d)",
                    p("l", id, "k", kind, "s", scope == null || scope.isEmpty() ? null : scope,
                            "d", Body.optStr(body, "description")));
            db.audit(user.username(), "list.create", id, body);
        });
        return body;
    }

    @GetMapping("/lists/{listId}")
    @RequireRole("viewer")
    public Map<String, Object> getList(@PathVariable String listId) {
        Map<String, Object> meta = db.row("SELECT * FROM lists WHERE list_id=:l", p("l", listId));
        if (meta == null) {
            throw new ApiException(404, "리스트가 없습니다");
        }
        meta.put("items", db.rows("SELECT value, mapped_value, expires_at, note FROM list_items WHERE list_id=:l ORDER BY value",
                p("l", listId)));
        return meta;
    }

    @PutMapping("/lists/{listId}")
    @RequireRole("author")
    public Map<String, Object> updateList(@PathVariable String listId, @RequestBody Map<String, Object> body, User user) {
        String scope = Body.optStr(body, "scope_org_id");
        db.txRun(() -> {
            if (db.row("SELECT 1 AS x FROM lists WHERE list_id=:l", p("l", listId)) == null) {
                throw new ApiException(404, "리스트가 없습니다");
            }
            db.execute("UPDATE lists SET scope_org_id=:s, description=:d WHERE list_id=:l",
                    p("l", listId, "s", scope == null || scope.isEmpty() ? null : scope, "d", Body.optStr(body, "description")));
            db.audit(user.username(), "list.update", listId, body);
        });
        ch.reloadDictionaries(LIST_DICTS);
        return Map.of("ok", true);
    }

    @DeleteMapping("/lists/{listId}")
    @RequireRole("author")
    public Map<String, Object> deleteList(@PathVariable String listId, User user) {
        db.txRun(() -> {
            List<Map<String, Object>> used = db.rows("SELECT v.rule_id FROM single_rule_versions v JOIN single_rules r "
                    + "ON r.rule_id=v.rule_id AND r.current_version=v.version WHERE JSON_SEARCH(v.definition, 'one', :l) IS NOT NULL",
                    p("l", listId));
            if (!used.isEmpty()) {
                throw new ApiException(409, "룰이 참조 중입니다: "
                        + String.join(", ", used.stream().map(u -> Db.str(u, "rule_id")).toList()));
            }
            db.execute("DELETE FROM lists WHERE list_id=:l", p("l", listId));
            db.audit(user.username(), "list.delete", listId, null);
        });
        ch.reloadDictionaries(LIST_DICTS);
        return Map.of("ok", true);
    }

    private void upsertItem(String listId, String kind, String value, String mapped, String expires, String note) {
        db.execute("INSERT INTO list_items (list_id, value, mapped_value, expires_at, note) VALUES (:l, :v, :m, :e, :n) "
                        + "ON DUPLICATE KEY UPDATE mapped_value=VALUES(mapped_value), expires_at=VALUES(expires_at), note=VALUES(note)",
                p("l", listId, "v", normItem(kind, value), "m", mapped == null || mapped.isEmpty() ? null : mapped,
                        "e", Kst.parse(expires), "n", note));
    }

    private String listKind(String listId) {
        Map<String, Object> meta = db.row("SELECT kind FROM lists WHERE list_id=:l", p("l", listId));
        if (meta == null) {
            throw new ApiException(404, "리스트가 없습니다");
        }
        return Db.str(meta, "kind");
    }

    @PostMapping("/lists/{listId}/items")
    @RequireRole("author")
    public Map<String, Object> addItem(@PathVariable String listId, @RequestBody Map<String, Object> body, User user) {
        db.txRun(() -> {
            upsertItem(listId, listKind(listId), Body.str(body, "value"), Body.optStr(body, "mapped_value"),
                    Body.optStr(body, "expires_at"), Body.optStr(body, "note"));
            db.audit(user.username(), "list.item.add", listId, body);
        });
        ch.reloadDictionaries(LIST_DICTS);
        return Map.of("ok", true);
    }

    @PostMapping("/lists/{listId}/items:delete")
    @RequireRole("author")
    public Map<String, Object> deleteItems(@PathVariable String listId, @RequestBody Map<String, Object> body, User user) {
        List<String> values = Json.strings(body.get("values"));
        db.txRun(() -> {
            for (String v : values) {
                db.execute("DELETE FROM list_items WHERE list_id=:l AND value=:v", p("l", listId, "v", v));
            }
            db.audit(user.username(), "list.item.delete", listId, Json.obj("values", values));
        });
        ch.reloadDictionaries(LIST_DICTS);
        return Json.obj("ok", true, "deleted", values.size());
    }

    /** CSV 일괄 등록. 열: value[,mapped_value[,expires_at[,note]]]. 첫 줄이 value 로 시작하면 머리글로 본다. */
    @PostMapping("/lists/{listId}/items:bulk")
    @RequireRole("author")
    public Map<String, Object> bulkItems(@PathVariable String listId, @RequestBody Map<String, Object> body, User user) {
        List<List<String>> recs = Csv.parse(Body.str(body, "csv").strip());
        boolean replace = Body.bool(body, "replace", false);
        List<List<String>> items = new ArrayList<>();
        for (int i = 0; i < recs.size(); i++) {
            List<String> rec = recs.get(i);
            if (rec.isEmpty() || rec.get(0).isBlank()) {
                continue;
            }
            if (i == 0 && rec.get(0).trim().equalsIgnoreCase("value")) {
                continue;
            }
            List<String> r = new ArrayList<>(rec);
            while (r.size() < 4) {
                r.add("");
            }
            items.add(r);
        }
        db.txRun(() -> {
            String kind = listKind(listId);
            if (replace) {
                db.execute("DELETE FROM list_items WHERE list_id=:l", p("l", listId));
            }
            for (List<String> r : items) {
                upsertItem(listId, kind, r.get(0), r.get(1), r.get(2).isEmpty() ? null : r.get(2), r.get(3).isEmpty() ? null : r.get(3));
            }
            db.audit(user.username(), "list.item.bulk", listId, Json.obj("count", items.size(), "replace", replace));
        });
        ch.reloadDictionaries(LIST_DICTS);
        return Json.obj("ok", true, "count", items.size());
    }

    // ---------------------------------------------------------------- 자산
    @GetMapping("/orgs/{orgId}/assets")
    @RequireRole("viewer")
    public List<Map<String, Object>> assets(@PathVariable String orgId, @RequestParam(required = false) String q) {
        List<Map<String, Object>> assets = db.rows("SELECT * FROM assets WHERE org_id=:o"
                + (q != null && !q.isEmpty() ? " AND (ip LIKE :q OR purpose LIKE :q)" : "") + " ORDER BY ip LIMIT 5000",
                p("o", orgId, "q", "%" + q + "%"));
        Map<String, List<String>> by = new HashMap<>();
        db.rows("SELECT ip, tag FROM asset_tags WHERE org_id=:o", p("o", orgId))
                .forEach(t -> by.computeIfAbsent(Db.str(t, "ip"), k -> new ArrayList<>()).add(Db.str(t, "tag")));
        for (Map<String, Object> a : assets) {
            a.put("tags", new ArrayList<>(new TreeSet<>(by.getOrDefault(Db.str(a, "ip"), List.of()))));
        }
        return assets;
    }

    private void saveAsset(String orgId, String ipAddr, String purpose, String os, Boolean sens, String source, List<String> tags) {
        for (String t : tags) {
            if (!TAG_RE.matcher(t).matches()) {
                throw new ApiException(400, "태그 형식이 아닙니다: " + t);
            }
        }
        db.execute("INSERT INTO assets (org_id, ip, purpose, os, holds_sensitive, source) VALUES (:o, :ip, :p, :os, :h, :s) "
                        + "ON DUPLICATE KEY UPDATE purpose=VALUES(purpose), os=VALUES(os), holds_sensitive=VALUES(holds_sensitive), "
                        + "source=VALUES(source)",
                p("o", orgId, "ip", ipAddr, "p", purpose, "os", os, "h", sens, "s", source));
        db.execute("DELETE FROM asset_tags WHERE org_id=:o AND ip=:ip", p("o", orgId, "ip", ipAddr));
        for (String t : new TreeSet<>(tags)) {
            db.execute("INSERT INTO asset_tags (org_id, ip, tag) VALUES (:o, :ip, :t)", p("o", orgId, "ip", ipAddr, "t", t));
        }
    }

    @PutMapping("/orgs/{orgId}/assets/{ipAddr}")
    @RequireRole("author")
    public Map<String, Object> putAsset(@PathVariable String orgId, @PathVariable String ipAddr,
                                        @RequestBody Map<String, Object> body, User user) {
        String nip = ip(ipAddr);
        Object hs = body.get("holds_sensitive");
        String source = body.containsKey("source") ? Body.optStr(body, "source") : "manual";
        db.txRun(() -> {
            if (db.row("SELECT 1 AS x FROM orgs WHERE org_id=:o", p("o", orgId)) == null) {
                throw new ApiException(404, "기관이 없습니다");
            }
            saveAsset(orgId, nip, Body.optStr(body, "purpose"), Body.optStr(body, "os"),
                    hs instanceof Boolean b ? b : null, source, Json.strings(body.getOrDefault("tags", List.of())));
            db.audit(user.username(), "asset.save", orgId + "/" + nip, body);
        });
        ch.reloadDictionaries(List.of("dict_assets"));
        return Map.of("ok", true);
    }

    @DeleteMapping("/orgs/{orgId}/assets/{ipAddr}")
    @RequireRole("author")
    public Map<String, Object> deleteAsset(@PathVariable String orgId, @PathVariable String ipAddr, User user) {
        db.txRun(() -> {
            db.execute("DELETE FROM assets WHERE org_id=:o AND ip=:ip", p("o", orgId, "ip", ipAddr));
            db.audit(user.username(), "asset.delete", orgId + "/" + ipAddr, null);
        });
        ch.reloadDictionaries(List.of("dict_assets"));
        return Map.of("ok", true);
    }

    /** CSV: ip,purpose,os,holds_sensitive,tags (tags 는 ; 로 구분). 첫 줄이 ip 로 시작하면 머리글. */
    @PostMapping("/orgs/{orgId}/assets:import")
    @RequireRole("author")
    public Map<String, Object> importAssets(@PathVariable String orgId, @RequestBody Map<String, Object> body, User user) {
        List<List<String>> recs = Csv.parse(Body.str(body, "csv").strip());
        int n = db.tx(() -> {
            if (db.row("SELECT 1 AS x FROM orgs WHERE org_id=:o", p("o", orgId)) == null) {
                throw new ApiException(404, "기관이 없습니다");
            }
            int cnt = 0;
            for (int i = 0; i < recs.size(); i++) {
                List<String> rec = new ArrayList<>(recs.get(i));
                if (rec.isEmpty() || rec.get(0).isBlank() || (i == 0 && rec.get(0).trim().equalsIgnoreCase("ip"))) {
                    continue;
                }
                while (rec.size() < 5) {
                    rec.add("");
                }
                String hs = rec.get(3).trim().toLowerCase(Locale.ROOT);
                List<String> tags = new ArrayList<>();
                for (String t : rec.get(4).split(";")) {
                    if (!t.isBlank()) {
                        tags.add(t.trim());
                    }
                }
                saveAsset(orgId, ip(rec.get(0)), rec.get(1).isEmpty() ? null : rec.get(1), rec.get(2).isEmpty() ? null : rec.get(2),
                        hs.isEmpty() ? null : List.of("1", "true", "y", "yes").contains(hs), "import", tags);
                cnt++;
            }
            db.audit(user.username(), "asset.import", orgId, Json.obj("count", cnt));
            return cnt;
        });
        ch.reloadDictionaries(List.of("dict_assets"));
        return Json.obj("ok", true, "count", n);
    }

    // ---------------------------------------------------------------- 과거 사고
    @GetMapping("/known-incidents")
    @RequireRole("viewer")
    public List<Map<String, Object>> incidents() {
        return db.rows("SELECT * FROM known_incidents ORDER BY occurred_at DESC");
    }

    @PostMapping("/known-incidents")
    @ResponseStatus(HttpStatus.CREATED)
    @RequireRole("author")
    public Map<String, Object> addIncident(@RequestBody Map<String, Object> body, User user) {
        String id = Body.str(body, "incident_id");
        db.txRun(() -> {
            db.execute("INSERT INTO known_incidents (incident_id, org_id, entity, occurred_at, summary) VALUES (:i, :o, :e, :t, :s) "
                            + "ON DUPLICATE KEY UPDATE org_id=VALUES(org_id), entity=VALUES(entity), occurred_at=VALUES(occurred_at), "
                            + "summary=VALUES(summary)",
                    p("i", id, "o", Body.str(body, "org_id"), "e", Body.str(body, "entity"),
                            "t", Kst.parse(Body.str(body, "occurred_at")), "s", Body.optStr(body, "summary")));
            db.audit(user.username(), "incident.save", id, null);
        });
        return Map.of("ok", true);
    }

    @DeleteMapping("/known-incidents/{incidentId}")
    @RequireRole("author")
    public Map<String, Object> deleteIncident(@PathVariable String incidentId, User user) {
        db.txRun(() -> {
            db.execute("DELETE FROM known_incidents WHERE incident_id=:i", p("i", incidentId));
            db.audit(user.username(), "incident.delete", incidentId, null);
        });
        return Map.of("ok", true);
    }

    // ---------------------------------------------------------------- 사용자·감사
    @GetMapping("/users")
    @RequireRole("admin")
    public List<Map<String, Object>> users() {
        return db.rows("SELECT username, role, enabled, created_at FROM users ORDER BY username");
    }

    @PutMapping("/users/{username}")
    @RequireRole("admin")
    public Map<String, Object> putUser(@PathVariable String username, @RequestBody Map<String, Object> body, User user) {
        String role = Body.str(body, "role");
        if (!AuthService.ROLES.contains(role)) {
            throw new ApiException(400, "역할은 viewer, analyst, author, admin 중 하나입니다");
        }
        boolean enabled = Body.bool(body, "enabled", true);
        String pw = Body.optStr(body, "password");
        db.txRun(() -> {
            Map<String, Object> ex = db.row("SELECT username FROM users WHERE username=:u", p("u", username));
            if (ex != null) {
                db.execute("UPDATE users SET role=:r, enabled=:e WHERE username=:u", p("u", username, "r", role, "e", enabled));
                if (pw != null && !pw.isEmpty()) {
                    db.execute("UPDATE users SET password_hash=:p WHERE username=:u",
                            p("u", username, "p", AuthService.hashPassword(pw)));
                }
            } else {
                if (pw == null || pw.length() < 8) {
                    throw new ApiException(400, "비밀번호는 8자 이상입니다");
                }
                db.execute("INSERT INTO users (username, password_hash, role, enabled) VALUES (:u, :p, :r, :e)",
                        p("u", username, "p", AuthService.hashPassword(pw), "r", role, "e", enabled));
            }
            db.audit(user.username(), "user.save", username, Json.obj("role", role, "enabled", enabled));
        });
        return Map.of("ok", true);
    }

    @GetMapping("/audit")
    @RequireRole("admin")
    public List<Map<String, Object>> audit(@RequestParam(defaultValue = "200") int limit) {
        List<Map<String, Object>> rs = db.rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT :n",
                p("n", Math.min(Math.max(limit, 1), 2000)));
        rs.forEach(r -> {
            if (r.get("detail") instanceof String s) {
                r.put("detail", Json.load(s));
            }
        });
        return rs;
    }
}
