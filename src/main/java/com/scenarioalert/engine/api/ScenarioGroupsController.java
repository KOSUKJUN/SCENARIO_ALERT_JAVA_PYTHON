package com.scenarioalert.engine.api;

import com.scenarioalert.engine.auth.AuthService.User;
import com.scenarioalert.engine.auth.RequireRole;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 시나리오 그룹 (시나리오 분석 화면 왼쪽 목록). 화면에서 묶어 보기 위한 분류라 탐지 판정·그래프 JSON·생성 코드와 무관하다.
 * 그룹을 지우면 그 그룹의 시나리오는 미분류가 된다 (FK ON DELETE SET NULL).
 */
@RestController
@RequestMapping("/api/v1")
public class ScenarioGroupsController {
    private static final int MAX_NAME = 100;
    private final Db db;

    public ScenarioGroupsController(Db db) {
        this.db = db;
    }

    /** 그룹 목록과 그룹별 시나리오 수. ungrouped = 미분류 수, total = 전체 수. */
    @GetMapping("/scenario-groups")
    @RequireRole("viewer")
    public Map<String, Object> list() {
        List<Map<String, Object>> groups = db.rows("SELECT g.group_id, g.grp_cd, g.name, g.sort_order, COUNT(s.scenario_id) AS scenario_count "
                + "FROM scenario_groups g LEFT JOIN scenarios s ON s.group_id=g.group_id "
                + "GROUP BY g.group_id, g.grp_cd, g.name, g.sort_order ORDER BY g.sort_order, g.name");
        Map<String, Object> c = db.row("SELECT COUNT(*) AS total, SUM(CASE WHEN group_id IS NULL THEN 1 ELSE 0 END) AS ungrouped "
                + "FROM scenarios", Map.of());
        return Json.obj("groups", groups, "total", c == null ? 0 : Db.lng(c, "total"),
                "ungrouped", c == null || c.get("ungrouped") == null ? 0 : Db.lng(c, "ungrouped"));
    }

    @PostMapping("/scenario-groups")
    @ResponseStatus(HttpStatus.CREATED)
    @RequireRole("author")
    /** 그룹 추가. grp_cd(경보 테이블 rull_grp_cd 로 들어가는 그룹 코드)를 비우면 SG001 형식으로 정한다. */
    public Map<String, Object> create(@RequestBody Map<String, Object> body, User user) {
        String name = name(body);
        String code = code(body);
        return db.tx(() -> {
            ensureUnique(name, null);
            if (code != null) {
                ensureCodeUnique(code, null);
            }
            Map<String, Object> mx = db.row("SELECT COALESCE(MAX(sort_order), 0) AS m FROM scenario_groups", Map.of());
            db.execute("INSERT INTO scenario_groups (grp_cd, name, sort_order, created_by) VALUES (:c, :n, :o, :u)",
                    p("c", code != null ? code : "TMP" + java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 24), "n", name,
                            "o", (mx == null ? 0 : Db.lng(mx, "m")) + 10, "u", user.username()));
            if (code == null) {
                db.execute("UPDATE scenario_groups SET grp_cd = CONCAT('SG', LPAD(group_id, 3, '0')) WHERE name=:n", p("n", name));
            }
            Map<String, Object> g = db.row("SELECT group_id, grp_cd, name, sort_order FROM scenario_groups WHERE name=:n", p("n", name));
            db.audit(user.username(), "scenario_group.create", name, g);
            return g;
        });
    }

    /** 이름(과 grp_cd) 바꾸기. 이미 만들어진 경보의 rull_grp_cd 는 그대로다 (경보는 만들 때의 값을 남긴다). */
    @PutMapping("/scenario-groups/{groupId}")
    @RequireRole("author")
    public Map<String, Object> rename(@PathVariable long groupId, @RequestBody Map<String, Object> body, User user) {
        String name = name(body);
        String code = code(body);
        return db.tx(() -> {
            exists(groupId);
            ensureUnique(name, groupId);
            if (code != null) {
                ensureCodeUnique(code, groupId);
            }
            db.execute("UPDATE scenario_groups SET name=:n" + (code != null ? ", grp_cd=:c" : "") + " WHERE group_id=:g",
                    p("n", name, "c", code, "g", groupId));
            db.audit(user.username(), "scenario_group.rename", String.valueOf(groupId), Json.obj("name", name, "grp_cd", code));
            return db.row("SELECT group_id, grp_cd, name, sort_order FROM scenario_groups WHERE group_id=:g", p("g", groupId));
        });
    }

    private static final java.util.regex.Pattern CODE_RE = java.util.regex.Pattern.compile("^[A-Za-z0-9_-]{1,32}$");

    /** grp_cd: 비우면 null(자동). 영문·숫자·_·- 1~32자 */
    private static String code(Map<String, Object> body) {
        String c = Body.optStr(body, "grp_cd");
        if (c == null || c.isBlank()) {
            return null;
        }
        c = c.trim();
        if (!CODE_RE.matcher(c).matches()) {
            throw new ApiException(400, "그룹 코드는 영문·숫자·_·- 1~32자입니다");
        }
        return c;
    }

    private void ensureCodeUnique(String code, Long except) {
        Map<String, Object> r = db.row("SELECT group_id FROM scenario_groups WHERE grp_cd=:c", p("c", code));
        if (r != null && (except == null || Db.lng(r, "group_id") != except)) {
            throw new ApiException(409, "같은 그룹 코드가 있습니다: " + code);
        }
    }

    @DeleteMapping("/scenario-groups/{groupId}")
    @RequireRole("author")
    public Map<String, Object> delete(@PathVariable long groupId, User user) {
        db.txRun(() -> {
            exists(groupId);
            db.execute("DELETE FROM scenario_groups WHERE group_id=:g", p("g", groupId));
            db.audit(user.username(), "scenario_group.delete", String.valueOf(groupId), Map.of());
        });
        return Json.obj("deleted", true);
    }

    /** 시나리오 여러 개를 한 그룹으로 옮긴다. group_id 가 null 이면 미분류. 순서도 버전은 바뀌지 않는다. */
    @PutMapping("/scenario-groups/assign")
    @RequireRole("author")
    public Map<String, Object> assign(@RequestBody Map<String, Object> body, User user) {
        Object gid = body.get("group_id");
        Long groupId = gid == null ? null : toLong(gid);
        List<String> ids = new ArrayList<>();
        Object raw = body.get("scenario_ids");
        if (!(raw instanceof List<?> l) || l.isEmpty()) {
            throw new ApiException(400, "scenario_ids 가 필요합니다");
        }
        for (Object o : l) {
            ids.add(String.valueOf(o));
        }
        return db.tx(() -> {
            if (groupId != null) {
                exists(groupId);
            }
            int n = 0;
            for (String sid : ids) {
                int c = db.execute("UPDATE scenarios SET group_id=:g, updated_at=updated_at WHERE scenario_id=:s",
                        p("g", groupId, "s", sid));
                if (c == 0) {
                    throw new ApiException(404, "없는 시나리오입니다: " + sid);
                }
                n += c;
            }
            db.audit(user.username(), "scenario_group.assign", groupId == null ? "(미분류)" : String.valueOf(groupId),
                    Json.obj("scenario_ids", ids));
            return Json.obj("updated", n, "group_id", groupId);
        });
    }

    private static String name(Map<String, Object> body) {
        String n = Body.str(body, "name").trim();
        if (n.isEmpty() || n.length() > MAX_NAME) {
            throw new ApiException(400, "그룹 이름은 1~" + MAX_NAME + "자입니다");
        }
        return n;
    }

    private void exists(long groupId) {
        if (db.row("SELECT 1 AS x FROM scenario_groups WHERE group_id=:g", p("g", groupId)) == null) {
            throw new ApiException(404, "없는 그룹입니다");
        }
    }

    private void ensureUnique(String name, Long except) {
        Map<String, Object> r = db.row("SELECT group_id FROM scenario_groups WHERE name=:n", p("n", name));
        if (r != null && (except == null || Db.lng(r, "group_id") != except)) {
            throw new ApiException(409, "같은 이름의 그룹이 있습니다: " + name);
        }
    }

    private static long toLong(Object o) {
        try {
            return o instanceof Number num ? num.longValue() : Long.parseLong(String.valueOf(o));
        } catch (NumberFormatException e) {
            throw new ApiException(400, "group_id 는 숫자입니다");
        }
    }
}
