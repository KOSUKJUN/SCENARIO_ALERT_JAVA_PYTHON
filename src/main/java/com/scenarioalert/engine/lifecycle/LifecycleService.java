package com.scenarioalert.engine.lifecycle;

import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.repo.Records.RuleRecord;
import com.scenarioalert.engine.repo.Records.ScenarioRecord;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.scenario.GraphValidation;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 룰·순서도 수명주기 (설계안 11장): draft → silent → active, disabled.
 * <ul>
 * <li>draft → silent : 백테스트 1회 이상 완료 (author). 순서도는 참조 룰이 silent 또는 active 여야 한다.</li>
 * <li>silent → active: 관리자 승인 (admin). 순서도는 참조 룰이 모두 active 여야 한다.</li>
 * <li>active 순서도가 참조하는 룰은 active 에서 내릴 수 없다.</li>
 * </ul>
 */
@Component
public class LifecycleService {
    static final Map<String, Set<String>> ALLOWED = Map.of(
            "draft", Set.of("silent", "disabled"),
            "silent", Set.of("active", "draft", "disabled"),
            "active", Set.of("silent", "disabled"),
            "disabled", Set.of("draft", "silent"));

    private final Db db;
    private final Repo repo;

    public LifecycleService(Db db, Repo repo) {
        this.db = db;
        this.repo = repo;
    }

    public static String requiredRole(String cur, String target) {
        return "active".equals(target) ? "admin" : "author";
    }

    private boolean backtestDone(String targetType, String targetId) {
        Map<String, Object> r = db.row("SELECT COUNT(*) AS n FROM backtest_jobs WHERE target_type=:t AND target_id=:i "
                + "AND status='done'", p("t", targetType, "i", targetId));
        return r != null && Db.lng(r, "n") > 0;
    }

    public Map<String, Object> operationStats(String sourceType, String sourceId) {
        Map<String, Object> r = db.row("SELECT COUNT(*) AS n FROM alert_state WHERE source_type=:t AND source_id=:i "
                + "AND created_at >= NOW() - INTERVAL 30 DAY", p("t", sourceType, "i", sourceId));
        Map<String, Object> a = db.row("SELECT MAX(at) AS since FROM audit_log WHERE target=:i AND action LIKE '%.status' "
                + "AND JSON_VALUE(detail, '$.to') = 'silent'", p("i", sourceId));
        return Json.obj("silent_since", a == null ? null : a.get("since"), "alerts_30d", r == null ? 0 : Db.lng(r, "n"));
    }

    public void changeRuleStatus(String ruleId, String target, String actor, boolean force) {
        RuleRecord rule = repo.getRule(ruleId, true);
        String cur = rule.status();
        if (target.equals(cur)) {
            return;
        }
        if (!ALLOWED.getOrDefault(cur, Set.of()).contains(target)) {
            throw ApiException.conflict(cur + " 에서 " + target + " 로 바꿀 수 없습니다");
        }
        if ("silent".equals(target) && Set.of("draft", "disabled").contains(cur) && !force
                && !backtestDone("single_rule", ruleId)) {
            throw ApiException.conflict("silent 로 올리려면 백테스트를 1회 이상 완료해야 합니다");
        }
        if ("active".equals(target) && !"silent".equals(cur) && !force) {
            throw ApiException.conflict("active 는 silent 에서만 올릴 수 있습니다");
        }
        if ("active".equals(cur)) {
            List<Map<String, Object>> users = db.rows("SELECT DISTINCT s.scenario_id FROM scenarios s JOIN scenario_rule_refs f "
                    + "ON f.scenario_id=s.scenario_id AND f.version=s.current_version WHERE f.rule_id=:r AND s.status='active'",
                    p("r", ruleId));
            if (!users.isEmpty() && !force) {
                throw ApiException.conflict("active 순서도가 참조 중입니다: "
                        + String.join(", ", users.stream().map(u -> Db.str(u, "scenario_id")).toList()));
            }
        }
        String extra = "";
        if (Set.of("draft", "disabled").contains(cur) && Set.of("silent", "active").contains(target)) {
            extra = ", last_evaluated_to=NULL, next_run_at=NULL, consecutive_failures=0";
        }
        db.execute("UPDATE single_rules SET status=:s" + extra + " WHERE rule_id=:id", p("s", target, "id", ruleId));
        db.audit(actor, "single_rule.status", ruleId, Json.obj("from", cur, "to", target));
    }

    public void changeScenarioStatus(String sid, String target, String actor, boolean force) {
        ScenarioRecord sc = repo.getScenario(sid);
        String cur = sc.status();
        if (target.equals(cur)) {
            return;
        }
        if (!ALLOWED.getOrDefault(cur, Set.of()).contains(target)) {
            throw ApiException.conflict(cur + " 에서 " + target + " 로 바꿀 수 없습니다");
        }
        if (Set.of("silent", "active").contains(target)) {
            List<String> need = "active".equals(target) ? List.of("active") : List.of("silent", "active");
            GraphValidation res = repo.checkGraph(sc.graph(), need);
            if (!res.ok()) {
                throw ApiException.conflict(res.summary());
            }
        }
        if ("silent".equals(target) && Set.of("draft", "disabled").contains(cur) && !force
                && !backtestDone("scenario", sid)) {
            throw ApiException.conflict("silent 로 올리려면 백테스트를 1회 이상 완료해야 합니다");
        }
        if ("active".equals(target) && !"silent".equals(cur) && !force) {
            throw ApiException.conflict("active 는 silent 에서만 올릴 수 있습니다");
        }
        db.execute("UPDATE scenarios SET status=:s WHERE scenario_id=:id", p("s", target, "id", sid));
        db.audit(actor, "scenario.status", sid, Json.obj("from", cur, "to", target));
    }
}
