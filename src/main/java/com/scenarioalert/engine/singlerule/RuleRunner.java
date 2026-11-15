package com.scenarioalert.engine.singlerule;

import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.scenario.EvalModels.Hit;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 단일룰 실행: INSERT INTO detect.rule_hits ... SELECT 한 문장 + rule_runs 기록.
 *
 * <p>새 히트 판정: 이번 창이 속한 hit_bucket 에 실행 전에 없던 (기관, 대상)만 "새 히트"다.
 * 같은 버킷을 다음 주기에 다시 평가해 값만 갱신된 히트는 새 히트가 아니다 (경보 반복 방지).</p>
 */
@Component
public class RuleRunner {
    public static final String HIT_COLUMNS = "rule_id, rule_version, org_id, entity, hit_bucket, first_seen, last_seen, "
            + "value, threshold, sample_event_ids, win_to";

    private final ClickHouse ch;
    private final Db db;
    private final Repo repo;

    public RuleRunner(ClickHouse ch, Db db, Repo repo) {
        this.ch = ch;
        this.db = db;
        this.repo = repo;
    }

    public record RunResult(String runId, boolean ok, int hitCount, List<Hit> newHits, String error, int durationMs) {
    }

    public static Hit hitFromRow(Map<String, Object> r, int windowSec) {
        return new Hit(ClickHouse.str(r, "rule_id"), (int) ClickHouse.num(r, "rule_version"), ClickHouse.str(r, "org_id"),
                ClickHouse.str(r, "entity"), ClickHouse.time(r, "hit_bucket"), ClickHouse.time(r, "first_seen"),
                ClickHouse.time(r, "last_seen"), ClickHouse.num(r, "value"), ClickHouse.num(r, "threshold"),
                ClickHouse.strList(r, "sample_event_ids"), ClickHouse.time(r, "win_to"), windowSec);
    }

    public RunResult runWindow(ParsedRule rule, int version, LocalDateTime winTo, String instanceId) {
        String runId = UUID.randomUUID().toString();
        LocalDateTime winFrom = winTo.minusSeconds(rule.windowSec());
        long t0 = System.nanoTime();
        RunResult res;
        try {
            RuleCompiler.CompiledRule compiled = db.tx(() -> RuleCompiler.compileRealtime(rule, repo.listLoader()));
            String bucketSql = "toStartOfInterval({win_to:DateTime64(3)}, INTERVAL " + rule.windowSec() + " SECOND)";
            List<Map<String, Object>> before = ch.query(
                    "SELECT org_id, entity FROM detect.rule_hits FINAL WHERE rule_id = {rid:String} AND hit_bucket = " + bucketSql,
                    p("rid", rule.id(), "win_to", Kst.fmt(winTo)));
            Set<String> existed = new HashSet<>();
            before.forEach(r -> existed.add(r.get("org_id") + "\u0000" + r.get("entity")));
            Map<String, Object> params = new LinkedHashMap<>(compiled.params());
            params.put("win_from", Kst.fmt(winFrom));
            params.put("win_to", Kst.fmt(winTo));
            params.put("rule_version", version);
            params.put("run_id", runId);
            ch.command(compiled.sql(), params);
            List<Map<String, Object>> produced = ch.query(
                    "SELECT " + HIT_COLUMNS + " FROM detect.rule_hits WHERE run_id = {run_id:UUID}", p("run_id", runId));
            List<Hit> hits = new ArrayList<>();
            produced.forEach(r -> hits.add(hitFromRow(r, rule.windowSec())));
            List<Hit> newHits = hits.stream().filter(h -> !existed.contains(h.orgId() + "\u0000" + h.entity())).toList();
            res = new RunResult(runId, true, hits.size(), newHits, null, 0);
        } catch (RuntimeException e) {  // 실패는 기록하고 다음 주기에 같은 구간을 다시 시도
            String msg = String.valueOf(e.getMessage());
            res = new RunResult(runId, false, 0, List.of(), msg.length() > 4000 ? msg.substring(0, 4000) : msg, 0);
        }
        int ms = (int) ((System.nanoTime() - t0) / 1_000_000);
        RunResult fin = new RunResult(res.runId(), res.ok(), res.hitCount(), res.newHits(), res.error(), ms);
        String status = fin.ok() ? "ok" : (fin.error() != null && fin.error().toUpperCase().contains("TIMEOUT") ? "timeout" : "failed");
        db.txRun(() -> db.execute("INSERT INTO rule_runs (run_id, rule_id, version, win_from, win_to, status, hit_count, "
                        + "new_hit_count, duration_ms, error, instance_id) VALUES (:id, :r, :v, :f, :t, :s, :h, :n, :d, :e, :i)",
                p("id", runId, "r", rule.id(), "v", version, "f", winFrom, "t", winTo, "s", status, "h", fin.hitCount(),
                        "n", fin.newHits().size(), "d", ms, "e", fin.error(), "i", instanceId)));
        return fin;
    }
}
