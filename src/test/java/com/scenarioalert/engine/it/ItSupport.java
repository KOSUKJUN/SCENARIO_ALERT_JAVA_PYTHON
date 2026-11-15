package com.scenarioalert.engine.it;

import com.scenarioalert.engine.InitService;
import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.ch.ClickHouse.Purpose;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.sample.SampleDataService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

import static com.scenarioalert.engine.common.Db.p;

/** 통합 테스트 공용 도구. 실제 ClickHouse·MariaDB(테스트용 compose)에 붙는다. 개발 DB 를 초기화한다. */
final class ItSupport {
    static final Path SCENARIO_DIR = TestFiles.ROOT.resolve("testdata/scenarios");
    static final int TIMELINE_MIN = 110;

    private ItSupport() {
    }

    static List<String> scenarios() {
        try (var s = Files.list(SCENARIO_DIR)) {
            return s.filter(p -> Files.exists(p.resolve("events.jsonl"))).map(p -> p.getFileName().toString()).sorted().toList();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    /** 이벤트·히트·경보·룰을 모두 지우고 기준 데이터와 기본 룰을 다시 넣는다. */
    static void resetAll(Db db, ClickHouse ch, InitService init, SampleDataService samples, String builtinStatus) {
        init.applyClickHouse(true);
        for (String t : List.of("codlog.log_integrated_success_all", "detect.rule_hits", "detect.rule_hits_backtest", "detect.peer_first_seen")) {
            ch.command("TRUNCATE TABLE " + t, Map.of(), Purpose.ADMIN);
        }
        db.txRun(() -> {
            for (String t : List.of("alerts", "rule_runs", "backtest_jobs", "known_incidents", "scenario_rule_refs",
                    "scenario_versions", "scenarios", "org_rule_params", "single_rule_versions", "single_rules", "asset_tags",
                    "assets", "list_items", "lists", "org_cidrs", "orgs", "sessions", "audit_log")) {
                db.execute("DELETE FROM " + t, Map.of());
            }
        });
        samples.seedReference();
        init.loadBuiltin(builtinStatus);
        ch.reloadDictionaries();
    }

    static LocalDateTime baseTime() {
        return Kst.floor(Kst.now().minusHours(3), 3600);
    }

    private static String v6(Object ip) {
        if (ip == null) {
            return null;
        }
        String s = String.valueOf(ip);
        return s.contains(":") ? s : "::ffff:" + s;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> loadScenario(Db db, ClickHouse ch, SampleDataService samples, String sid, LocalDateTime base) {
        Path d = SCENARIO_DIR.resolve(sid);
        Map<String, Object> exp = Json.loadYamlMap(TestFiles.read(d.resolve("expected.yaml")));
        List<Map<String, Object>> rows = new ArrayList<>();
        for (String line : TestFiles.read(d.resolve("events.jsonl")).split("\n")) {
            if (line.isBlank()) {
                continue;
            }
            Map<String, Object> e = Json.loadMap(line);
            Map<String, Object> r = new LinkedHashMap<>();
            for (String c : SampleDataService.COLUMNS) {
                r.put(c, e.get(c));
            }
            r.put("event_id", UUID.randomUUID().toString());
            r.put("mgr_time", Kst.fmt(base.plusNanos(((Number) e.get("offset_ms")).longValue() * 1_000_000)));
            Object eo = e.get("event_offset_ms");
            r.put("event_time", eo == null ? null : Kst.fmt(base.plusNanos(((Number) eo).longValue() * 1_000_000)));
            r.put("s_info", v6(e.get("s_info")));
            r.put("d_info", v6(e.get("d_info")));
            rows.add(r);
        }
        samples.insertEvents(rows);
        Map<String, Object> setup = exp.get("setup") == null ? Map.of() : (Map<String, Object>) exp.get("setup");
        db.txRun(() -> {
            for (Object o : (List<Object>) setup.getOrDefault("assets", List.of())) {
                List<Object> a = (List<Object>) o;
                db.execute("INSERT INTO assets (org_id, ip, purpose, source) VALUES ('ORG001', :ip, '테스트', 'manual') "
                        + "ON DUPLICATE KEY UPDATE purpose=purpose", p("ip", a.get(0)));
                for (Object t : (List<Object>) a.get(1)) {
                    db.execute("INSERT IGNORE INTO asset_tags (org_id, ip, tag) VALUES ('ORG001', :ip, :t)", p("ip", a.get(0), "t", t));
                }
            }
            for (Object o : (List<Object>) setup.getOrDefault("list_items", List.of())) {
                List<Object> li = (List<Object>) o;
                db.execute("INSERT IGNORE INTO list_items (list_id, value) VALUES (:l, :v)", p("l", li.get(0), "v", li.get(1)));
            }
        });
        ch.reloadDictionaries();
        return exp;
    }

    static void insertBackground(SampleDataService samples, LocalDateTime base, int minutes) {
        samples.insertEvents(SampleDataService.background(base, base.plusMinutes(minutes), new Random(1), 30));
    }

    static void rewindRules(Db db, LocalDateTime start) {
        db.txRun(() -> db.execute("UPDATE single_rules SET last_evaluated_to=:s, next_run_at=NULL WHERE status IN ('silent','active')",
                p("s", start)));
    }
}
