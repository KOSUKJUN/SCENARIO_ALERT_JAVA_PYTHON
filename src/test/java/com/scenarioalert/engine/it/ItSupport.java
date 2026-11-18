package com.scenarioalert.engine.it;

import com.scenarioalert.engine.InitService;
import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.d3fend.D3fendService;
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
    static final Path ATTACK_FIXTURES = TestFiles.ROOT.resolve("src/test/resources/attack");

    /**
     * ATT&CK 테스트 번들(공식 번들에서 잘라 낸 19.2, 20.1)을 새로 넣고 20.1 을 활성화한다.
     * 기본 룰의 기법 참조 검사와 경보의 기법 스냅샷이 이 데이터를 쓴다.
     */
    static void loadAttack(Db db, AttackService attack) {
        db.txRun(() -> db.execute("DELETE FROM attack_versions", Map.of()));
        for (String v : List.of("19.2", "20.1")) {
            String name = "enterprise-attack-mini-" + v + ".json";
            try (var in = Files.newInputStream(ATTACK_FIXTURES.resolve(name))) {
                attack.importStream(in, name, "test", null);
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        }
        attack.activate("enterprise-attack", "20.1", "test");
    }

    static final Path D3FEND_FIXTURES = TestFiles.ROOT.resolve("src/test/resources/d3fend");

    /** 잘라 낸 D3FEND 1.5.0·1.6.0 을 가져오고 1.6.0 을 활성화한다 (imported_by=test: reset-data 가 지운다). */
    static void loadD3fend(Db db, D3fendService d3fend) {
        db.txRun(() -> db.execute("DELETE FROM d3fend_versions", Map.of()));
        for (String v : List.of("1.5.0", "1.6.0")) {
            try (var o = Files.newInputStream(D3FEND_FIXTURES.resolve(v).resolve(D3fendService.ONTOLOGY_FILE));
                 var m = Files.newInputStream(D3FEND_FIXTURES.resolve(v).resolve(D3fendService.MAPPINGS_FILE))) {
                d3fend.importStreams(o, D3fendService.ONTOLOGY_FILE, m, D3fendService.MAPPINGS_FILE, "test-" + v, "test", null);
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        }
        d3fend.activate("1.6.0", "test");
    }

    static void resetAll(Db db, ClickHouse ch, InitService init, SampleDataService samples, AttackService attack,
                         D3fendService d3fend, String builtinStatus) {
        init.applyClickHouse(true);
        for (String t : List.of(InitService.SOURCE_STORE, "detect.rule_hits", "detect.rule_hits_backtest", "detect.peer_first_seen")) {
            ch.command("TRUNCATE TABLE " + t, Map.of(), Purpose.ADMIN);
        }
        db.txRun(() -> {
            for (String t : List.of("alerts", "rule_runs", "backtest_jobs", "known_incidents", "scenario_rule_refs",
                    "scenario_versions", "scenarios", "org_rule_params", "single_rule_versions", "single_rules", "asset_tags",
                    "assets", "list_items", "lists", "log_sources", "org_cidrs", "orgs", "sessions", "audit_log")) {
                db.execute("DELETE FROM " + t, Map.of());
            }
        });
        samples.seedReference();
        loadAttack(db, attack);
        loadD3fend(db, d3fend);
        init.loadBuiltin(builtinStatus);
        ch.reloadDictionaries();
    }

    static LocalDateTime baseTime() {
        return Kst.floor(Kst.now().minusHours(3), 3600);
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
            // events.jsonl 은 운영 원본 키(_data_type, _asset_id, 공통 필드, fields 객체)에 시간 대신 기준 시각부터의 offset 을 쓴다
            Map<String, Object> r = new LinkedHashMap<>(e);
            r.put("_event_cd", UUID.randomUUID().toString());
            r.put("_collect_time", Kst.fmt(base.plusNanos(((Number) e.get("offset_ms")).longValue() * 1_000_000)));
            Object eo = e.get("event_offset_ms");
            r.put("event_time", eo == null ? null : Kst.fmt(base.plusNanos(((Number) eo).longValue() * 1_000_000)));
            rows.add(SampleDataService.toRow(r));
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
