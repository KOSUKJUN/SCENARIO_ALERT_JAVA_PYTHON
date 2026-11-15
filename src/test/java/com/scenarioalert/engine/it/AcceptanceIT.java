package com.scenarioalert.engine.it;

import com.scenarioalert.engine.InitService;
import com.scenarioalert.engine.ModeRunner;
import com.scenarioalert.engine.backtest.BacktestService;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.ch.ClickHouse.Purpose;
import com.scenarioalert.engine.common.AppClock;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.sample.SampleDataService;
import com.scenarioalert.engine.scenario.ScenarioCodeGenerator;
import com.scenarioalert.engine.scenario.ScenarioCodeStore;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M3·M4·M5 수용 기준: 기본 순서도 7개를 합성 이벤트로 끝까지 돌려 본다 (실제 ClickHouse·MariaDB·Python).
 *
 * <p>7개 시나리오 이벤트와 정상 트래픽을 한 시간축에 넣고, 서버 1대로 앞 50분을 평가한 뒤 "중단"하고,
 * 서버 2대를 동시에 띄워 나머지를 따라잡는다. 순서도 평가는 순서도마다 생성된 Python 코드가 한다.</p>
 * <ul>
 * <li>M3: 시나리오마다 기대 경보가 정확히 1건씩, 반례는 경보 없음, 단일룰 히트 대상이 기대값과 일치, 기대하지 않은 경보 없음.</li>
 * <li>M4: 같은 룰·같은 구간을 두 번 실행하지 않고, 같은 대상에 경보가 중복되지 않으며, 중단 이후 구간을 빈틈 없이 따라잡는다.</li>
 * <li>M5: 같은 데이터에서 백테스트와 실시간 평가의 경보가 일치한다.</li>
 * </ul>
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "app.mode=test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AcceptanceIT {
    static final String ORG = "ORG001";
    static final int EVAL_DELAY_SEC = 15;

    @Autowired Db db;
    @Autowired ClickHouse ch;
    @Autowired InitService init;
    @Autowired SampleDataService samples;
    @Autowired ModeRunner modes;
    @Autowired BacktestService backtests;
    @Autowired ScenarioCodeStore codeStore;

    LocalDateTime base;
    LocalDateTime end;
    final Map<String, Map<String, Object>> expected = new LinkedHashMap<>();
    List<Map<String, Object>> alerts;
    Map<String, Set<List<String>>> hits;
    List<Map<String, Object>> runs;
    List<Map<String, Object>> rules;

    static List<String> scenarios() {
        return ItSupport.scenarios();
    }

    void runDetection(LocalDateTime now, int servers) {
        List<CompletableFuture<Void>> fs = new ArrayList<>();
        for (int i = 0; i < servers; i++) {
            String inst = "test-" + (i + 1);
            fs.add(CompletableFuture.runAsync(() -> modes.newScheduler(new AppClock.Fixed(now), inst).runUntilCaughtUp(1000)));
        }
        fs.forEach(CompletableFuture::join);
    }

    Map<String, Set<List<String>>> allHits() {
        Map<String, Set<List<String>>> out = new HashMap<>();
        for (Map<String, Object> r : ch.query("SELECT DISTINCT rule_id, org_id, entity FROM detect.rule_hits FINAL", Map.of(),
                Purpose.ADMIN)) {
            out.computeIfAbsent(ClickHouse.str(r, "rule_id"), k -> new HashSet<>())
                    .add(List.of(ClickHouse.str(r, "org_id"), ClickHouse.str(r, "entity")));
        }
        return out;
    }

    @BeforeAll
    void bigRun() {
        init.waitReady(120);
        ItSupport.resetAll(db, ch, init, samples, "active");
        base = ItSupport.baseTime();
        end = base.plusMinutes(ItSupport.TIMELINE_MIN);
        for (String sid : scenarios()) {
            expected.put(sid, ItSupport.loadScenario(db, ch, samples, sid, base));
        }
        ItSupport.insertBackground(samples, base, ItSupport.TIMELINE_MIN);
        ItSupport.rewindRules(db, base);
        runDetection(base.plusMinutes(50), 1);   // 서버 1대로 앞 50분 → "서버 중단"
        runDetection(end, 2);                    // 서버 2대 동시에 따라잡기
        alerts = db.rows("SELECT * FROM alerts ORDER BY created_at");
        hits = allHits();
        runs = db.rows("SELECT rule_id, version, win_from, win_to, status, instance_id FROM rule_runs");
        rules = db.rows("SELECT r.rule_id, r.status, r.last_evaluated_to, r.consecutive_failures, "
                + "JSON_VALUE(v.definition, '$.schedule') AS schedule FROM single_rules r JOIN single_rule_versions v "
                + "ON v.rule_id = r.rule_id AND v.version = r.current_version");
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> list(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? List.of() : (List<Map<String, Object>>) v;
    }

    Set<String> scenarioIps(String sid) {
        Set<String> ips = new HashSet<>();
        for (String line : com.scenarioalert.engine.TestFiles.read(ItSupport.SCENARIO_DIR.resolve(sid).resolve("events.jsonl")).split("\n")) {
            if (!line.isBlank()) {
                Map<String, Object> e = Json.loadMap(line);
                for (String k : List.of("s_info", "d_info")) {
                    if (e.get(k) != null) {
                        ips.add(String.valueOf(e.get(k)));
                    }
                }
            }
        }
        return ips;
    }

    // ------------------------------------------------------------------ 생성 코드
    @Test
    void everyScenarioHasGeneratedPythonCode() {
        List<Map<String, Object>> vs = db.rows("SELECT v.scenario_id, v.version, v.python_code, v.code_sha256 FROM scenarios s "
                + "JOIN scenario_versions v ON v.scenario_id=s.scenario_id AND v.version=s.current_version", Map.of());
        assertEquals(13, vs.size());   // 원본 7 + 사고 사례 6 (docs/cases.md)
        for (Map<String, Object> v : vs) {
            String code = Db.str(v, "python_code");
            assertTrue(code.contains("SCENARIO_ID = \"" + v.get("scenario_id") + "\""));
            assertEquals(ScenarioCodeGenerator.sha256(code), v.get("code_sha256"));
            Path f = codeStore.root().resolve(Db.str(v, "scenario_id")).resolve("v" + v.get("version") + ".py");
            assertTrue(Files.isRegularFile(f), "생성 코드 파일 없음: " + f);
        }
    }

    // ------------------------------------------------------------------ M3
    @Test
    void sevenScenariosPresent() {
        assertEquals(13, scenarios().size());   // testdata/scenarios 디렉터리 수 (원본 7 + 사례 6)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("scenarios")
    void expectedAlerts(String sid) {
        for (Map<String, Object> exp : list(expected.get(sid), "alerts")) {
            List<Map<String, Object>> got = alerts.stream().filter(a -> a.get("source_id").equals(exp.get("source_id"))
                    && ORG.equals(a.get("org_id")) && a.get("entity").equals(exp.get("entity"))).toList();
            assertEquals(1, got.size(), sid + " / " + exp.get("case") + ": " + exp.get("source_id") + " " + exp.get("entity")
                    + " 경보 " + got.size() + "건 (기대 1건)");
            assertEquals(exp.get("severity"), got.get(0).get("severity"), sid + " / " + exp.get("case"));
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("scenarios")
    void counterexamplesHaveNoAlert(String sid) {
        Map<String, Object> exp = expected.get(sid);
        long nCounter = list(exp, "no_alert").size() + list(exp, "alerts").stream()
                .filter(a -> Boolean.TRUE.equals(a.get("counterexample"))).count();
        assertTrue(nCounter >= 3, sid + ": 반례가 3개 미만");
        Set<Object> sources = new HashSet<>();
        sources.add(sid);
        list(exp, "alerts").forEach(a -> sources.add(a.get("source_id")));
        for (Map<String, Object> ne : list(exp, "no_alert")) {
            List<Map<String, Object>> got = alerts.stream().filter(a -> sources.contains(a.get("source_id"))
                    && ORG.equals(a.get("org_id")) && a.get("entity").equals(ne.get("entity"))).toList();
            assertTrue(got.isEmpty(), sid + " / " + ne.get("case") + ": " + ne.get("entity") + " 에 경보가 생김");
        }
    }

    @SuppressWarnings("unchecked")
    @ParameterizedTest(name = "{0}")
    @MethodSource("scenarios")
    void singleRuleHits(String sid) {
        Set<String> ips = scenarioIps(sid);
        Map<String, Object> exp = (Map<String, Object>) expected.get(sid).getOrDefault("hits", Map.of());
        if (exp == null) {
            return;
        }
        for (Map.Entry<String, Object> en : exp.entrySet()) {
            Set<String> got = new TreeSet<>();
            for (List<String> oe : hits.getOrDefault(en.getKey(), Set.of())) {
                if (ORG.equals(oe.get(0)) && ips.contains(oe.get(1))) {
                    got.add(oe.get(1));
                }
            }
            assertEquals(new TreeSet<>(Json.strings(en.getValue())), got, sid + " / " + en.getKey() + ": 히트 대상");
        }
    }

    @Test
    void noUnexpectedAlerts() {
        Set<List<Object>> want = new HashSet<>();
        expected.values().forEach(e -> list(e, "alerts").forEach(a -> want.add(List.of(a.get("source_id"), ORG, a.get("entity")))));
        Set<String> unexpected = new TreeSet<>();
        for (Map<String, Object> a : alerts) {
            List<Object> k = List.of(a.get("source_id"), a.get("org_id"), a.get("entity"));
            if (!want.contains(k)) {
                unexpected.add(k.toString());
            }
        }
        assertTrue(unexpected.isEmpty(), "기대하지 않은 경보: " + unexpected);
    }

    // ------------------------------------------------------------------ M4
    @Test
    void noDuplicateRuleRuns() {
        Map<String, Integer> ok = new HashMap<>();
        runs.stream().filter(r -> "ok".equals(r.get("status")))
                .forEach(r -> ok.merge(r.get("rule_id") + "@" + r.get("win_to"), 1, Integer::sum));
        List<String> dup = ok.entrySet().stream().filter(e -> e.getValue() > 1).map(Map.Entry::getKey).limit(5).toList();
        assertTrue(dup.isEmpty(), "같은 구간을 두 번 실행: " + dup);
        assertTrue(runs.stream().map(r -> r.get("instance_id")).distinct().count() >= 2, "두 서버가 모두 일하지 않았습니다");
    }

    @Test
    void noDuplicateAlerts() {
        Map<String, Integer> n = new HashMap<>();
        alerts.forEach(a -> n.merge(a.get("source_id") + "|" + a.get("org_id") + "|" + a.get("entity"), 1, Integer::sum));
        List<String> dup = n.entrySet().stream().filter(e -> e.getValue() > 1).map(Map.Entry::getKey).toList();
        assertTrue(dup.isEmpty(), "중복 경보: " + dup);
    }

    @Test
    void catchUpAfterOutage() {
        Map<String, List<LocalDateTime>> byRule = new HashMap<>();
        runs.stream().filter(r -> "ok".equals(r.get("status")))
                .forEach(r -> byRule.computeIfAbsent(Db.str(r, "rule_id"), k -> new ArrayList<>()).add(Db.time(r, "win_to")));
        List<Map<String, Object>> active = rules.stream().filter(r -> List.of("silent", "active").contains(r.get("status"))).toList();
        assertFalse(active.isEmpty(), "활성 룰이 없음");
        for (Map<String, Object> rule : active) {
            String rid = Db.str(rule, "rule_id");
            int sch = Kst.parseDuration(rule.get("schedule") == null ? "1m" : rule.get("schedule"));
            LocalDateTime target = Kst.floor(end.minusSeconds(EVAL_DELAY_SEC), sch);
            assertEquals(target, Db.time(rule, "last_evaluated_to"), rid);
            assertEquals(0, Db.integer(rule, "consecutive_failures"), rid);
            List<LocalDateTime> want = new ArrayList<>();
            for (LocalDateTime t = base.plusSeconds(sch); !t.isAfter(target); t = t.plusSeconds(sch)) {
                want.add(t);
            }
            List<LocalDateTime> got = new ArrayList<>(byRule.getOrDefault(rid, List.of()));
            got.sort(null);
            assertEquals(want, got, rid + ": 평가 구간에 빈틈 또는 초과");
        }
    }

    // ------------------------------------------------------------------ M5
    @ParameterizedTest(name = "{0}")
    @MethodSource("scenarios")
    void backtestMatchesRealtime(String sid) {
        LocalDateTime tTo = Kst.floor(end.minusSeconds(EVAL_DELAY_SEC), 60);
        String job = backtests.createJob("scenario", sid, null, null, base, tTo, "test");
        Map<String, Object> res = backtests.runJob(job, AppClock.SYSTEM);
        assertFalse(res.isEmpty(), sid + ": 백테스트 실패");
        List<String> realtime = alerts.stream().filter(a -> sid.equals(a.get("source_id")))
                .map(a -> a.get("org_id") + "|" + a.get("entity") + "|" + a.get("severity")).sorted().toList();
        List<String> bt = list(res, "alerts").stream()
                .map(a -> a.get("org_id") + "|" + a.get("entity") + "|" + a.get("severity")).sorted().toList();
        assertFalse(realtime.isEmpty(), sid + ": 실시간 경보 없음");
        assertEquals(realtime, bt, sid + ": 백테스트 / 실시간");
        // 백테스트 히트는 rule_hits_backtest 에만 쓴다 (실시간 히트를 바꾸지 않는다)
        assertEquals(hits, allHits());
    }
}
