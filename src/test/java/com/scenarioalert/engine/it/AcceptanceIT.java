package com.scenarioalert.engine.it;

import com.scenarioalert.engine.InitService;
import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.d3fend.D3fendService;
import com.scenarioalert.engine.ModeRunner;
import com.scenarioalert.engine.backtest.BacktestService;
import com.scenarioalert.engine.alerting.AlertStore;
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
import static org.junit.jupiter.api.Assertions.assertNull;
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
    @Autowired AttackService attack;
    @Autowired D3fendService d3fend;

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
        ItSupport.resetAll(db, ch, init, samples, attack, d3fend, "active");
        base = ItSupport.baseTime();
        end = base.plusMinutes(ItSupport.TIMELINE_MIN);
        for (String sid : scenarios()) {
            expected.put(sid, ItSupport.loadScenario(db, ch, samples, sid, base));
        }
        ItSupport.insertBackground(samples, base, ItSupport.TIMELINE_MIN);
        ItSupport.rewindRules(db, base);
        runDetection(base.plusMinutes(50), 1);   // 서버 1대로 앞 50분 → "서버 중단"
        runDetection(end, 2);                    // 서버 2대 동시에 따라잡기
        alerts = db.rows("SELECT * FROM alert_state ORDER BY created_at");
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
                for (String k : List.of("src_ip", "dst_ip")) {
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
        assertEquals(14, vs.size());   // 원본 7 + 사고 사례 6 + PHP2Shell 1 (docs/cases.md)
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
        assertEquals(14, scenarios().size());   // testdata/scenarios 디렉터리 수 (원본 7 + 사례 6 + PHP2Shell 1)
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

    // ------------------------------------------------------------------ ATT&CK
    Map<String, Object> alertOf(String source, String entity) {
        return alerts.stream().filter(a -> source.equals(a.get("source_id")) && entity.equals(a.get("entity"))).findFirst()
                .orElseThrow(() -> new AssertionError("경보 없음: " + source + " " + entity));
    }

    @SuppressWarnings("unchecked")
    static Set<String> attackIds(Map<String, Object> a) {
        Set<String> ids = new TreeSet<>();
        if (a.get("attack") != null) {
            for (Object o : Json.asList(Json.load(Db.str(a, "attack")))) {
                ids.add((String) ((Map<String, Object>) o).get("id"));
            }
        }
        return ids;
    }

    @SuppressWarnings("unchecked")
    static Set<String> d3fendIds(Map<String, Object> a) {
        Set<String> ids = new TreeSet<>();
        if (a.get("d3fend") != null) {
            for (Object o : Json.asList(Json.load(Db.str(a, "d3fend")))) {
                ids.add((String) ((Map<String, Object>) o).get("id"));
            }
        }
        return ids;
    }

    /** 경보 본문은 ClickHouse codlog.alert_integrated_all 에만 있다: 상태(MariaDB) 마다 같은 ID 의 행이 하나 있어야 한다. */
    @Test
    void alertBodiesAreInClickHouse() {
        assertFalse(alerts.isEmpty());
        Map<String, Map<String, Object>> bodies = new java.util.HashMap<>();
        ch.query("SELECT _alert_cd, _data_type, attack, risk, max_lvl, count, event_sdt, event_edt, window_ms, "
                        + "replaceRegexpOne(IPv6NumToString(ifNull(src_ip, toIPv6('::'))), '^::ffff:', '') AS s, "
                        + "replaceRegexpOne(IPv6NumToString(ifNull(dst_ip, toIPv6('::'))), '^::ffff:', '') AS d, "
                        + "toString(fields.org_id) AS org, toString(fields.source_id) AS src FROM " + AlertStore.TABLE
                        + " FINAL WHERE _data_type IN ('SCENARIO', 'EVENT_MODULE')", Map.of(), Purpose.ADMIN)
                .forEach(r -> assertNull(bodies.put(String.valueOf(r.get("_alert_cd")), r), "경보 ID 가 두 행: " + r.get("_alert_cd")));
        assertEquals(alerts.size(), bodies.size(), "ClickHouse 경보 수");
        for (Map<String, Object> a : alerts) {
            Map<String, Object> b = bodies.get(Db.str(a, "alert_id"));
            assertTrue(b != null, "본문 없음: " + a.get("alert_id"));
            assertEquals("scenario".equals(a.get("source_type")) ? "SCENARIO" : "EVENT_MODULE", b.get("_data_type"));
            assertEquals(Db.str(a, "severity").toUpperCase(), b.get("risk"));
            assertEquals(Db.str(a, "org_id"), b.get("org"));
            assertEquals(Db.str(a, "source_id"), b.get("src"));
            assertEquals(Db.lng(a, "ch_window_ms"), ((Number) b.get("window_ms")).longValue());
            assertFalse(String.valueOf(b.get("attack")).isBlank());
            assertTrue(((Number) b.get("count")).longValue() >= 1);
            assertTrue(String.valueOf(b.get("event_sdt")).compareTo(String.valueOf(b.get("event_edt"))) <= 0);
            if ("host".equals(a.get("entity_type"))) {
                assertTrue(a.get("entity").equals(b.get("s")) || a.get("entity").equals(b.get("d")), "대상 IP 칸: " + b);
            }
        }
    }

    /** 지정 대응방책(D3FEND) = 경보 노드의 d3fend + 경로에서 성립한 룰의 d3fend. 이름·전술·버전을 경보에 함께 저장하고 단계가 늘면 누적한다. */
    @Test
    @SuppressWarnings("unchecked")
    void alertsCarryD3fendSnapshot() {
        // 실행 성공(a1): 경보 노드(격리·종료·차단·패치·프로세스 분석) + 공격 룰(차단·패치) + 명령 결과 룰(종료·프로세스 분석)
        // + 먼저 만든 공격 경보(a3 높음)의 대응방책(애플리케이션 강화 D3-AH): 높음 → 긴급 상향 때 누적한다
        Map<String, Object> rce = alertOf("SC_PHP2SHELL", "10.10.11.10");
        assertEquals(Set.of("D3-AH", "D3-ITF", "D3-NI", "D3-PSA", "D3-PT", "D3-SU"), d3fendIds(rce));
        assertEquals("D3FEND 1.6.0", rce.get("d3fend_version"));
        Map<String, Object> pt = ((List<Map<String, Object>>) (List<?>) Json.asList(Json.load(Db.str(rce, "d3fend")))).stream()
                .filter(m -> "D3-PT".equals(m.get("id"))).findFirst().orElseThrow();
        assertEquals("Process Termination", pt.get("name"));
        assertEquals("Evict", pt.get("tactic"));
        // 실행 → 도구 반입 (같은 긴급 등급, 억제 시간 안): 도구 반입 단계의 대응방책(파일 퇴출·외부 차단·무결성 감시)이 더해진다
        assertTrue(d3fendIds(alertOf("SC_PHP2SHELL", "10.10.11.19")).containsAll(Set.of("D3-NI", "D3-PT", "D3-FEV", "D3-OTF", "D3-FIM")));
        // 단일룰 단독 경보
        assertEquals(Set.of("D3-NI", "D3-RF", "D3-SU"), d3fendIds(alertOf("SR_WANNACRY_SIG", "10.10.6.30")));
        // 지정 대응방책이 없는 경로: 비워 둔다
        Map<String, Object> p2p = alertOf("SC_P2P_USAGE", "10.10.7.21");
        assertNull(p2p.get("d3fend"));
        assertNull(p2p.get("d3fend_version"));
    }

    /** 경보의 ATT&CK 기법 = 경보 노드의 attack + 경로에서 성립한 룰의 attack. 이름·전술·버전을 경보에 함께 저장한다. */
    @Test
    @SuppressWarnings("unchecked")
    void alertsCarryAttackSnapshot() {
        // 응답에 명령 실행 결과: PHP2Shell 공격(T1190) + 명령 결과 룰(T1059.004, T1033, T1082). 높음 → 긴급 상향 때 다시 저장
        Map<String, Object> rce = alertOf("SC_PHP2SHELL", "10.10.11.10");
        assertEquals(Set.of("T1190", "T1059.004", "T1033", "T1082"), attackIds(rce));
        assertEquals("a1", rce.get("alert_node"));
        assertEquals("enterprise-attack 20.1", rce.get("attack_version"));
        Map<String, Object> t1190 = ((List<Map<String, Object>>) (List<?>) Json.asList(Json.load(Db.str(rce, "attack")))).stream()
                .filter(m -> "T1190".equals(m.get("id"))).findFirst().orElseThrow();
        assertEquals("Exploit Public-Facing Application", t1190.get("name"));
        assertEquals("TA0001", ((Map<String, Object>) ((List<Object>) t1190.get("tactics")).get(0)).get("id"));
        // 내려받기: 공격 + 도구 반입(T1105) + 같은 내려받기가 처음 보는 외부 접속(T1071)이기도 하다 — 성립한 가지의 기법만
        Set<String> dl = attackIds(alertOf("SC_PHP2SHELL", "10.10.11.11"));
        assertEquals(Set.of("T1190", "T1105", "T1071"), dl);

        // v2 ATT&CK 단계 누적: 같은 등급(긴급)의 다음 단계가 억제 시간 안에 보이면 경보의 기법이 늘어난다 (순서 무관)
        Set<String> chain = Set.of("T1190", "T1059.004", "T1033", "T1082", "T1105", "T1071");
        Map<String, Object> c19 = alertOf("SC_PHP2SHELL", "10.10.11.19");   // 실행·정찰 → 도구 반입
        assertEquals(chain, attackIds(c19));
        assertEquals("a1", c19.get("alert_node"), "경보 노드·제목은 먼저 성립한 단계 그대로");
        Map<String, Object> c20 = alertOf("SC_PHP2SHELL", "10.10.11.20");   // 도구 반입 → 실행·정찰
        assertEquals(chain, attackIds(c20));
        // uname -a 결과만 (T1082 정찰) 으로도 실행 성공
        Map<String, Object> c21 = alertOf("SC_PHP2SHELL", "10.10.11.21");
        assertEquals(Set.of("T1190", "T1059.004", "T1033", "T1082"), attackIds(c21));
        // 내려받기 표지 없는 처음 보는 외부 접속: C2 가지 (a5)
        Map<String, Object> c22 = alertOf("SC_PHP2SHELL", "10.10.11.22");
        assertEquals("a5", c22.get("alert_node"));
        assertEquals(Set.of("T1190", "T1071"), attackIds(c22));
        assertTrue(Db.str(c22, "title").contains("[초기 침투 → C2]"), Db.str(c22, "title"));
        // 공격만 (높음): 공격 룰의 기법만
        assertEquals(Set.of("T1190"), attackIds(alertOf("SC_PHP2SHELL", "10.10.11.12")));
        // 경보 노드에 단 기법(T1505.003) + 경로의 룰 기법
        assertEquals(Set.of("T1505.003", "T1190", "T1595.002", "T1071"), attackIds(alertOf("SC_WEB_ATTACK_SUCCESS", "10.10.3.20")));
        // 단일룰 단독 경보
        assertEquals(Set.of("T1486", "T1210"), attackIds(alertOf("SR_WANNACRY_SIG", "10.10.6.30")));
        // 기법이 없는 룰만 거친 경보는 비워 둔다 (P2P 는 정책 위반이라 ATT&CK 매핑 없음)
        Map<String, Object> p2p = alertOf("SC_P2P_USAGE", "10.10.7.21");
        assertNull(p2p.get("attack"));
        assertNull(p2p.get("attack_version"));
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
