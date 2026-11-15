package com.scenarioalert.engine.scenario;

import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.alerting.AlertService;
import com.scenarioalert.engine.alerting.AlertService.Decision;
import com.scenarioalert.engine.alerting.AlertService.ExistingAlert;
import com.scenarioalert.engine.config.AppProperties;
import com.scenarioalert.engine.scenario.EvalModels.EvalCase;
import com.scenarioalert.engine.scenario.EvalModels.EvalOutcome;
import com.scenarioalert.engine.scenario.EvalModels.Hit;
import com.scenarioalert.engine.scenario.EvalModels.ScenarioProgram;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M3: 시나리오별로 생성된 Python 코드의 평가 결과 (Python 원본 tests/unit/test_evaluator.py 와 같은 기대값).
 * Python 이 없으면 건너뛴다 (docker compose 테스트 환경에서는 항상 돈다).
 */
class ScenarioEvaluationTest {
    static final LocalDateTime T0 = LocalDateTime.of(2026, 11, 12, 10, 0, 0);
    static final Map<String, Integer> WIN = Map.ofEntries(Map.entry("SR_SMB_OUT_FANOUT", 600), Map.entry("SR_WANNACRY_SIG", 300),
            Map.entry("SR_TI_HIT", 300), Map.entry("SR_AUTH_BRUTEFORCE", 300), Map.entry("SR_AUTH_SUCCESS", 300),
            Map.entry("SR_REMOTE_TOOL", 600), Map.entry("SR_MALWARE_SIG", 600), Map.entry("SR_WAF_BURST", 60),
            Map.entry("SR_NEW_OUTBOUND", 600), Map.entry("SR_COINMINER", 600), Map.entry("SR_COINMINER_REPEAT", 3600));

    @TempDir
    static Path codeDir;
    static PythonScenarioEngine engine;

    static AppProperties props(Path dir) {
        String exe = System.getenv().getOrDefault("PYTHON_EXECUTABLE", "python3");
        return new AppProperties("test", "test", false, false, 5, 4, 15, 24, 30, 12, "http://localhost", ".",
                new AppProperties.ClickHouse("http://localhost:8123", "", "", "", "", "", ""),
                new AppProperties.Case("", ""),
                new AppProperties.Python(exe, TestFiles.ROOT.resolve("python").toString(), dir.toString(), 2, 10),
                new AppProperties.Init(false, 0, "draft"));
    }

    @BeforeAll
    static void start() {
        AppProperties p = props(codeDir);
        engine = new PythonScenarioEngine(p, new ScenarioCodeStore(p), new SimpleMeterRegistry());
        try {
            engine.ping();
        } catch (RuntimeException e) {
            Assumptions.abort("Python 을 실행할 수 없어 건너뜀: " + e.getMessage());
        }
    }

    @AfterAll
    static void stop() {
        if (engine != null) {
            engine.close();
        }
    }

    static ScenarioProgram program(String sid) {
        Map<String, Object> g = TestFiles.scenario(sid);
        GraphValidation r = GraphValidator.validate(g);
        ScenarioCodeGenerator.GeneratedCode c = ScenarioCodeGenerator.generate(g, 1, r.maxSpanSec);
        return new ScenarioProgram(sid, 1, c.code(), c.sha256(), false);
    }

    static Hit hit(String rule, double minutes) {
        LocalDateTime t = T0.plusSeconds((long) (minutes * 60));
        return new Hit(rule, 1, "ORG001", "10.0.0.1", t, t, t, 10.0, 5.0, List.of("e1"), t, WIN.getOrDefault(rule, 0));
    }

    static EvalOutcome eval(String sid, List<Hit> hits, Set<String> tags) {
        return engine.evaluateOne(program(sid), new EvalCase("ORG001", "10.0.0.1", hits, tags, null));
    }

    static EvalOutcome evalNew(String sid, List<Hit> hits, Set<EvalModels.HitKey> fresh) {
        return engine.evaluateOne(program(sid), new EvalCase("ORG001", "10.0.0.1", hits, Set.of(), fresh));
    }

    @SuppressWarnings("unchecked")
    static String reason(EvalOutcome o, String node) {
        return (String) ((Map<String, Object>) o.nodeStatus().get(node)).get("reason");
    }

    @Test
    void smbWormBranches() {
        EvalOutcome r = eval("SC_SMB_WORM", List.of(hit("SR_SMB_OUT_FANOUT", 0)), Set.of());
        assertEquals("high", r.chosen().severity());
        assertEquals("a2", r.chosen().node());
        r = eval("SC_SMB_WORM", List.of(hit("SR_SMB_OUT_FANOUT", 0)), Set.of("legacy_os"));
        assertEquals("critical", r.chosen().severity());
        assertEquals(List.of("no", "yes"), r.chosen().path().stream()
                .filter(s -> List.of("check", "asset").contains(s.get("type"))).map(s -> s.get("result")).toList());
        assertEquals("SMB 웜 전파 (고위험): 10.0.0.1", r.chosen().title());
        // check: 앞뒤 24시간 안의 WannaCry 히트 (뒤에 생겨도 예)
        r = eval("SC_SMB_WORM", List.of(hit("SR_SMB_OUT_FANOUT", 0), hit("SR_WANNACRY_SIG", 23 * 60)), Set.of());
        assertEquals("critical", r.chosen().severity());
        r = eval("SC_SMB_WORM", List.of(hit("SR_SMB_OUT_FANOUT", 0), hit("SR_WANNACRY_SIG", 25 * 60)), Set.of());
        assertEquals("high", r.chosen().severity());
        r = eval("SC_SMB_WORM", List.of(), Set.of());
        assertEquals("no_hit", reason(r, "n1"));
        assertTrue(r.reachedAlerts().isEmpty());
    }

    @Test
    void sequenceWithin() {
        assertNotNull(eval("SC_BRUTEFORCE_SUCCESS", List.of(hit("SR_AUTH_BRUTEFORCE", 0), hit("SR_AUTH_SUCCESS", 20)), Set.of()).chosen());
        EvalOutcome r = eval("SC_BRUTEFORCE_SUCCESS", List.of(hit("SR_AUTH_BRUTEFORCE", 0), hit("SR_AUTH_SUCCESS", 45)), Set.of());
        assertTrue(r.reachedAlerts().isEmpty());
        assertEquals("timeout", reason(r, "n2"));
        // 순서가 반대면 성립하지 않는다
        assertTrue(eval("SC_BRUTEFORCE_SUCCESS", List.of(hit("SR_AUTH_SUCCESS", 0), hit("SR_AUTH_BRUTEFORCE", 20)), Set.of())
                .reachedAlerts().isEmpty());
    }

    @Test
    void differentWindowSizesOrder() {
        // 1분 창 히트(10:07) 뒤의 10분 창 히트는 버킷 시작(10:00)이 앞서도 '이후'로 본다
        assertNotNull(eval("SC_WEB_ATTACK_SUCCESS", List.of(hit("SR_WAF_BURST", 7), hit("SR_NEW_OUTBOUND", 0)), Set.of()).chosen());
        assertTrue(eval("SC_WEB_ATTACK_SUCCESS", List.of(hit("SR_WAF_BURST", 17), hit("SR_NEW_OUTBOUND", 0)), Set.of())
                .reachedAlerts().isEmpty());
        assertTrue(eval("SC_WEB_ATTACK_SUCCESS", List.of(hit("SR_WAF_BURST", 0), hit("SR_NEW_OUTBOUND", 70)), Set.of())
                .reachedAlerts().isEmpty());
    }

    @Test
    void andOrJoinWithin24h() {
        assertNotNull(eval("SC_REMOTE_TOOL_MALICIOUS", List.of(hit("SR_REMOTE_TOOL", 0), hit("SR_TI_HIT", 23 * 60)), Set.of()).chosen());
        assertNotNull(eval("SC_REMOTE_TOOL_MALICIOUS", List.of(hit("SR_MALWARE_SIG", 0), hit("SR_REMOTE_TOOL", 60)), Set.of()).chosen());
        // v2 (사례 11): and 합류가 안 되면 n4(check, 앞뒤 24h) 의 no 가지로 "도구만 사용" 낮음 경보가 난다
        EvalOutcome r = eval("SC_REMOTE_TOOL_MALICIOUS", List.of(hit("SR_REMOTE_TOOL", 0), hit("SR_TI_HIT", 25 * 60)), Set.of());
        assertEquals(List.of("a2"), r.reachedAlerts());
        assertEquals("low", r.chosen().severity());
        assertEquals("timeout", reason(r, "j2"));
        r = eval("SC_REMOTE_TOOL_MALICIOUS", List.of(hit("SR_REMOTE_TOOL", 0)), Set.of());
        assertEquals(List.of("a2"), r.reachedAlerts());
        assertEquals("branch_missing", reason(r, "j2"));
        assertTrue(eval("SC_REMOTE_TOOL_MALICIOUS", List.of(hit("SR_TI_HIT", 0)), Set.of()).reachedAlerts().isEmpty());
    }

    @Test
    void newHitsFilter() {
        Hit old = hit("SR_COINMINER", 0);
        assertNotNull(evalNew("SC_COINMINER", List.of(old), Set.of(old.key())).chosen());
        assertNull(evalNew("SC_COINMINER", List.of(old), Set.of(hit("SR_TI_HIT", 1).key())).chosen());
        Hit rep = hit("SR_COINMINER_REPEAT", 30);
        EvalOutcome r = evalNew("SC_COINMINER", List.of(old, rep), Set.of(rep.key()));
        assertEquals("high", r.chosen().severity());
    }

    @Test
    void batchKeepsOrder() {
        ScenarioProgram p = program("SC_SMB_WORM");
        List<EvalOutcome> outs = engine.evaluate(p, List.of(
                new EvalCase("ORG001", "10.0.0.1", List.of(hit("SR_SMB_OUT_FANOUT", 0)), Set.of(), null),
                new EvalCase("ORG001", "10.0.0.1", List.of(hit("SR_SMB_OUT_FANOUT", 0)), Set.of("kiosk"), null),
                new EvalCase("ORG001", "10.0.0.1", List.of(), Set.of(), null)));
        assertEquals("high", outs.get(0).chosen().severity());
        assertEquals("critical", outs.get(1).chosen().severity());
        assertNull(outs.get(2).chosen());
    }

    @Test
    void decidePolicy() {
        LocalDateTime now = T0;
        assertEquals(Decision.CREATE, AlertService.decide(null, "high", now, 3600));
        ExistingAlert ex = new ExistingAlert("a", "high", now.minusMinutes(10));
        assertEquals(Decision.TOUCH, AlertService.decide(ex, "high", now, 3600));
        assertEquals(Decision.TOUCH, AlertService.decide(ex, "medium", now, 3600));
        assertEquals(Decision.UPGRADE, AlertService.decide(ex, "critical", now, 3600));
        assertEquals(Decision.CREATE, AlertService.decide(new ExistingAlert("a", "high", now.minusHours(2)), "high", now, 3600));
    }
}
