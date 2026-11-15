package com.scenarioalert.engine.scenario;

import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.scenario.ScenarioCodeGenerator.GeneratedCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 시나리오별 Python 코드 생성 (Python 없이 확인할 수 있는 부분). 실행 결과는 ScenarioEvaluationTest. */
class ScenarioCodeGeneratorTest {
    static List<Path> builtin() {
        return TestFiles.builtinScenarios();
    }

    static GeneratedCode gen(Map<String, Object> g, int v) {
        GraphValidation r = GraphValidator.validate(g);
        assertTrue(r.ok(), String.valueOf(r.errors));
        return ScenarioCodeGenerator.generate(g, v, r.maxSpanSec);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("builtin")
    void generatesOneModulePerScenario(Path p) {
        Map<String, Object> g = TestFiles.json(p);
        GeneratedCode c = gen(g, 3);
        assertTrue(c.code().contains("SCENARIO_ID = \"" + g.get("id") + "\""));
        assertTrue(c.code().contains("VERSION = 3"));
        assertTrue(c.code().contains("def evaluate(hits, asset_tags):"));
        assertTrue(c.code().contains("from scenario_runtime import runtime as rt"));
        // 노드마다 연산 한 줄
        for (Object o : Json.asList(g.get("nodes"))) {
            String id = (String) Json.asMap(o).get("id");
            assertTrue(c.code().contains("\"" + id + "\""), id);
        }
        assertEquals(64, c.sha256().length());
    }

    @Test
    void deterministicAndVersioned() {
        Map<String, Object> g = TestFiles.scenario("SC_SMB_WORM");
        assertEquals(gen(g, 1).code(), gen(Json.copy(g), 1).code());
        assertNotEquals(gen(g, 1).sha256(), gen(g, 2).sha256());
    }

    @Test
    void smbWormStructure() {
        String code = gen(TestFiles.scenario("SC_SMB_WORM"), 1).code();
        assertTrue(code.contains("ev.rule(\"n1\", \"SR_SMB_OUT_FANOUT\", t0_n0, within=None)"), code);
        assertTrue(code.contains("ev.check(\"n2\", (\"SR_WANNACRY_SIG\", \"SR_TI_HIT\"), t1_n1, lookaround=86400)"), code);
        assertTrue(code.contains("ev.asset(\"n3\", (\"legacy_os\", \"medical_device\", \"kiosk\"), t2_n2_no)"), code);
        // a1 은 두 갈래(n2 yes, n3 yes)에서 온다
        assertTrue(Pattern.compile("ev\\.alert\\(\"a1\", \"critical\",[\\s\\S]*\\(t2_n2_yes, t3_n3_yes\\)\\)").matcher(code).find(), code);
    }

    @Test
    void userStringsCannotEscapeLiterals() {
        Map<String, Object> g = TestFiles.scenario("SC_SMB_WORM");
        for (Object o : Json.asList(g.get("nodes"))) {
            Map<String, Object> n = Json.asMap(o);
            if ("a1".equals(n.get("id"))) {
                n.put("title", "x\"\"\")\nimport os; os.system('rm -rf /') # \\ \u2028 \u0000 {{entity}}");
                n.put("playbook", "line1\r\nline2\t\"q\" '");
            }
        }
        g.put("name", "\"; import os #\n");
        String code = gen(g, 1).code();
        // 사용자 문자열의 줄바꿈은 이스케이프되어 코드 줄이 새로 생기지 않는다
        for (String line : code.split("\n")) {
            assertFalse(line.startsWith("import os"), line);
        }
        assertTrue(code.contains("\\nimport os; os.system('rm -rf /') # \\\\ \\u2028 \\u0000 {{entity}}"), code);
        assertTrue(code.contains("NAME = \"\\\"; import os #\\n\""), code);
    }

    @Test
    void pyLiteralKeepsKorean() {
        assertEquals("\"SMB 웜 전파\"", ScenarioCodeGenerator.py("SMB 웜 전파"));
        assertEquals("\"a\\\\b\\\"c\"", ScenarioCodeGenerator.py("a\\b\"c"));
        assertEquals("\"😀\"", ScenarioCodeGenerator.py("😀"));  // 인쇄 가능한 기호는 그대로
        assertEquals("\"\\ue000\\U000f0000\"", ScenarioCodeGenerator.py("󰀀"));  // 사용자 정의 영역은 이스케이프
    }

    @Test
    void joinNodes() {
        String code = gen(TestFiles.scenario("SC_REMOTE_TOOL_MALICIOUS"), 1).code();
        assertTrue(code.contains("ev.and_("), code);
        assertTrue(code.contains("ev.or_("), code);
    }
}
