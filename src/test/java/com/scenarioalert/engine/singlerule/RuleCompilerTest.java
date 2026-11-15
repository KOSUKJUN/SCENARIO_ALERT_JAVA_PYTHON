package com.scenarioalert.engine.singlerule;

import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.singlerule.RuleCompiler.CompiledRule;
import com.scenarioalert.engine.singlerule.RuleCompiler.ListInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M2: 컴파일러 출력. Python 원본(scenario-alert-engine-python)의 스냅샷과 글자 하나까지 같아야 한다.
 * 정렬 키 조건, sum(event_count), 값은 파라미터로만.
 */
class RuleCompilerTest {
    static final Map<String, ListInfo> FAKE = Map.of(
            "wannacry_killswitch_domains", new ListInfo("wannacry_killswitch_domains", "domain", null, List.of("killswitch.example")),
            "threat_domains", new ListInfo("threat_domains", "domain", null, List.of("bad-c2.example")),
            "coinmining_pools", new ListInfo("coinmining_pools", "domain", null, List.of("pool.example")),
            "smb_allowed_sources", new ListInfo("smb_allowed_sources", "ip", null, List.of("10.10.1.99")),
            "false_positive_hosts", new ListInfo("false_positive_hosts", "ip", null, List.of()),
            "internal_nets", new ListInfo("internal_nets", "cidr", "ORG001", List.of("10.0.0.0/8")));
    static final Function<String, ListInfo> LOADER = FAKE::get;

    static List<Path> rules() {
        return TestFiles.builtinRules();
    }

    static ParsedRule parsed(Path p) {
        return RuleValidator.parse(TestFiles.yaml(p), FAKE::containsKey);
    }

    /** Python 테스트와 같은 표기: "-- p0 = 'X'" (repr). */
    static String snapshotText(CompiledRule c) {
        return c.sql() + "\n-- params\n" + c.params().entrySet().stream()
                .map(e -> "-- " + e.getKey() + " = " + RuleCompiler.pyRepr(e.getValue()))
                .collect(Collectors.joining("\n")) + "\n";
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rules")
    void realtimeMatchesPythonSnapshot(Path path) throws Exception {
        CompiledRule c = RuleCompiler.compileRealtime(parsed(path), LOADER);
        Path snap = Path.of("src/test/resources/snapshots/" + TestFiles.stem(path) + ".sql");
        assertEquals(Files.readString(snap).replace("\r\n", "\n"), snapshotText(c),
                "컴파일 결과가 Python 원본 스냅샷과 다릅니다");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rules")
    void everyQueryHasSortKeyConditions(Path path) {
        ParsedRule p = parsed(path);
        String dtp = "data_tp IN (" + p.dataTp().stream().map(d -> "'" + d + "'").collect(Collectors.joining(", ")) + ")";
        for (CompiledRule c : List.of(RuleCompiler.compileRealtime(p, LOADER), RuleCompiler.compileBacktest(p, LOADER),
                RuleCompiler.compilePreview(p, LOADER), RuleCompiler.compileBucketCount(p, LOADER, 0.5))) {
            assertTrue(Pattern.compile("mgr_time >= .*mgr_time < ").matcher(c.sql()).find(), "mgr_time 범위 조건 없음");
            assertTrue(c.sql().contains(dtp), "data_tp 조건 없음");
            assertTrue(c.sql().contains("LIMIT") || c.sql().contains("count() AS hits"));
        }
    }

    @Test
    void countUsesSumEventCount() {
        String sql = RuleCompiler.compileRealtime(parsed(TestFiles.ROOT.resolve("rules/builtin/single/SR_AUTH_BRUTEFORCE.yaml")),
                LOADER).sql();
        assertTrue(sql.contains("sum(event_count)"));
        assertFalse(sql.contains("count()"));
    }

    @Test
    void valuesOnlyAsParameters() {
        String evil = "x'); DROP TABLE detect.rule_hits; --";
        Map<String, Object> d = Map.of("id", "SR_INJ", "name", "주입", "type", "signature",
                "entity", Map.of("type", "host", "field", "src_ip"), "data_tp", List.of("IDS"), "window", "5m",
                "filter", Map.of("any", List.of(
                        Map.of("field", "payload", "op", "contains", "value", evil),
                        Map.of("field", "signature_name", "op", "eq", "value", evil),
                        Map.of("field", "payload", "op", "regex", "value", "a'b"),
                        Map.of("field", "signature_name", "op", "in", "value", List.of(evil, "ok")))));
        CompiledRule c = RuleCompiler.compileRealtime(RuleValidator.parse(d, x -> true), LOADER);
        assertFalse(c.sql().contains("DROP TABLE"));
        assertFalse(c.sql().contains("a'b"));
        assertTrue(c.params().values().stream().anyMatch(v -> String.valueOf(v).contains(evil)));
    }

    @Test
    void cidrListScope() {
        Map<String, Object> d = Map.of("id", "SR_CIDR", "name", "대역", "type", "signature",
                "entity", Map.of("type", "host", "field", "src_ip"), "data_tp", List.of("FIREWALL"), "window", "5m",
                "filter", Map.of("all", List.of(Map.of("field", "dst_ip", "op", "in_list", "value", "internal_nets"))));
        String sql = RuleCompiler.compileRealtime(RuleValidator.parse(d, x -> true), LOADER).sql();
        assertTrue(sql.contains("isIPAddressInRange") && sql.contains("org_id = {p"));
    }
}
