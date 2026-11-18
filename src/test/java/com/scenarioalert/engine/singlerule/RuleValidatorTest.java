package com.scenarioalert.engine.singlerule;

import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.common.Json;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** M2: 단일룰 정의 검증. 잘못된 정의 20종 이상이 원인 메시지와 함께 거부되고, SQL 주입 시도가 거부된다. */
class RuleValidatorTest {
    static final Set<String> LISTS = Set.of("smb_allowed_sources", "false_positive_hosts", "wannacry_killswitch_domains",
            "threat_domains", "coinmining_pools", "threat_ip", "php2shell_request_markers", "web_cmd_output_markers",
            "web_downloader_markers");

    static Map<String, Object> base() {
        return Json.loadMap("""
                {"id": "SR_TEST_RULE", "name": "테스트", "type": "count",
                 "entity": {"type": "host", "field": "src_ip"}, "data_tp": ["FIREWALL", "IPS", "TMS"],
                 "filter": {"all": [{"field": "net_direction", "op": "eq", "value": "outbound"},
                                    {"field": "dst_port", "op": "eq", "value": 445}]},
                 "aggregate": {"func": "distinct_count", "field": "dst_ip"}, "window": "10m", "threshold": 20,
                 "schedule": "1m", "severity": "medium"}""");
    }

    static Map<String, Object> mut(Consumer<Map<String, Object>> f) {
        Map<String, Object> d = base();
        f.accept(d);
        return d;
    }

    static Map<String, Object> filter(String json) {
        return Json.loadMap(json);
    }

    static Stream<Arguments> invalid() {
        return Stream.of(
                Arguments.of("id 형식", mut(d -> d.put("id", "sr-bad id")), "id", "ID는"),
                Arguments.of("이름 없음", mut(d -> d.put("name", "")), "name", "이름"),
                Arguments.of("유형 오류", mut(d -> d.put("type", "sequence")), "type", "유형은"),
                Arguments.of("대상 유형 오류", mut(d -> d.put("entity", Map.of("type", "user", "field", "src_ip"))), "entity.type", "대상 유형"),
                Arguments.of("대상 필드 오류", mut(d -> d.put("entity", Map.of("type", "host", "field", "payload"))), "entity.field", "대상 필드"),
                Arguments.of("data_tp 없음", mut(d -> d.remove("data_tp")), "data_tp", "필수"),
                Arguments.of("data_tp 알 수 없음", mut(d -> d.put("data_tp", List.of("FIREWALL", "SIEM"))), "data_tp[1]", "알 수 없는"),
                Arguments.of("허용되지 않은 필드", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"secret_col\",\"op\":\"eq\",\"value\":1}]}"))),
                        "filter.all[0].field", "허용되지 않은"),
                Arguments.of("연산자 불일치", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"dst_port\",\"op\":\"contains\",\"value\":\"44\"}]}"))),
                        "filter.all[0].op", "쓸 수 없는 연산자"),
                Arguments.of("값 타입 오류", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"dst_port\",\"op\":\"eq\",\"value\":\"445\"}]}"))),
                        "filter.all[0].value", "정수"),
                Arguments.of("IP 형식 오류", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"dst_ip\",\"op\":\"eq\",\"value\":\"10.0.0.999\"}]}"))),
                        "filter.all[0].value", "IP 형식"),
                Arguments.of("CIDR 형식 오류", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"dst_ip\",\"op\":\"cidr\",\"value\":\"10.0.0.0/99\"}]}"))),
                        "filter.all[0].value", "CIDR"),
                Arguments.of("정규식 역참조", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"payload\",\"op\":\"regex\",\"value\":\"(a)\\\\1\"}]}"))),
                        "filter.all[0].value", "역참조"),
                Arguments.of("없는 리스트", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"src_ip\",\"op\":\"in_list\",\"value\":\"no_such_list\"}]}"))),
                        "filter.all[0].value", "리스트가 없습니다"),
                Arguments.of("모든 유형에서 빈 필드", mut(d -> d.put("data_tp", List.of("IDS", "UTM", "WAF"))), "filter.all[1]", "모두에서 비어"),
                Arguments.of("카운트형 집계 없음", mut(d -> d.remove("aggregate")), "aggregate", "aggregate"),
                Arguments.of("임계치 0", mut(d -> d.put("threshold", 0)), "threshold", "임계치"),
                Arguments.of("창 형식 오류", mut(d -> d.put("window", "10 minutes")), "window", "시간 형식"),
                Arguments.of("창이 주기의 배수 아님", mut(d -> {
                    d.put("window", "5m");
                    d.put("schedule", "2m");
                }), "schedule", "배수"),
                Arguments.of("주기가 1시간을 나누지 못함", mut(d -> {
                    d.put("window", "1h");
                    d.put("schedule", "7m");
                }), "schedule", "1시간을 나누어"),
                Arguments.of("알 수 없는 항목", mut(d -> d.put("sql", "SELECT 1")), "sql", "알 수 없는 항목"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalid")
    void invalidDefinitionsRejected(String label, Map<String, Object> defn, String path, String msg) {
        RuleValidator.Result r = RuleValidator.validate(defn, LISTS::contains);
        assertNull(r.parsed(), label);
        assertTrue(r.validation().errors.stream().anyMatch(e -> e.path().equals(path) && e.message().contains(msg)),
                label + ": " + path + " 에 '" + msg + "' 오류가 없음. 실제: " + r.validation().errors);
    }

    @Test
    void atLeastTwentyKinds() {
        assertTrue(invalid().count() >= 20);
    }

    static Stream<Arguments> injection() {
        return Stream.of(
                Arguments.of("필드명", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"src_ip) OR 1=1 --\",\"op\":\"eq\",\"value\":\"x\"}]}")))),
                Arguments.of("연산자", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"src_ip\",\"op\":\"= '' OR 1=1 --\",\"value\":\"x\"}]}")))),
                Arguments.of("대상 필드", mut(d -> d.put("entity", Map.of("type", "host", "field", "src_ip; DROP TABLE detect.rule_hits")))),
                Arguments.of("데이터 유형", mut(d -> d.put("data_tp", List.of("FIREWALL') OR ('1'='1")))),
                Arguments.of("룰 ID", mut(d -> d.put("id", "SR_X'; DROP TABLE alerts; --"))),
                Arguments.of("집계 필드", mut(d -> d.put("aggregate", Map.of("func", "distinct_count", "field", "dst_ip)) FROM system.users --")))),
                Arguments.of("집계 함수", mut(d -> d.put("aggregate", Map.of("func", "sum(1); DROP", "field", "dst_ip")))),
                Arguments.of("리스트 ID", mut(d -> d.put("exclude_lists", List.of("x' OR '1'='1")))),
                Arguments.of("창", mut(d -> d.put("window", "10m; DROP TABLE x"))),
                Arguments.of("태그", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"src_asset_tags\",\"op\":\"has_tag\",\"value\":\"a') OR 1=1 --\"}]}")))),
                Arguments.of("IP 값", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"src_ip\",\"op\":\"eq\",\"value\":\"192.0.2.1' OR '1'='1\"}]}")))),
                Arguments.of("포트 값", mut(d -> d.put("filter", filter("{\"all\":[{\"field\":\"dst_port\",\"op\":\"eq\",\"value\":\"445 OR 1=1\"}]}")))),
                Arguments.of("등급", mut(d -> d.put("severity", "high'; --"))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("injection")
    void sqlInjectionStructureRejected(String label, Map<String, Object> defn) {
        RuleValidator.Result r = RuleValidator.validate(defn, LISTS::contains);
        assertNull(r.parsed(), label);
        assertFalse(r.validation().errors.isEmpty(), label);
    }

    @Test
    void portOnIdsWarnsButAllows() {
        RuleValidator.Result r = RuleValidator.validate(mut(d -> d.put("data_tp", List.of("FIREWALL", "IDS"))), LISTS::contains);
        assertNotNull(r.parsed());
        assertTrue(r.validation().warnings.stream().anyMatch(w -> w.message().contains("IDS") && w.path().startsWith("filter")));
    }

    static List<Path> builtin() {
        return TestFiles.builtinRules();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("builtin")
    void builtinRulesValid(Path p) {
        RuleValidator.Result r = RuleValidator.validate(TestFiles.yaml(p), LISTS::contains);
        assertNotNull(r.parsed(), String.valueOf(r.validation().errors));
    }

    @Test
    void builtinCount() {
        // 원본 14 + 7 에 사고 사례 기반 7 + 6, PHP2Shell 3 + 1 을 더했다 (docs/cases.md)
        assertEquals(24, TestFiles.builtinRules().size());
        assertEquals(14, TestFiles.builtinScenarios().size());
    }
}
