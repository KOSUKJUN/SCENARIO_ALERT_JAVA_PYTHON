package com.scenarioalert.engine.scenario;

import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.scenario.GraphValidator.RuleRef;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** M3: 그래프 검증. 잘못된 그래프 15종 이상 거부, 기본 순서도 7개 통과. */
class GraphValidatorTest {
    static final Map<String, RuleRef> RULES = Map.of(
            "SR_A", new RuleRef("SR_A", "host", "active"), "SR_B", new RuleRef("SR_B", "host", "active"),
            "SR_C", new RuleRef("SR_C", "host", "silent"), "SR_USER", new RuleRef("SR_USER", "user", "active"),
            "SR_DRAFT", new RuleRef("SR_DRAFT", "host", "draft"));
    static final Function<String, RuleRef> LOOKUP = RULES::get;

    static Map<String, Object> good() {
        return Json.loadMap("""
                {"id": "SC_TEST", "name": "테스트", "entity_type": "host", "suppress_for": "6h",
                 "nodes": [
                   {"id": "n0", "type": "start"},
                   {"id": "n1", "type": "rule", "rule_id": "SR_A"},
                   {"id": "n2", "type": "check", "rule_ids": ["SR_B"], "lookaround": "1h"},
                   {"id": "n3", "type": "rule", "rule_id": "SR_C"},
                   {"id": "a1", "type": "alert", "severity": "high", "title": "t1 {{entity}}"},
                   {"id": "a2", "type": "alert", "severity": "low", "title": "t2"}],
                 "edges": [
                   {"from": "n0", "to": "n1"}, {"from": "n1", "to": "n2"},
                   {"from": "n2", "to": "n3", "branch": "yes", "within": "30m"}, {"from": "n2", "to": "a2", "branch": "no"},
                   {"from": "n3", "to": "a1"}]}""");
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> nodes(Map<String, Object> g) {
        return (List<Map<String, Object>>) (List<?>) g.get("nodes");
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> edges(Map<String, Object> g) {
        return (List<Map<String, Object>>) (List<?>) g.get("edges");
    }

    static Map<String, Object> node(Map<String, Object> g, String id) {
        return nodes(g).stream().filter(n -> n.get("id").equals(id)).findFirst().orElseThrow();
    }

    static Map<String, Object> g(Consumer<Map<String, Object>> f) {
        Map<String, Object> x = good();
        f.accept(x);
        return x;
    }

    static Stream<Arguments> invalid() {
        return Stream.of(
                Arguments.of("순환", g(x -> edges(x).add(Json.obj("from", "n3", "to", "n1", "within", "1h"))), "순환"),
                Arguments.of("시작 노드 2개", g(x -> nodes(x).add(Json.obj("id", "n9", "type", "start"))), "시작 노드는 1개"),
                Arguments.of("시작 노드 없음", g(x -> {
                    nodes(x).remove(0);
                    edges(x).remove(0);
                }), "시작 노드는 1개"),
                Arguments.of("경보 노드 없음", g(x -> {
                    x.put("nodes", new ArrayList<>(nodes(x).stream().filter(n -> !"alert".equals(n.get("type"))).toList()));
                    x.put("edges", new ArrayList<>(edges(x).stream().filter(e -> !String.valueOf(e.get("to")).startsWith("a")).toList()));
                }), "경보 노드"),
                Arguments.of("도달 불가 노드", g(x -> {
                    nodes(x).add(Json.obj("id", "n8", "type", "rule", "rule_id", "SR_A"));
                    edges(x).add(Json.obj("from", "n8", "to", "a1"));
                }), "도달할 수 없습니다"),
                Arguments.of("나가는 화살표 없음", g(x -> edges(x).remove(4)), "나가는 화살표가 없습니다"),
                Arguments.of("마름모 가지 하나", g(x -> edges(x).remove(3)), "yes"),
                Arguments.of("마름모 같은 가지 둘", g(x -> edges(x).get(3).put("branch", "yes")), "하나씩"),
                Arguments.of("없는 룰 참조", g(x -> node(x, "n1").put("rule_id", "SR_NONE")), "없습니다: SR_NONE"),
                Arguments.of("대상 유형 다른 룰", g(x -> node(x, "n1").put("rule_id", "SR_USER")), "대상 유형"),
                Arguments.of("rule 화살표 within 없음", g(x -> edges(x).get(2).remove("within")), "within)이 필요"),
                Arguments.of("within 7일 초과", g(x -> edges(x).get(2).put("within", "8d")), "7일"),
                Arguments.of("허용 시간 합 7일 초과", g(x -> {
                    node(x, "n2").put("lookaround", "4d");
                    edges(x).get(2).put("within", "4d");
                }), "7일을 넘습니다"),
                Arguments.of("없는 노드 연결", g(x -> edges(x).add(Json.obj("from", "n1", "to", "zz"))), "존재하지 않는"),
                Arguments.of("경보 등급 오류", g(x -> node(x, "a1").put("severity", "urgent")), "등급"),
                Arguments.of("합류에 가지 하나", g(x -> {
                    nodes(x).add(Json.obj("id", "j1", "type", "or"));
                    edges(x).remove(4);
                    edges(x).add(Json.obj("from", "n3", "to", "j1"));
                    edges(x).add(Json.obj("from", "j1", "to", "a1"));
                }), "2개 이상"),
                Arguments.of("코드에 들어갈 수 없는 노드 ID", g(x -> node(x, "a2").put("id", "a2\"); import os #")), "노드 ID 형식"));
    }

    @Test
    void goodGraphValid() {
        GraphValidation r = GraphValidator.validate(good(), LOOKUP, null);
        assertTrue(r.ok(), String.valueOf(r.errors));
        assertEquals(3600 + 1800, r.maxSpanSec);
        assertEquals(Set.of("SR_A", "SR_B", "SR_C"), new HashSet<>(r.ruleRefs));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalid")
    void invalidGraphsRejected(String label, Map<String, Object> graph, String msg) {
        GraphValidation r = GraphValidator.validate(graph, LOOKUP, null);
        assertFalse(r.ok(), label);
        assertTrue(r.errors.stream().anyMatch(e -> e.message().contains(msg)), label + ": " + r.errors);
        assertTrue(r.errors.stream().allMatch(e -> List.of("node", "edge", "graph").contains(e.target())));
    }

    @Test
    void fifteenKinds() {
        assertTrue(invalid().count() >= 15);
    }

    @Test
    void statusRequirement() {
        Map<String, Object> x = g(y -> node(y, "n1").put("rule_id", "SR_DRAFT"));
        assertTrue(GraphValidator.validate(x, LOOKUP, null).ok());
        assertFalse(GraphValidator.validate(x, LOOKUP, null).warnings.isEmpty());
        assertFalse(GraphValidator.validate(x, LOOKUP, List.of("silent", "active")).ok());
        assertTrue(GraphValidator.validate(good(), LOOKUP, List.of("active")).errors.stream()
                .anyMatch(e -> e.message().contains("SR_C")));
    }

    static List<Path> builtin() {
        return TestFiles.builtinScenarios();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("builtin")
    void builtinScenariosValid(Path p) {
        java.util.Map<String, String> types = new java.util.HashMap<>();   // rule_id → entity.type (host | org)
        TestFiles.builtinRules().forEach(r -> {
            java.util.Map<String, Object> d = TestFiles.yaml(r);
            types.put((String) d.get("id"), String.valueOf(((java.util.Map<?, ?>) d.get("entity")).get("type")));
        });
        GraphValidation r = GraphValidator.validate(TestFiles.json(p),
                rid -> types.containsKey(rid) ? new RuleRef(rid, types.get(rid), "active") : null, null);
        assertTrue(r.ok(), String.valueOf(r.errors));
    }
}
