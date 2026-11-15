package com.scenarioalert.engine.scenario;

import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 순서도(그래프 JSON) → 시나리오 전용 Python 모듈.
 *
 * <p>시나리오가 저장될 때마다(버전마다) 한 번 생성한다. 생성 코드는 노드를 위상 순서로 펼친 직선 코드이며
 * 노드 연산은 python/scenario_runtime/runtime.py 를 쓴다. 생성 코드는 DB·파일·네트워크에 접근하지 않는 순수 함수
 * evaluate(hits, asset_tags) 하나를 내보낸다.</p>
 *
 * <p>안전 규칙: 사용자가 입력한 문자열(이름, 제목, 대응 방법, 룰 ID, 태그 …)은 모두 {@link #py(String)} 로
 * 이스케이프한 문자열 리터럴로만 들어간다. 주석에는 정규식으로 검증된 노드 ID 와 노드 유형만 쓴다.
 * 반드시 {@link GraphValidator} 를 통과한 그래프만 넘긴다.</p>
 */
public final class ScenarioCodeGenerator {
    /** 생성기 버전. 생성 규칙이 바뀌면 올린다 (기존 버전 코드는 DB 에 남은 그대로 쓴다). */
    public static final String GENERATOR = "java-codegen/1";
    /** worker.py 의 PROTOCOL 과 맞춘다. */
    public static final int PROTOCOL = 1;
    private static final ObjectMapper CANON = Json.MAPPER.copy().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    public record GeneratedCode(String code, String sha256, String graphSha256) {
    }

    private ScenarioCodeGenerator() {
    }

    public static GeneratedCode generate(Map<String, Object> graph, int version, int maxSpanSec) {
        Map<String, Map<String, Object>> nodes = new LinkedHashMap<>();
        for (Object o : Json.asList(graph.get("nodes"))) {
            Map<String, Object> n = Json.asMap(o);
            nodes.put((String) n.get("id"), n);
        }
        List<Map<String, Object>> edges = new ArrayList<>();
        for (Object o : Json.asList(graph.get("edges"))) {
            edges.add(Json.asMap(o));
        }
        List<String> order = GraphValidator.topoOrder(new ArrayList<>(nodes.keySet()), edges);
        if (order == null) {
            throw new IllegalArgumentException("순환이 있는 그래프는 코드로 만들 수 없습니다");
        }
        Map<String, List<Map<String, Object>>> incoming = new LinkedHashMap<>();
        nodes.keySet().forEach(n -> incoming.put(n, new ArrayList<>()));
        for (Map<String, Object> e : edges) {
            incoming.get((String) e.get("to")).add(e);
        }
        Map<String, String> var = new LinkedHashMap<>();
        for (int i = 0; i < order.size(); i++) {
            var.put(order.get(i), "t" + i + "_" + order.get(i).replace('-', '_'));
        }

        java.util.TreeSet<String> ruleIds = new java.util.TreeSet<>();
        for (Map<String, Object> n : nodes.values()) {
            if ("rule".equals(n.get("type"))) {
                ruleIds.add((String) n.get("rule_id"));
            } else if ("check".equals(n.get("type"))) {
                ruleIds.addAll(Json.strings(n.get("rule_ids")));
            }
        }
        String graphSha = sha256(canonical(graph));
        String sid = (String) graph.get("id");

        StringBuilder b = new StringBuilder();
        b.append("# -*- coding: utf-8 -*-\n");
        b.append("# =============================================================================\n");
        b.append("# 자동 생성 코드 - 직접 고치지 마세요.\n");
        b.append("# 순서도를 저장하면 Java(ScenarioCodeGenerator)가 버전마다 이 파일을 새로 만듭니다.\n");
        b.append("# 노드 연산의 의미는 python/scenario_runtime/runtime.py 를 보세요.\n");
        b.append("# =============================================================================\n");
        b.append("from scenario_runtime import runtime as rt\n\n");
        b.append("PROTOCOL = ").append(PROTOCOL).append('\n');
        b.append("GENERATOR = ").append(py(GENERATOR)).append('\n');
        b.append("SCENARIO_ID = ").append(py(sid)).append('\n');
        b.append("VERSION = ").append(version).append('\n');
        b.append("NAME = ").append(py(String.valueOf(graph.get("name")))).append('\n');
        b.append("ENTITY_TYPE = ").append(py(String.valueOf(graph.get("entity_type")))).append('\n');
        b.append("SUPPRESS_SEC = ").append(Kst.parseDuration(graph.getOrDefault("suppress_for", "6h"))).append('\n');
        b.append("MAX_SPAN_SEC = ").append(maxSpanSec).append('\n');
        b.append("RULE_IDS = ").append(pyTuple(new ArrayList<>(ruleIds))).append('\n');
        b.append("GRAPH_SHA256 = ").append(py(graphSha)).append("\n\n\n");

        b.append("def evaluate(hits, asset_tags):\n");
        b.append("    \"\"\"순서도를 따라가며 도달한 경보 노드와 노드별 성립 상태를 돌려준다 (순수 함수).\"\"\"\n");
        b.append("    ev = rt.Evaluation(hits, asset_tags)\n");
        for (String nid : order) {
            Map<String, Object> n = nodes.get(nid);
            String t = (String) n.get("type");
            String v = var.get(nid);
            List<Map<String, Object>> ins = incoming.get(nid);
            List<String> inVars = new ArrayList<>();
            List<String> inFrom = new ArrayList<>();
            for (Map<String, Object> e : ins) {
                String from = (String) e.get("from");
                inFrom.add(from);
                String fv = var.get(from);
                if (GraphValidator.DIAMONDS.contains(nodes.get(from).get("type"))) {
                    fv = fv + ("yes".equals(e.get("branch")) ? "_yes" : "_no");
                }
                inVars.add(fv);
            }
            b.append("\n    # [").append(nid).append("] ").append(t);
            if (!inFrom.isEmpty()) {
                b.append("  <- ").append(String.join(", ", inFrom));
            }
            b.append('\n');
            switch (t) {
                case "start" -> b.append("    ").append(v).append(" = ev.start(").append(py(nid)).append(")\n");
                case "rule" -> {
                    Map<String, Object> e = ins.get(0);
                    String within = e.containsKey("within") ? String.valueOf(Kst.parseDuration(e.get("within"))) : "None";
                    b.append("    ").append(v).append(" = ev.rule(").append(py(nid)).append(", ")
                            .append(py((String) n.get("rule_id"))).append(", ").append(inVars.get(0))
                            .append(", within=").append(within).append(")\n");
                }
                case "check" -> b.append("    ").append(v).append("_yes, ").append(v).append("_no = ev.check(")
                        .append(py(nid)).append(", ").append(pyTuple(Json.strings(n.get("rule_ids")))).append(", ")
                        .append(inVars.get(0)).append(", lookaround=").append(Kst.parseDuration(n.get("lookaround")))
                        .append(")\n");
                case "asset" -> b.append("    ").append(v).append("_yes, ").append(v).append("_no = ev.asset(")
                        .append(py(nid)).append(", ").append(pyTuple(Json.strings(n.get("tags")))).append(", ")
                        .append(inVars.get(0)).append(")\n");
                case "or" -> b.append("    ").append(v).append(" = ev.or_(").append(py(nid)).append(", ")
                        .append(tupleOfVars(inVars)).append(")\n");
                case "and" -> b.append("    ").append(v).append(" = ev.and_(").append(py(nid)).append(", ")
                        .append(tupleOfVars(inVars)).append(", ").append(pyTuple(inFrom)).append(", within=")
                        .append(Kst.parseDuration(n.get("within"))).append(")\n");
                case "alert" -> {
                    Object pb = n.get("playbook");
                    b.append("    ev.alert(").append(py(nid)).append(", ").append(py((String) n.get("severity")))
                            .append(",\n             ").append(py((String) n.get("title")))
                            .append(",\n             ").append(py(pb == null ? "" : String.valueOf(pb)))
                            .append(",\n             ").append(tupleOfVars(inVars)).append(")\n");
                }
                default -> throw new IllegalArgumentException("알 수 없는 노드 유형: " + t);
            }
        }
        b.append("\n    return ev.result()\n");
        String code = b.toString();
        return new GeneratedCode(code, sha256(code), graphSha);
    }

    private static String tupleOfVars(List<String> vars) {
        return "(" + String.join(", ", vars) + (vars.size() == 1 ? ",)" : ")");
    }

    static String pyTuple(List<String> items) {
        List<String> lits = items.stream().map(ScenarioCodeGenerator::py).toList();
        return "(" + String.join(", ", lits) + (lits.size() == 1 ? ",)" : ")");
    }

    /**
     * Python 문자열 리터럴. 따옴표·역슬래시·제어 문자·줄 구분 문자는 이스케이프하고, 한글 등 인쇄 가능한 문자는 그대로 둔다.
     */
    public static String py(String s) {
        StringBuilder sb = new StringBuilder("\"");
        s.codePoints().forEach(cp -> {
            switch (cp) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (cp >= 0x20 && cp < 0x7f) {
                        sb.append((char) cp);
                    } else if (cp >= 0xa0 && printable(cp)) {
                        sb.appendCodePoint(cp);
                    } else if (cp <= 0xffff) {
                        sb.append(String.format("\\u%04x", cp));
                    } else {
                        sb.append(String.format("\\U%08x", cp));
                    }
                }
            }
        });
        return sb.append('"').toString();
    }

    private static boolean printable(int cp) {
        int type = Character.getType(cp);
        return type != Character.CONTROL && type != Character.FORMAT && type != Character.LINE_SEPARATOR
                && type != Character.PARAGRAPH_SEPARATOR && type != Character.SURROGATE && type != Character.PRIVATE_USE
                && type != Character.UNASSIGNED && type != Character.SPACE_SEPARATOR;
    }

    static String canonical(Map<String, Object> graph) {
        try {
            return CANON.writeValueAsString(graph);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
