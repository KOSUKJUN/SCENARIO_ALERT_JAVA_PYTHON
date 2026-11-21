package com.scenarioalert.engine.scenario;

import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.d3fend.D3fendService;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.meta.Fields;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * 순서도 그래프 모델 검증 (설계안 5장). 검증을 통과한 그래프만 Python 코드로 생성한다.
 */
public final class GraphValidator {
    public static final Pattern SCENARIO_ID_RE = Pattern.compile("^[A-Z][A-Z0-9_]{2,63}$");
    public static final Pattern NODE_ID_RE = Pattern.compile("^[A-Za-z0-9_\\-]{1,32}$");
    static final Pattern TAG_RE = Pattern.compile("^[a-z0-9][a-z0-9_\\-]{0,63}$");
    public static final int MAX_SPAN_SEC = 7 * 86400;
    static final Set<String> DIAMONDS = Set.of("check", "asset");
    static final Map<String, Set<String>> NODE_KEYS = Map.of(
            "start", Set.of(),
            "rule", Set.of("rule_id"),
            "check", Set.of("rule_ids", "lookaround"),
            "asset", Set.of("tags"),
            "and", Set.of("within"),
            "or", Set.of(),
            "alert", Set.of("severity", "title", "playbook", "attack", "d3fend"));
    static final Set<String> COMMON_NODE_KEYS = Set.of("id", "type", "pos", "label");
    static final Set<String> GRAPH_KEYS = Set.of("id", "name", "description", "entity_type", "status", "suppress_for",
            "nodes", "edges");
    static final Set<String> EDGE_KEYS = Set.of("from", "to", "branch", "within", "id");

    /** 참조 룰 정보 (검증용). */
    public record RuleRef(String ruleId, String entityType, String status) {
    }

    private GraphValidator() {
    }

    public static String edgeId(Map<String, Object> e) {
        return e.get("from") + "->" + e.get("to");
    }

    /** 위상 순서 (노드 선언 순서 기준 FIFO). 순환이면 null. */
    public static List<String> topoOrder(List<String> nodeIds, List<Map<String, Object>> edges) {
        Map<String, Integer> indeg = new LinkedHashMap<>();
        Map<String, List<String>> out = new HashMap<>();
        for (String n : nodeIds) {
            indeg.put(n, 0);
            out.put(n, new ArrayList<>());
        }
        for (Map<String, Object> e : edges) {
            Object f = e.get("from");
            Object t = e.get("to");
            if (out.containsKey(f) && indeg.containsKey(t)) {
                out.get(f).add((String) t);
                indeg.merge((String) t, 1, Integer::sum);
            }
        }
        Deque<String> q = new ArrayDeque<>();
        indeg.forEach((n, d) -> {
            if (d == 0) {
                q.add(n);
            }
        });
        List<String> order = new ArrayList<>();
        while (!q.isEmpty()) {
            String n = q.poll();
            order.add(n);
            for (String m : out.get(n)) {
                int d = indeg.merge(m, -1, Integer::sum);
                if (d == 0) {
                    q.add(m);
                }
            }
        }
        return order.size() == nodeIds.size() ? order : null;
    }

    public static GraphValidation validate(Object graph) {
        return validate(graph, null, null);
    }

    /**
     * @param ruleLookup    참조 룰 조회 (null 이면 참조 검사 생략)
     * @param requireStatus 참조 룰이 가져야 할 상태 (silent 전환 시 silent/active, active 전환 시 active)
     */
    public static GraphValidation validate(Object graphObj, Function<String, RuleRef> ruleLookup, List<String> requireStatus) {
        GraphValidation res = new GraphValidation();
        Map<String, Object> graph = Json.asMap(graphObj);
        if (graph == null) {
            res.err("graph", "", "그래프는 객체여야 합니다");
            return res;
        }
        for (String k : new TreeSet<>(graph.keySet())) {
            if (!GRAPH_KEYS.contains(k)) {
                res.err("graph", k, "알 수 없는 항목입니다");
            }
        }
        if (!(graph.get("id") instanceof String sid) || !SCENARIO_ID_RE.matcher(sid).matches()) {
            res.err("graph", "id", "ID는 대문자로 시작하고 대문자·숫자·_ 로 3~64자여야 합니다 (예: SC_SMB_WORM)");
        }
        if (!(graph.get("name") instanceof String name) || name.isBlank() || name.length() > 200) {
            res.err("graph", "name", "이름은 1~200자여야 합니다");
        }
        Object etype = graph.get("entity_type");
        if (!(etype instanceof String et) || !Fields.ENTITY_TYPES.containsKey(et)) {
            res.err("graph", "entity_type", "대상 유형은 " + String.join(", ", Fields.ENTITY_TYPES.keySet()) + " 중 하나입니다");
        }
        try {
            int sup = Kst.parseDuration(graph.getOrDefault("suppress_for", "6h"));
            if (sup > MAX_SPAN_SEC) {
                res.err("graph", "suppress_for", "억제 시간은 7일 이하입니다");
            }
        } catch (IllegalArgumentException e) {
            res.err("graph", "suppress_for", e.getMessage());
        }
        Object desc = graph.get("description");
        if (desc != null && (!(desc instanceof String ds) || ds.length() > 2000)) {
            res.err("graph", "description", "설명은 2000자 이하 문자열입니다");
        }

        List<Object> nodesRaw = Json.asList(graph.get("nodes"));
        List<Object> edgesRaw = Json.asList(graph.get("edges"));
        if (nodesRaw == null || edgesRaw == null) {
            res.err("graph", "nodes", "nodes 와 edges 는 목록이어야 합니다");
            return res;
        }

        Map<String, Map<String, Object>> nodes = new LinkedHashMap<>();
        for (int i = 0; i < nodesRaw.size(); i++) {
            Map<String, Object> n = Json.asMap(nodesRaw.get(i));
            if (n == null) {
                res.err("node", "#" + i, "노드는 객체여야 합니다");
                continue;
            }
            Object nidO = n.get("id");
            if (!(nidO instanceof String nid) || !NODE_ID_RE.matcher(nid).matches()) {
                res.err("node", String.valueOf(nidO), "노드 ID 형식이 아닙니다 (영문, 숫자, _, - 1~32자)");
                continue;
            }
            if (nodes.containsKey(nid)) {
                res.err("node", nid, "노드 ID가 중복됩니다");
                continue;
            }
            Object ntype = n.get("type");
            if (!(ntype instanceof String nt) || !NODE_KEYS.containsKey(nt)) {
                res.err("node", nid, "알 수 없는 노드 유형: " + Json.repr(ntype));
                continue;
            }
            Set<String> extra = new TreeSet<>(n.keySet());
            extra.removeAll(COMMON_NODE_KEYS);
            extra.removeAll(NODE_KEYS.get(nt));
            if (!extra.isEmpty()) {
                res.err("node", nid, nt + " 노드에 쓸 수 없는 속성: " + String.join(", ", extra));
            }
            Object pos = n.get("pos");
            if (pos != null) {
                List<Object> pl = Json.asList(pos);
                if (pl == null || pl.size() != 2 || !pl.stream().allMatch(Json::isNumber)) {
                    res.err("node", nid, "pos 는 [x, y] 숫자 쌍입니다");
                }
            }
            Object label = n.get("label");
            if (label != null && (!(label instanceof String ls) || ls.length() > 200)) {
                res.err("node", nid, "label 은 200자 이하 문자열입니다");
            }
            nodes.put(nid, n);
        }

        List<Map<String, Object>> edges = new ArrayList<>();
        Set<String> seenEdges = new HashSet<>();
        for (int i = 0; i < edgesRaw.size(); i++) {
            Map<String, Object> e = Json.asMap(edgesRaw.get(i));
            if (e == null) {
                res.err("edge", "#" + i, "화살표는 객체여야 합니다");
                continue;
            }
            String eid = edgeId(e);
            Set<String> extra = new TreeSet<>(e.keySet());
            extra.removeAll(EDGE_KEYS);
            if (!extra.isEmpty()) {
                res.err("edge", eid, "알 수 없는 속성: " + String.join(", ", extra));
            }
            Object f = e.get("from");
            Object t = e.get("to");
            if (!(f instanceof String) || !(t instanceof String) || !nodes.containsKey(f) || !nodes.containsKey(t)) {
                res.err("edge", eid, "존재하지 않는 노드를 잇습니다");
                continue;
            }
            if (f.equals(t)) {
                res.err("edge", eid, "자기 자신을 잇는 화살표입니다");
                continue;
            }
            if (!seenEdges.add(f + "\u0000" + t)) {
                res.err("edge", eid, "같은 화살표가 중복됩니다");
                continue;
            }
            edges.add(e);
        }

        if (!res.ok()) {
            return res;
        }

        List<Map<String, Object>> starts = nodes.values().stream().filter(n -> "start".equals(n.get("type"))).toList();
        List<Map<String, Object>> alerts = nodes.values().stream().filter(n -> "alert".equals(n.get("type"))).toList();
        if (starts.size() != 1) {
            res.err("graph", "start", "시작 노드는 1개여야 합니다 (현재 " + starts.size() + "개)");
        }
        if (alerts.isEmpty()) {
            res.err("graph", "alert", "경보 노드가 1개 이상 있어야 합니다");
        }

        Map<String, List<Map<String, Object>>> incoming = new LinkedHashMap<>();
        Map<String, List<Map<String, Object>>> outgoing = new LinkedHashMap<>();
        for (String n : nodes.keySet()) {
            incoming.put(n, new ArrayList<>());
            outgoing.put(n, new ArrayList<>());
        }
        for (Map<String, Object> e : edges) {
            outgoing.get((String) e.get("from")).add(e);
            incoming.get((String) e.get("to")).add(e);
        }

        List<String> order = topoOrder(new ArrayList<>(nodes.keySet()), edges);
        if (order == null) {
            res.err("graph", "cycle", "순환이 있습니다");
        }

        // 노드별 규칙
        for (Map.Entry<String, Map<String, Object>> en : nodes.entrySet()) {
            String nid = en.getKey();
            Map<String, Object> n = en.getValue();
            String t = (String) n.get("type");
            List<Map<String, Object>> ins = incoming.get(nid);
            List<Map<String, Object>> outs = outgoing.get(nid);
            switch (t) {
                case "start" -> {
                    if (!ins.isEmpty()) {
                        res.err("node", nid, "시작 노드로 들어오는 화살표가 있습니다");
                    }
                }
                case "rule", "check", "asset" -> {
                    if (ins.size() != 1) {
                        res.err("node", nid, "들어오는 화살표가 1개여야 합니다 (여러 가지를 모으려면 and/or 합류를 쓰세요)");
                    }
                }
                case "and", "or" -> {
                    if (ins.size() < 2) {
                        res.err("node", nid, "합류 노드는 들어오는 화살표가 2개 이상이어야 합니다");
                    }
                }
                case "alert" -> {
                    if (ins.isEmpty()) {
                        res.err("node", nid, "경보 노드로 들어오는 화살표가 없습니다");
                    }
                    if (!outs.isEmpty()) {
                        res.err("node", nid, "경보 노드에서 나가는 화살표가 있습니다");
                    }
                }
                default -> {
                }
            }
            if (!t.equals("alert") && outs.isEmpty()) {
                res.err("node", nid, "나가는 화살표가 없습니다");
            }
            if (DIAMONDS.contains(t)) {
                List<String> branches = new ArrayList<>();
                for (Map<String, Object> o : outs) {
                    if (o.get("branch") instanceof String b) {
                        branches.add(b);
                    }
                }
                branches.sort(null);
                if (!branches.equals(List.of("no", "yes")) || outs.size() != 2) {
                    res.err("node", nid, "마름모는 예(yes)와 아니오(no) 화살표를 하나씩 가져야 합니다");
                }
            } else {
                for (Map<String, Object> o : outs) {
                    if (o.containsKey("branch")) {
                        res.err("edge", edgeId(o), "branch 는 마름모(check, asset)에서 나가는 화살표에만 씁니다");
                    }
                }
            }

            switch (t) {
                case "rule" -> {
                    if (!(n.get("rule_id") instanceof String rid) || rid.isEmpty()) {
                        res.err("node", nid, "rule_id 가 필요합니다");
                    } else {
                        res.ruleRefs.add(rid);
                    }
                }
                case "check" -> {
                    List<Object> rids = Json.asList(n.get("rule_ids"));
                    if (rids == null || rids.isEmpty() || !rids.stream().allMatch(r -> r instanceof String s && !s.isEmpty())) {
                        res.err("node", nid, "rule_ids(1개 이상)가 필요합니다");
                    } else {
                        rids.forEach(r -> res.ruleRefs.add((String) r));
                    }
                    try {
                        int lk = Kst.parseDuration(n.getOrDefault("lookaround", ""));
                        if (lk > MAX_SPAN_SEC) {
                            res.err("node", nid, "lookaround 는 7일 이하입니다");
                        }
                    } catch (IllegalArgumentException ex) {
                        res.err("node", nid, "lookaround: " + ex.getMessage());
                    }
                }
                case "asset" -> {
                    List<Object> tags = Json.asList(n.get("tags"));
                    if (tags == null || tags.isEmpty()
                            || !tags.stream().allMatch(x -> x instanceof String s && TAG_RE.matcher(s).matches())) {
                        res.err("node", nid, "tags(소문자 태그 1개 이상)가 필요합니다");
                    }
                }
                case "and" -> {
                    try {
                        Kst.parseDuration(n.getOrDefault("within", ""));
                    } catch (IllegalArgumentException ex) {
                        res.err("node", nid, "within: " + ex.getMessage());
                    }
                }
                case "alert" -> {
                    if (!(n.get("severity") instanceof String sev) || !Fields.SEVERITIES.contains(sev)) {
                        res.err("node", nid, "등급은 " + String.join(", ", Fields.SEVERITIES) + " 중 하나입니다");
                    }
                    if (!(n.get("title") instanceof String title) || title.isBlank() || title.length() > 300) {
                        res.err("node", nid, "제목은 1~300자여야 합니다");
                    }
                    Object pb = n.get("playbook");
                    if (pb != null && (!(pb instanceof String ps) || ps.length() > 4000)) {
                        res.err("node", nid, "playbook 은 4000자 이하 문자열입니다");
                    }
                    String attackErr = AttackService.formatError(n.get("attack"));
                    if (attackErr != null) {
                        res.err("node", nid, attackErr);
                    }
                    String d3fendErr = D3fendService.formatError(n.get("d3fend"));
                    if (d3fendErr != null) {
                        res.err("node", nid, d3fendErr);
                    }
                }
                default -> {
                }
            }
        }

        // 화살표 within
        for (Map<String, Object> e : edges) {
            Map<String, Object> src = nodes.get((String) e.get("from"));
            Map<String, Object> dst = nodes.get((String) e.get("to"));
            Object b = e.get("branch");
            if (b != null && !"yes".equals(b) && !"no".equals(b)) {
                res.err("edge", edgeId(e), "branch 는 yes 또는 no 입니다");
            }
            if (e.containsKey("within")) {
                if (!"rule".equals(dst.get("type"))) {
                    res.err("edge", edgeId(e), "within 은 rule 노드로 들어가는 화살표에만 씁니다");
                } else if ("start".equals(src.get("type"))) {
                    res.err("edge", edgeId(e), "시작 노드에서 나가는 화살표에는 within 이 없습니다");
                } else {
                    try {
                        int w = Kst.parseDuration(e.get("within"));
                        if (w > MAX_SPAN_SEC) {
                            res.err("edge", edgeId(e), "within 은 7일 이하입니다");
                        }
                    } catch (IllegalArgumentException ex) {
                        res.err("edge", edgeId(e), "within: " + ex.getMessage());
                    }
                }
            } else if ("rule".equals(dst.get("type")) && !"start".equals(src.get("type"))) {
                res.err("edge", edgeId(e), "rule 노드로 들어가는 화살표에는 허용 시간(within)이 필요합니다");
            }
        }

        // 도달 가능성
        if (starts.size() == 1) {
            Set<String> seen = new HashSet<>();
            Deque<String> stack = new ArrayDeque<>();
            String s0 = (String) starts.get(0).get("id");
            seen.add(s0);
            stack.push(s0);
            while (!stack.isEmpty()) {
                String cur = stack.pop();
                for (Map<String, Object> e : outgoing.get(cur)) {
                    String to = (String) e.get("to");
                    if (seen.add(to)) {
                        stack.push(to);
                    }
                }
            }
            for (String nid : nodes.keySet()) {
                if (!seen.contains(nid)) {
                    res.err("node", nid, "시작 노드에서 도달할 수 없습니다");
                }
            }
        }

        // 참조 룰
        if (ruleLookup != null) {
            for (String rid : res.ruleRefs) {
                RuleRef ref = ruleLookup.apply(rid);
                String hid = rid;
                for (Map.Entry<String, Map<String, Object>> en : nodes.entrySet()) {
                    Map<String, Object> n = en.getValue();
                    if (rid.equals(n.get("rule_id")) || Json.strings(n.get("rule_ids")).contains(rid)) {
                        hid = en.getKey();
                        break;
                    }
                }
                if (ref == null) {
                    res.err("node", hid, "참조한 이벤트 탐지모듈이 없습니다: " + rid);
                    continue;
                }
                if (etype instanceof String et && !ref.entityType().equals(et)) {
                    res.err("node", hid, rid + " 의 대상 유형(" + ref.entityType() + ")이 순서도(" + et + ")와 다릅니다");
                }
                if (requireStatus != null && !requireStatus.contains(ref.status())) {
                    res.err("node", hid, rid + " 상태가 " + ref.status() + " 입니다. 필요 상태: " + String.join(", ", requireStatus));
                } else if (ref.status().equals("draft") || ref.status().equals("disabled")) {
                    res.warn("node", hid, rid + " 상태가 " + ref.status() + " 라 실시간 평가에서 히트가 생기지 않습니다");
                }
            }
        }

        // 최대 기간 (시작→경보 경로의 within + lookaround 합)
        if (order != null && res.ok()) {
            Map<String, Integer> span = new HashMap<>();
            for (String nid : order) {
                Map<String, Object> n = nodes.get(nid);
                int best = 0;
                for (Map<String, Object> e : incoming.get(nid)) {
                    int w = e.containsKey("within") ? Kst.parseDuration(e.get("within")) : 0;
                    best = Math.max(best, span.get((String) e.get("from")) + w);
                }
                if ("check".equals(n.get("type"))) {
                    best += Kst.parseDuration(n.get("lookaround"));
                }
                if ("and".equals(n.get("type"))) {
                    best += Kst.parseDuration(n.get("within"));
                }
                span.put(nid, best);
            }
            res.maxSpanSec = alerts.stream().mapToInt(a -> span.get((String) a.get("id"))).max().orElse(0);
            if (res.maxSpanSec > MAX_SPAN_SEC) {
                res.err("graph", "span", "시작에서 경보까지 허용 시간 합이 7일을 넘습니다 (" + res.maxSpanSec + "초)");
            }
        }
        return res;
    }
}
