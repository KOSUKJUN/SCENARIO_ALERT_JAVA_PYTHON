package com.scenarioalert.engine.scenario;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** 순서도 그래프 검증 결과. 오류는 노드·화살표 ID 와 함께: {"target": "node"|"edge"|"graph", "id", "message"}. */
public class GraphValidation {
    public record Issue(String target, String id, String message) {
        public Map<String, String> asMap() {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("target", target);
            m.put("id", id);
            m.put("message", message);
            return m;
        }
    }

    public final List<Issue> errors = new ArrayList<>();
    public final List<Issue> warnings = new ArrayList<>();
    public int maxSpanSec;
    public final Set<String> ruleRefs = new TreeSet<>();

    public boolean ok() {
        return errors.isEmpty();
    }

    public void err(String target, String id, String msg) {
        errors.add(new Issue(target, id, msg));
    }

    public void warn(String target, String id, String msg) {
        warnings.add(new Issue(target, id, msg));
    }

    public List<Map<String, String>> errorMaps() {
        return errors.stream().map(Issue::asMap).toList();
    }

    public List<Map<String, String>> warningMaps() {
        return warnings.stream().map(Issue::asMap).toList();
    }

    public String summary() {
        StringBuilder sb = new StringBuilder();
        for (Issue i : errors) {
            if (!sb.isEmpty()) {
                sb.append("; ");
            }
            sb.append(i.id()).append(": ").append(i.message());
        }
        return sb.toString();
    }

    /** 검증 실패 예외 (API 에서 422). */
    public static class GraphValidationException extends RuntimeException {
        public final GraphValidation result;

        public GraphValidationException(GraphValidation result) {
            super(result.summary());
            this.result = result;
        }
    }
}
