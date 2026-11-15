package com.scenarioalert.engine.singlerule;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 단일룰 검증 결과. 오류가 하나라도 있으면 저장·컴파일하지 않는다. 경고는 저장 가능. */
public class RuleValidation {
    public record Issue(String path, String message) {
        public Map<String, String> asMap() {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("path", path);
            m.put("message", message);
            return m;
        }
    }

    public final List<Issue> errors = new ArrayList<>();
    public final List<Issue> warnings = new ArrayList<>();

    public boolean ok() {
        return errors.isEmpty();
    }

    public void err(String path, String msg) {
        errors.add(new Issue(path, msg));
    }

    public void warn(String path, String msg) {
        warnings.add(new Issue(path, msg));
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
            sb.append(i.path()).append(": ").append(i.message());
        }
        return sb.toString();
    }
}
