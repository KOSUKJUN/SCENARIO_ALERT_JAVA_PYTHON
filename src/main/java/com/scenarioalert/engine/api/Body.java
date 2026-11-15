package com.scenarioalert.engine.api;

import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Json;

import java.util.List;
import java.util.Map;

/** 요청 본문(Map) 값 꺼내기. 형식이 틀리면 422. */
final class Body {
    private Body() {
    }

    static Map<String, Object> map(Map<String, Object> b, String k) {
        Map<String, Object> m = Json.asMap(b == null ? null : b.get(k));
        if (m == null) {
            throw new ApiException(422, "요청 형식이 올바르지 않습니다",
                    List.of(Map.of("path", k, "message", "객체가 필요합니다")), List.of());
        }
        return m;
    }

    static Map<String, Object> optMap(Map<String, Object> b, String k) {
        return Json.asMap(b == null ? null : b.get(k));
    }

    static String str(Map<String, Object> b, String k) {
        Object v = b == null ? null : b.get(k);
        if (v == null) {
            throw new ApiException(422, "요청 형식이 올바르지 않습니다",
                    List.of(Map.of("path", k, "message", "필수 항목입니다")), List.of());
        }
        return String.valueOf(v);
    }

    static String optStr(Map<String, Object> b, String k) {
        Object v = b == null ? null : b.get(k);
        return v == null ? null : String.valueOf(v);
    }

    static boolean bool(Map<String, Object> b, String k, boolean dflt) {
        Object v = b == null ? null : b.get(k);
        return v instanceof Boolean bo ? bo : dflt;
    }

    static Double optDouble(Map<String, Object> b, String k) {
        Object v = b == null ? null : b.get(k);
        if (v == null) {
            return null;
        }
        if (v instanceof Number n) {
            return n.doubleValue();
        }
        throw new ApiException(422, "요청 형식이 올바르지 않습니다", List.of(Map.of("path", k, "message", "숫자여야 합니다")),
                List.of());
    }

    static int intOr(Map<String, Object> b, String k, int dflt) {
        Object v = b == null ? null : b.get(k);
        return v instanceof Number n ? n.intValue() : dflt;
    }

    static List<String> strings(Map<String, Object> b, String k) {
        Object v = b == null ? null : b.get(k);
        return v == null ? null : Json.strings(v);
    }
}
