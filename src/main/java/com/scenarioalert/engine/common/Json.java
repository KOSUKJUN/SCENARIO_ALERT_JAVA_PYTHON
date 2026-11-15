package com.scenarioalert.engine.common;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON 도구. 룰 정의와 순서도 그래프는 Python 원본과 같이 "검증 전 자유 형식"이라 Map/List 로 다룬다.
 * 응답 직렬화 규칙: LocalDateTime 은 +09:00 ISO 문자열, 키 순서는 넣은 순서.
 */
public final class Json {
    public static final ObjectMapper MAPPER = build();
    public static final YAMLMapper YAML = new YAMLMapper();
    private static final TypeReference<LinkedHashMap<String, Object>> MAP_T = new TypeReference<>() {
    };

    private Json() {
    }

    private static ObjectMapper build() {
        SimpleModule kst = new SimpleModule("kst");
        kst.addSerializer(LocalDateTime.class, new JsonSerializer<>() {
            @Override
            public void serialize(LocalDateTime v, JsonGenerator g, SerializerProvider p) throws IOException {
                g.writeString(Kst.iso(v));
            }
        });
        kst.addSerializer(LocalDate.class, new JsonSerializer<>() {
            @Override
            public void serialize(LocalDate v, JsonGenerator g, SerializerProvider p) throws IOException {
                g.writeString(v.toString());
            }
        });
        return JsonMapper.builder()
                .addModule(new JavaTimeModule())
                .addModule(kst)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .build();
    }

    public static String dump(Object v) {
        try {
            return MAPPER.writeValueAsString(v);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Object load(String s) {
        if (s == null) {
            return null;
        }
        try {
            return MAPPER.readValue(s, Object.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("JSON 형식이 아닙니다: " + e.getMessage(), e);
        }
    }

    public static Map<String, Object> loadMap(String s) {
        if (s == null) {
            return null;
        }
        try {
            return MAPPER.readValue(s, MAP_T);
        } catch (IOException e) {
            throw new IllegalArgumentException("JSON 형식이 아닙니다: " + e.getMessage(), e);
        }
    }

    public static Map<String, Object> loadYamlMap(String s) {
        try {
            return YAML.readValue(s, MAP_T);
        } catch (IOException e) {
            throw new IllegalArgumentException("YAML 형식이 아닙니다: " + e.getMessage(), e);
        }
    }

    /** 깊은 복사 (JSON 왕복). */
    public static Map<String, Object> copy(Map<String, Object> m) {
        return loadMap(dump(m));
    }

    // ---------- 자유 형식 값 판별 ----------
    @SuppressWarnings("unchecked")
    public static Map<String, Object> asMap(Object v) {
        return v instanceof Map<?, ?> ? (Map<String, Object>) v : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asList(Object v) {
        return v instanceof List<?> ? (List<Object>) v : null;
    }

    public static boolean isInt(Object v) {
        return v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof java.math.BigInteger;
    }

    public static boolean isNumber(Object v) {
        return v instanceof Number && !(v instanceof Boolean);
    }

    public static List<String> strings(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof Collection<?> c) {
            for (Object o : c) {
                if (o instanceof String s) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    /** 오류 메시지용 표현 (Python repr 과 비슷하게). */
    public static String repr(Object v) {
        if (v == null) {
            return "None";
        }
        if (v instanceof String s) {
            return "'" + s + "'";
        }
        return String.valueOf(v);
    }

    /** LinkedHashMap 짧은 생성: Json.obj("a", 1, "b", 2). null 값도 넣는다. */
    public static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }
}
