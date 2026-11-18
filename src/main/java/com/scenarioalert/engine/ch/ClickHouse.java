package com.scenarioalert.engine.ch;

import com.fasterxml.jackson.core.type.TypeReference;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * ClickHouse HTTP 인터페이스 클라이언트. 모든 쿼리에 실행 시간 제한을 걸고, 용도별 사용자 프로필을 쓴다.
 * <ul>
 * <li>REALTIME : 실시간 탐지 (사용자 detect, 30초)</li>
 * <li>BACKTEST : 백테스트·미리보기 (사용자 detect_bt, 낮은 우선순위)</li>
 * <li>ADMIN    : DDL·샘플 데이터 적재 (개발·테스트 환경 전용)</li>
 * </ul>
 * 값은 {name:Type} 서버 측 파라미터로만 보낸다 (HTTP param_name). SQL 에 값을 잇지 않는다.
 */
@Component
public class ClickHouse {
    private static final Logger log = LoggerFactory.getLogger(ClickHouse.class);
    public static final int MAX_RESULT_ROWS = 100_000;
    private static final TypeReference<LinkedHashMap<String, Object>> ROW_T = new TypeReference<>() {
    };

    public enum Purpose {
        REALTIME(30), BACKTEST(300), ADMIN(600);
        final int timeoutSec;

        Purpose(int t) {
            this.timeoutSec = t;
        }
    }

    private final AppProperties.ClickHouse cfg;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public ClickHouse(AppProperties props) {
        this.cfg = props.clickhouse();
    }

    /** ClickHouse 오류 (쿼리 실패, 시간 초과). */
    public static class ClickHouseException extends RuntimeException {
        public ClickHouseException(String msg) {
            super(msg);
        }
    }

    // ---------------------------------------------------------------- 공개 API
    public List<Map<String, Object>> query(String sql, Map<String, ?> params) {
        return query(sql, params, Purpose.REALTIME, null);
    }

    public List<Map<String, Object>> query(String sql, Map<String, ?> params, Purpose purpose) {
        return query(sql, params, purpose, null);
    }

    public List<Map<String, Object>> query(String sql, Map<String, ?> params, Purpose purpose, Map<String, Object> settings) {
        Map<String, Object> st = new LinkedHashMap<>();
        st.put("max_result_rows", MAX_RESULT_ROWS);
        st.put("result_overflow_mode", "break");
        if (settings != null) {
            st.putAll(settings);
        }
        String body = send(sql + "\nFORMAT JSONEachRow", params, purpose, st);
        List<Map<String, Object>> out = new ArrayList<>();
        for (String line : body.split("\n")) {
            if (line.isBlank()) {
                continue;
            }
            try {
                out.add(Json.MAPPER.readValue(line, ROW_T));
            } catch (IOException e) {
                throw new ClickHouseException("결과 해석 실패: " + e.getMessage());
            }
        }
        return out;
    }

    public void command(String sql, Map<String, ?> params) {
        send(sql, params, Purpose.REALTIME, Map.of());
    }

    public void command(String sql, Map<String, ?> params, Purpose purpose) {
        send(sql, params, purpose, Map.of());
    }

    /** JSONEachRow 로 행을 넣는다. */
    public void insert(String table, List<String> columns, List<Map<String, Object>> rows, Purpose purpose) {
        if (rows.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder("INSERT INTO ").append(table).append(" (")
                .append(String.join(", ", columns)).append(") FORMAT JSONEachRow\n");
        for (Map<String, Object> r : rows) {
            sb.append(Json.dump(r)).append('\n');
        }
        send(sb.toString(), Map.of(), purpose, Map.of());
    }

    /** 설정 변경 후 딕셔너리 즉시 갱신 (실패해도 60초 주기 갱신으로 반영된다). */
    public void reloadDictionaries(Collection<String> names) {
        List<String> targets = names == null || names.isEmpty()
                ? List.of("dict_orgs", "dict_assets", "dict_list_items", "dict_threat_ip", "dict_signature_map",
                "dict_org_rule_params", "dict_log_sources")
                : List.copyOf(names);
        for (String n : targets) {
            try {
                command("SYSTEM RELOAD DICTIONARY detect." + n, Map.of());
            } catch (RuntimeException e) {
                log.debug("dictionary reload {} failed: {}", n, e.getMessage());
            }
        }
    }

    public void reloadDictionaries() {
        reloadDictionaries(null);
    }

    // ---------------------------------------------------------------- 전송
    private String send(String sql, Map<String, ?> params, Purpose purpose, Map<String, Object> settings) {
        String[] cred = switch (purpose) {
            case REALTIME -> new String[]{cfg.user(), cfg.password()};
            case BACKTEST -> new String[]{cfg.btUser(), cfg.btPassword()};
            case ADMIN -> new String[]{cfg.adminUser(), cfg.adminPassword()};
        };
        StringBuilder q = new StringBuilder("?max_execution_time=").append(purpose.timeoutSec)
                .append("&output_format_json_quote_64bit_integers=0&output_format_json_quote_64bit_floats=0")
                .append("&date_time_output_format=simple");
        settings.forEach((k, v) -> q.append('&').append(enc(k)).append('=').append(enc(String.valueOf(v))));
        if (params != null) {
            params.forEach((k, v) -> q.append("&param_").append(enc(k)).append('=').append(enc(formatParam(v))));
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(cfg.url().replaceAll("/+$", "") + "/" + q))
                .timeout(Duration.ofSeconds(purpose.timeoutSec + 30L))
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (cred[0] + ":" + (cred[1] == null ? "" : cred[1])).getBytes(StandardCharsets.UTF_8)))
                .header("Content-Type", "text/plain; charset=utf-8")
                .POST(HttpRequest.BodyPublishers.ofString(sql, StandardCharsets.UTF_8))
                .build();
        try {
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (res.statusCode() != 200) {
                String b = res.body();
                throw new ClickHouseException("ClickHouse HTTP " + res.statusCode() + ": "
                        + (b.length() > 2000 ? b.substring(0, 2000) : b).trim());
            }
            return res.body();
        } catch (IOException e) {
            throw new ClickHouseException("ClickHouse 연결 실패: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ClickHouseException("ClickHouse 요청 중단");
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /**
     * 서버 측 파라미터 값의 텍스트 표현.
     * 최상위 문자열은 Escaped 형식(\\, \t, \n), 배열 원소 문자열은 작은따옴표 Quoted 형식.
     */
    static String formatParam(Object v) {
        if (v == null) {
            return "\\N";
        }
        if (v instanceof String s) {
            return escapeTop(s);
        }
        if (v instanceof LocalDateTime t) {
            return Kst.fmt(t);
        }
        if (v instanceof Boolean b) {
            return b ? "1" : "0";
        }
        if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            return d == Math.rint(d) && !Double.isInfinite(d) ? String.format(Locale.ROOT, "%.1f", d) : String.valueOf(d);
        }
        if (v instanceof Number) {
            return String.valueOf(v);
        }
        if (v instanceof Collection<?> c) {
            List<String> items = new ArrayList<>();
            for (Object o : c) {
                items.add(o instanceof String s ? quoted(s) : formatParam(o));
            }
            return "[" + String.join(",", items) + "]";
        }
        return escapeTop(String.valueOf(v));
    }

    private static String escapeTop(String s) {
        return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String quoted(String s) {
        return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'";
    }

    // ---------------------------------------------------------------- 결과 값
    public static LocalDateTime time(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? null : Kst.parse(String.valueOf(v));
    }

    public static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? null : String.valueOf(v);
    }

    public static double num(Map<String, Object> row, String key) {
        Object v = row.get(key);
        if (v instanceof Number n) {
            return n.doubleValue();
        }
        return v == null ? 0 : Double.parseDouble(String.valueOf(v));
    }

    public static List<String> strList(Map<String, Object> row, String key) {
        return Json.strings(row.get(key));
    }
}
