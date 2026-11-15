package com.scenarioalert.engine.common;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * MariaDB 접근 도구 (named parameter). 결과 행은 Map 이고 값은 응답에 바로 쓸 수 있게 정규화한다.
 * Timestamp → LocalDateTime(KST), BigDecimal → Long/Double, UUID → String, byte[] → String.
 */
@Component
public class Db {
    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public Db(NamedParameterJdbcTemplate jdbc, PlatformTransactionManager tm) {
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(tm);
    }

    public NamedParameterJdbcTemplate jdbc() {
        return jdbc;
    }

    /** 트랜잭션 (성공 시 commit, 예외 시 rollback). 이미 트랜잭션 안이면 참여한다. */
    public <T> T tx(Supplier<T> body) {
        return tx.execute(s -> body.get());
    }

    public void txRun(Runnable body) {
        tx.executeWithoutResult(s -> body.run());
    }

    public List<Map<String, Object>> rows(String sql, Map<String, ?> params) {
        List<Map<String, Object>> raw = jdbc.queryForList(sql, new MapSqlParameterSource(params == null ? Map.of() : params));
        List<Map<String, Object>> out = new ArrayList<>(raw.size());
        for (Map<String, Object> r : raw) {
            Map<String, Object> m = new LinkedHashMap<>();
            r.forEach((k, v) -> m.put(k, norm(v)));
            out.add(m);
        }
        return out;
    }

    public List<Map<String, Object>> rows(String sql) {
        return rows(sql, Map.of());
    }

    public Map<String, Object> row(String sql, Map<String, ?> params) {
        List<Map<String, Object>> r = rows(sql, params);
        return r.isEmpty() ? null : r.get(0);
    }

    public int execute(String sql, Map<String, ?> params) {
        return jdbc.update(sql, new MapSqlParameterSource(params == null ? Map.of() : params));
    }

    public void audit(String actor, String action, String target, Object detail) {
        execute("INSERT INTO audit_log (actor, action, target, detail) VALUES (:a, :ac, :t, :d)",
                p("a", actor, "ac", action, "t", target.length() > 200 ? target.substring(0, 200) : target,
                        "d", detail == null ? null : Json.dump(detail)));
    }

    /** 파라미터 Map (null 허용). */
    public static Map<String, Object> p(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    public static Object norm(Object v) {
        if (v instanceof Timestamp ts) {
            return ts.toLocalDateTime();
        }
        if (v instanceof BigDecimal bd) {
            try {
                return bd.longValueExact();
            } catch (ArithmeticException e) {
                return bd.doubleValue();
            }
        }
        if (v instanceof BigInteger bi) {
            return bi.longValue();
        }
        if (v instanceof UUID u) {
            return u.toString();
        }
        if (v instanceof byte[] b) {
            return new String(b, java.nio.charset.StandardCharsets.UTF_8);
        }
        return v;
    }

    // ---------- 값 꺼내기 ----------
    public static String str(Map<String, Object> r, String k) {
        Object v = r.get(k);
        return v == null ? null : String.valueOf(v);
    }

    public static long lng(Map<String, Object> r, String k) {
        Object v = r.get(k);
        if (v == null) {
            return 0;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        if (v instanceof Boolean b) {
            return b ? 1 : 0;
        }
        return Long.parseLong(String.valueOf(v));
    }

    public static int integer(Map<String, Object> r, String k) {
        return (int) lng(r, k);
    }

    public static double dbl(Map<String, Object> r, String k) {
        Object v = r.get(k);
        return v instanceof Number n ? n.doubleValue() : 0.0;
    }

    public static boolean bool(Map<String, Object> r, String k) {
        Object v = r.get(k);
        if (v instanceof Boolean b) {
            return b;
        }
        return v instanceof Number n && n.intValue() != 0;
    }

    public static LocalDateTime time(Map<String, Object> r, String k) {
        Object v = r.get(k);
        if (v instanceof LocalDateTime t) {
            return t;
        }
        if (v instanceof Timestamp ts) {
            return ts.toLocalDateTime();
        }
        return v == null ? null : Kst.parse(String.valueOf(v));
    }
}
