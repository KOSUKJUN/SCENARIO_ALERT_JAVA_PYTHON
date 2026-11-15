package com.scenarioalert.engine.singlerule;

import com.scenarioalert.engine.common.Ip;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.meta.Fields;
import com.scenarioalert.engine.meta.Fields.FieldDef;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

/**
 * 단일룰 정의 → ClickHouse SQL (설계안 4장).
 *
 * <ul>
 * <li>필드명은 {@link Fields} 허용 목록에서만 SQL 에 들어간다. 데이터 유형·대상 유형·창 길이는 검증된 열거값/정수만 인라인한다.</li>
 * <li>사용자가 입력한 값(문자열, 숫자, IP, 리스트 ID, 정규식 …)은 모두 서버 측 쿼리 파라미터 {pN:Type} 로 넘긴다.</li>
 * <li>모든 쿼리는 mgr_time 범위와 data_tp 조건을 먼저 건다 (원본 정렬 키). 건수는 count() 가 아니라 sum(event_count).</li>
 * </ul>
 * 형태: realtime(INSERT INTO rule_hits ... SELECT), backtest(과거 기간을 평가 주기 간격 창 끝마다 펼쳐 한 번에 계산), preview.
 */
public final class RuleCompiler {
    public static final int MAX_ROWS = 100_000;
    static final int MULTISEARCH_CHUNK = 200;

    /** 리스트 정보 (컴파일 때 펼치는 항목 포함). */
    public record ListInfo(String listId, String kind, String scopeOrgId, List<String> items) {
    }

    /** 컴파일 결과: SQL 과 서버 측 파라미터. */
    public record CompiledRule(String sql, Map<String, Object> params) {
    }

    private final ParsedRule r;
    private final Function<String, ListInfo> loadList;
    private final Map<String, Object> params = new LinkedHashMap<>();
    private int n;
    private final String rid;
    private String windowStart = "";

    public RuleCompiler(ParsedRule rule, Function<String, ListInfo> listLoader) {
        this.r = rule;
        this.loadList = listLoader;
        this.rid = p(rule.id(), "String");
    }

    private String p(Object value, String chType) {
        String name = "p" + n++;
        params.put(name, value);
        return "{" + name + ":" + chType + "}";
    }

    private static String likeEscape(String s) {
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    private static Object normScalar(String fname, Object v) {
        FieldDef f = Fields.FIELDS.get(fname);
        if (f.type().equals("ip")) {
            return Ip.normalize(String.valueOf(v));
        }
        if (f.type().equals("string") && RuleValidator.LOWER_FIELDS.contains(fname)) {
            return String.valueOf(v).toLowerCase(Locale.ROOT);
        }
        if (Json.isInt(v)) {
            return ((Number) v).longValue();
        }
        return v;
    }

    // ---------------------------------------------------------------- 조건
    private String listMembership(String expr, String listId) {
        ListInfo info = loadList.apply(listId);
        if ("cidr".equals(info.kind())) {
            List<String> cidrs = new ArrayList<>();
            for (String c : info.items()) {
                String nc = Ip.normalizeCidr(c);
                if (nc != null) {
                    cidrs.add(nc);
                }
            }
            if (cidrs.isEmpty()) {
                return "0";
            }
            String arr = p(cidrs, "Array(String)");
            String cond = "(" + expr + " != '' AND arrayExists(c -> isIPAddressInRange(" + expr + ", c), " + arr + "))";
            if (info.scopeOrgId() != null && !info.scopeOrgId().isEmpty()) {
                cond = "(org_id = " + p(info.scopeOrgId(), "String") + " AND " + cond + ")";
            }
            return cond;
        }
        String lp = p(listId, "String");
        return "has(['', org_id], dictGetOrDefault('detect.dict_list_items', 'scope', tuple(" + lp
                + ", lower(toString(" + expr + "))), '-'))";
    }

    @SuppressWarnings("unchecked")
    String cond(Map<String, Object> node) {
        if (node.containsKey("all")) {
            return "(" + String.join(" AND ", ((List<Object>) node.get("all")).stream()
                    .map(x -> cond(Json.asMap(x))).toList()) + ")";
        }
        if (node.containsKey("any")) {
            return "(" + String.join(" OR ", ((List<Object>) node.get("any")).stream()
                    .map(x -> cond(Json.asMap(x))).toList()) + ")";
        }
        if (node.containsKey("not")) {
            return "(NOT " + cond(Json.asMap(node.get("not"))) + ")";
        }
        String fname = (String) node.get("field");
        String op = (String) node.get("op");
        Object v = node.get("value");
        FieldDef f = Fields.FIELDS.get(fname);
        String col = fname;
        String ctype = switch (f.type()) {
            case "int" -> "Int64";
            case "bool" -> "UInt8";
            default -> "String";
        };

        if (f.type().equals("peer")) {
            // 평가 창 안에서 처음 관측된 (출발지, 목적지) 쌍
            return Boolean.TRUE.equals(v) ? "(peer_first >= " + windowStart + ")" : "(peer_first < " + windowStart + ")";
        }
        switch (op) {
            case "eq", "ne", "gte", "lte" -> {
                String sym = switch (op) {
                    case "eq" -> "=";
                    case "ne" -> "!=";
                    case "gte" -> ">=";
                    default -> "<=";
                };
                Object val = f.type().equals("bool") ? (Boolean.TRUE.equals(v) ? 1L : 0L) : normScalar(fname, v);
                return "(" + col + " " + sym + " " + p(val, ctype) + ")";
            }
            case "in", "not_in" -> {
                List<Object> vals = new ArrayList<>();
                for (Object x : (List<Object>) v) {
                    vals.add(normScalar(fname, x));
                }
                String arr = p(vals, "Array(" + ctype + ")");
                String target = f.nullable() ? "ifNull(" + col + ", -1)" : col;
                String expr = "has(" + arr + ", " + target + ")";
                return op.equals("in") ? expr : "(NOT " + expr + ")";
            }
            case "cidr" -> {
                String net = Ip.normalizeCidr(String.valueOf(v));
                return "(" + col + " != '' AND isIPAddressInRange(" + col + ", " + p(net, "String") + "))";
            }
            case "contains" -> {
                if (fname.equals("search_text")) {
                    return "(" + col + " LIKE " + p("%" + likeEscape(String.valueOf(v).toLowerCase(Locale.ROOT)) + "%", "String") + ")";
                }
                return "(positionCaseInsensitiveUTF8(" + col + ", " + p(String.valueOf(v), "String") + ") > 0)";
            }
            case "contains_list" -> {
                List<String> items = new ArrayList<>();
                for (String i : loadList.apply(String.valueOf(v)).items()) {
                    if (i != null && !i.isEmpty()) {
                        items.add(i.toLowerCase(Locale.ROOT));
                    }
                }
                if (items.isEmpty()) {
                    return "0";
                }
                List<String> parts = new ArrayList<>();
                for (int i = 0; i < items.size(); i += MULTISEARCH_CHUNK) {
                    String arr = p(new ArrayList<>(items.subList(i, Math.min(items.size(), i + MULTISEARCH_CHUNK))),
                            "Array(String)");
                    parts.add("multiSearchAnyCaseInsensitiveUTF8(" + col + ", " + arr + ")");
                }
                return "(" + String.join(" OR ", parts) + ")";
            }
            case "regex" -> {
                return "match(" + col + ", " + p(String.valueOf(v), "String") + ")";
            }
            case "in_list" -> {
                return listMembership(col, String.valueOf(v));
            }
            case "not_in_list" -> {
                return "(NOT " + listMembership(col, String.valueOf(v)) + ")";
            }
            case "has_tag" -> {
                return "has(" + col + ", " + p(String.valueOf(v), "String") + ")";
            }
            case "exists" -> {
                if (f.type().equals("tags")) {
                    return "notEmpty(" + col + ")";
                }
                if (f.nullable()) {
                    return "isNotNull(" + col + ")";
                }
                if (f.type().equals("string") || f.type().equals("ip")) {
                    return "(" + col + " != '')";
                }
                return "1";
            }
            default -> throw new IllegalArgumentException("unsupported op " + op);
        }
    }

    // ---------------------------------------------------------------- 공통 조각
    private String valueExpr() {
        if (r.type().equals("signature") || r.aggFunc().equals("count")) {
            return "toFloat64(sum(event_count))";
        }
        if (r.aggFunc().equals("distinct_count")) {
            return "toFloat64(uniqExact(" + r.aggField() + "))";
        }
        return "toFloat64(sum(" + r.aggField() + "))";
    }

    private String thresholdExpr(String mult) {
        String base = p(r.threshold(), "Float64");
        String orgThr = "dictGetOrDefault('detect.dict_org_rule_params', 'threshold', tuple(org_id, " + rid + "), -1.)";
        String expr = "if(" + orgThr + " < 0, " + base + ", " + orgThr + ")";
        return mult != null ? "(" + expr + " * " + mult + ")" : expr;
    }

    private List<String> commonWhere() {
        List<String> w = new ArrayList<>();
        w.add(r.entityField() + " != ''");
        w.add("dictGetOrDefault('detect.dict_org_rule_params', 'enabled', tuple(org_id, " + rid + "), toUInt8(1)) = 1");
        w.add(cond(r.filter()));
        for (String lid : r.excludeLists()) {
            w.add("(NOT " + listMembership(r.entityField(), lid) + ")");
        }
        return w;
    }

    private String source(String peerLowerBound) {
        if (!r.usesNewPeer()) {
            return "detect.v_events";
        }
        return "detect.v_events LEFT JOIN ("
                + "SELECT org_id, src_ip, dst_ip, min(first_seen) AS peer_first FROM detect.peer_first_seen "
                + "GROUP BY org_id, src_ip, dst_ip HAVING peer_first >= " + peerLowerBound
                + ") AS peers USING (org_id, src_ip, dst_ip)";
    }

    private String dtpIn() {
        // 검증된 열거값만 인라인 (정렬 키 조건)
        return "data_tp IN (" + String.join(", ", r.dataTp().stream().map(d -> "'" + d + "'").toList()) + ")";
    }

    // ---------------------------------------------------------------- 형태
    public CompiledRule realtime() {
        windowStart = "{win_from:DateTime64(3)}";
        List<String> where = new ArrayList<>();
        where.add("mgr_time >= {win_from:DateTime64(3)} AND mgr_time < {win_to:DateTime64(3)}");
        where.add(dtpIn());
        where.addAll(commonWhere());
        String valueExpr = valueExpr();
        String thr = thresholdExpr(null);
        String sql = "INSERT INTO detect.rule_hits\n"
                + "  (hit_bucket, rule_id, rule_version, org_id, entity_type, entity,\n"
                + "   first_seen, last_seen, value, threshold, sample_event_ids, run_id, win_to)\n"
                + "SELECT\n"
                + "  toStartOfInterval({win_to:DateTime64(3)}, INTERVAL " + r.windowSec() + " SECOND) AS hit_bucket,\n"
                + "  " + rid + " AS rule_id, {rule_version:UInt32} AS rule_version, org_id, '" + r.entityType() + "' AS entity_type,\n"
                + "  " + r.entityField() + " AS entity,\n"
                + "  min(event_time) AS first_seen, max(event_time) AS last_seen,\n"
                + "  " + valueExpr + " AS value,\n"
                + "  " + thr + " AS threshold,\n"
                + "  groupArray(20)(event_id) AS sample_event_ids,\n"
                + "  {run_id:UUID} AS run_id, {win_to:DateTime64(3)} AS win_to\n"
                + "FROM " + source("{win_from:DateTime64(3)}") + "\n"
                + "WHERE " + String.join("\n  AND ", where) + "\n"
                + "GROUP BY org_id, entity\n"
                + "HAVING value >= threshold\n"
                + "LIMIT " + MAX_ROWS;
        return new CompiledRule(sql, new LinkedHashMap<>(params));
    }

    /**
     * 과거 기간 [time_from, time_to] 의 모든 창 끝(평가 주기 간격)에 대한 (기관, 대상, 창 끝) 집계.
     * 이벤트 하나가 속하는 창 끝은 floor(mgr_time, 주기) + k*주기 (k = 1..창/주기) 이며,
     * 실시간 평가가 같은 창 끝에서 계산하는 [win_end - 창, win_end) 구간과 정확히 같다.
     */
    private String windowedSelect(String mult) {
        int step = r.scheduleSec();
        int win = r.windowSec();
        windowStart = "(win_end - toIntervalSecond(" + win + "))";
        List<String> where = new ArrayList<>();
        where.add("win_end > {time_from:DateTime64(3)} AND win_end <= {time_to:DateTime64(3)}");
        where.addAll(commonWhere());
        String valueExpr = valueExpr();
        String thr = thresholdExpr(mult);
        return "SELECT\n"
                + "    org_id, " + r.entityField() + " AS entity, win_end,\n"
                + "    toStartOfInterval(win_end, INTERVAL " + win + " SECOND) AS hit_bucket,\n"
                + "    min(event_time) AS first_seen, max(event_time) AS last_seen,\n"
                + "    " + valueExpr + " AS value,\n"
                + "    " + thr + " AS threshold,\n"
                + "    groupArray(20)(event_id) AS sample_event_ids\n"
                + "  FROM (\n"
                + "    SELECT *, arrayJoin(arrayMap(i -> toStartOfInterval(mgr_time, INTERVAL " + step + " SECOND)\n"
                + "                                      + toIntervalSecond((i + 1) * " + step + "), range(" + (win / step) + "))) AS win_end\n"
                + "    FROM " + source("({time_from:DateTime64(3)} - toIntervalSecond(" + win + "))") + "\n"
                + "    WHERE mgr_time >= ({time_from:DateTime64(3)} - toIntervalSecond(" + win + ")) AND mgr_time < {time_to:DateTime64(3)}\n"
                + "      AND " + dtpIn() + "\n"
                + "  )\n"
                + "  WHERE " + String.join("\n    AND ", where) + "\n"
                + "  GROUP BY org_id, entity, win_end\n"
                + "  HAVING value >= threshold";
    }

    /** 백테스트: 창 끝별 결과를 hit_bucket 당 1행(실시간 ReplacingMergeTree 와 같은 마지막 창)으로 줄여 저장. */
    public CompiledRule backtestInsert() {
        String inner = windowedSelect(null);
        String sql = "INSERT INTO detect.rule_hits_backtest\n"
                + "  (job_id, hit_bucket, rule_id, rule_version, org_id, entity_type, entity,\n"
                + "   first_seen, last_seen, value, threshold, sample_event_ids, win_to, first_win_to)\n"
                + "SELECT\n"
                + "  {job_id:UUID}, hit_bucket, " + rid + ", {rule_version:UInt32}, org_id, '" + r.entityType() + "', entity,\n"
                + "  argMax(first_seen, win_end), argMax(last_seen, win_end), argMax(value, win_end), argMax(threshold, win_end),\n"
                + "  argMax(sample_event_ids, win_end), max(win_end), min(win_end)\n"
                + "FROM (\n"
                + "  " + inner + "\n"
                + ")\n"
                + "GROUP BY org_id, entity, hit_bucket\n"
                + "LIMIT " + MAX_ROWS;
        return new CompiledRule(sql, new LinkedHashMap<>(params));
    }

    /** 임계치 민감도: 임계치 × mult 일 때의 히트(대상·창) 수. */
    public CompiledRule bucketCount(double mult) {
        String m = p(mult, "Float64");
        String inner = windowedSelect(m);
        String sql = "SELECT count() AS hits FROM (SELECT org_id, entity, hit_bucket FROM (" + inner
                + ") GROUP BY org_id, entity, hit_bucket)";
        return new CompiledRule(sql, new LinkedHashMap<>(params));
    }

    public CompiledRule previewRows() {
        String inner = windowedSelect(null);
        String sql = "SELECT org_id, entity, hit_bucket,\n"
                + "  argMax(value, win_end) AS value, argMax(threshold, win_end) AS threshold,\n"
                + "  argMax(first_seen, win_end) AS first_seen, argMax(last_seen, win_end) AS last_seen,\n"
                + "  argMax(sample_event_ids, win_end) AS sample_event_ids, min(win_end) AS first_win_to\n"
                + "FROM (" + inner + ")\n"
                + "GROUP BY org_id, entity, hit_bucket\n"
                + "ORDER BY hit_bucket\n"
                + "LIMIT 10000";
        return new CompiledRule(sql, new LinkedHashMap<>(params));
    }

    public static CompiledRule compileRealtime(ParsedRule rule, Function<String, ListInfo> loader) {
        return new RuleCompiler(rule, loader).realtime();
    }

    public static CompiledRule compileBacktest(ParsedRule rule, Function<String, ListInfo> loader) {
        return new RuleCompiler(rule, loader).backtestInsert();
    }

    public static CompiledRule compileBucketCount(ParsedRule rule, Function<String, ListInfo> loader, double mult) {
        return new RuleCompiler(rule, loader).bucketCount(mult);
    }

    public static CompiledRule compilePreview(ParsedRule rule, Function<String, ListInfo> loader) {
        return new RuleCompiler(rule, loader).previewRows();
    }

    /** 화면 표시용: 파라미터 값을 주석으로 붙인다 (실행에는 쓰지 않는다). */
    public static String renderForDisplay(CompiledRule c) {
        StringBuilder sb = new StringBuilder(c.sql()).append("\n\n-- parameters");
        c.params().forEach((k, v) -> sb.append("\n--   ").append(k).append(" = ").append(pyRepr(v)));
        return sb.toString();
    }

    static String pyRepr(Object v) {
        if (v instanceof String s) {
            return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'";
        }
        if (v instanceof Double d) {
            return d == Math.rint(d) && !Double.isInfinite(d) ? String.format(Locale.ROOT, "%.1f", d) : String.valueOf(d);
        }
        if (v instanceof List<?> l) {
            return "[" + String.join(", ", l.stream().map(RuleCompiler::pyRepr).toList()) + "]";
        }
        if (v instanceof Boolean b) {
            return b ? "True" : "False";
        }
        return String.valueOf(v);
    }
}
