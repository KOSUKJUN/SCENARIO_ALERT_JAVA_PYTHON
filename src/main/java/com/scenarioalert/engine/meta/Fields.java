package com.scenarioalert.engine.meta;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * detect.v_events 컬럼 허용 목록, 타입, 연산자, 데이터 유형별 채움 여부 (설계안 3장 표).
 * 필드명은 이 목록에 있어야만 SQL 에 들어간다. 화면은 GET /meta/fields 로 이 내용을 받는다.
 */
public final class Fields {
    public static final List<String> DATA_TYPES = List.of(
            "APT", "DDos", "DPX", "FIREWALL", "IDS", "IPS", "TMS", "UTM", "VPN", "WAF", "WEB", "WFILTER");
    public static final Set<String> ALL = Set.copyOf(DATA_TYPES);

    public static final Map<String, List<String>> OPS_BY_TYPE = new LinkedHashMap<>();
    public static final Map<String, String> OP_LABELS = new LinkedHashMap<>();
    public static final Map<String, FieldDef> FIELDS = new LinkedHashMap<>();
    /**
     * 대상 유형. host 는 IP 하나, org 는 기관 전체(org_id)가 대상이다.
     * org 대상 룰은 "기관 안에서 같은 행위를 한 호스트 수" 같은 기관 단위 집계에 쓴다 (예: 1시간 안 외부 445 접근 호스트 3대 이상).
     * org 대상에는 자산 태그가 없으므로 순서도의 asset 노드는 항상 no 가지로 간다.
     */
    public static final Map<String, List<String>> ENTITY_TYPES = new LinkedHashMap<>();

    static {
        ENTITY_TYPES.put("host", List.of("src_ip", "dst_ip"));
        ENTITY_TYPES.put("org", List.of("org_id"));
    }
    public static final Map<String, List<String>> AGGREGATE_FUNCS = new LinkedHashMap<>();
    public static final List<String> SEVERITIES = List.of("low", "medium", "high", "critical");
    public static final List<String> STATUSES = List.of("draft", "silent", "active", "disabled");
    public static final List<String> NODE_TYPES = List.of("start", "rule", "check", "asset", "and", "or", "alert");

    /** 필드 정의. type: string | int | ip | bool | tags | peer */
    public record FieldDef(String name, String type, String label, Set<String> available, boolean nullable,
                           List<String> enumValues, String note) {
    }

    private static Set<String> but(String... excl) {
        Set<String> s = new LinkedHashSet<>(DATA_TYPES);
        for (String e : excl) {
            s.remove(e);
        }
        return s;
    }

    private static Set<String> only(String... in) {
        return new LinkedHashSet<>(List.of(in));
    }

    private static void f(String name, String type, String label, Set<String> avail, boolean nullable,
                          List<String> enums, String note) {
        FIELDS.put(name, new FieldDef(name, type, label, avail, nullable, enums, note));
    }

    private static void f(String name, String type, String label) {
        f(name, type, label, ALL, false, List.of(), "");
    }

    private static void f(String name, String type, String label, Set<String> avail) {
        f(name, type, label, avail, false, List.of(), "");
    }

    static {
        OPS_BY_TYPE.put("string", List.of("eq", "ne", "in", "not_in", "contains", "contains_list", "regex", "in_list",
                "not_in_list", "exists"));
        OPS_BY_TYPE.put("int", List.of("eq", "ne", "gte", "lte", "in", "not_in", "exists"));
        OPS_BY_TYPE.put("ip", List.of("eq", "ne", "in", "not_in", "cidr", "in_list", "not_in_list", "exists"));
        OPS_BY_TYPE.put("bool", List.of("eq"));
        OPS_BY_TYPE.put("tags", List.of("has_tag"));
        OPS_BY_TYPE.put("peer", List.of("eq"));

        String[][] labels = {{"eq", "같음"}, {"ne", "다름"}, {"gte", "이상"}, {"lte", "이하"}, {"in", "다음 중 하나"},
                {"not_in", "다음 중 아님"}, {"cidr", "대역 포함"}, {"contains", "문자열 포함"},
                {"contains_list", "리스트 항목 포함"}, {"regex", "정규식"}, {"in_list", "리스트에 있음"},
                {"not_in_list", "리스트에 없음"}, {"has_tag", "태그 보유"}, {"exists", "값 있음"}};
        for (String[] l : labels) {
            OP_LABELS.put(l[0], l[1]);
        }

        Set<String> ipTypes = but("WFILTER");
        f("data_tp", "string", "데이터 유형", ALL, false, DATA_TYPES, "");
        f("org_id", "string", "기관 (로그 수집원 매핑)");
        f("log_source", "string", "로그 수집원 (원본 _asset_id)");
        f("product", "string", "제품");
        f("log", "string", "로그 종류");
        f("sublog", "string", "하위 로그 종류");
        f("src_ip", "ip", "출발지 IP", ipTypes);
        f("dst_ip", "ip", "목적지 IP", ipTypes);
        f("src_port", "int", "출발지 포트", only("DDos", "FIREWALL", "IPS"), true, List.of(), "");
        f("dst_port", "int", "목적지 포트", only("DDos", "FIREWALL", "IPS", "TMS"), true, List.of(), "");
        f("protocol", "string", "프로토콜(소문자)");
        f("action", "string", "조치(소문자)", ALL, false, List.of(), "APT, WFILTER 는 mstatus 값");
        f("net_direction", "string", "방향(보강)", ALL, false, List.of("inbound", "outbound", "internal", "external"),
                "장비 값 우선, 없으면 기관 내부 대역으로 판정");
        f("src_internal", "bool", "출발지 내부 대역", ipTypes);
        f("dst_internal", "bool", "목적지 내부 대역", ipTypes);
        f("src_country", "string", "출발지 국가", ipTypes);
        f("dst_country", "string", "목적지 국가", ipTypes);
        f("signature_name", "string", "시그니처명(method)", but("APT", "VPN"));
        f("signature_category", "string", "시그니처 분류(매핑 리스트)", but("APT", "VPN"));
        f("attack", "string", "공격명", only("DDos", "FIREWALL", "IPS", "TMS", "UTM", "WAF", "WEB", "WFILTER"));
        f("risk", "string", "위험도");
        f("event_type", "string", "이벤트 유형");
        f("category", "string", "분류(장비 값)");
        f("origin_id", "string", "수집 장비 ID");
        f("origin_name", "string", "수집 장비명");
        f("origin_ip", "ip", "수집 장비 IP");
        f("event_count", "int", "이벤트 수", ALL, false, List.of(), "TMS, VPN, WAF 는 1건으로 계산");
        f("uri", "string", "URI", only("WAF", "WEB"));
        f("url_method", "string", "HTTP 메서드", only("WAF", "WEB"));
        f("payload", "string", "페이로드", only("DDos", "IDS", "IPS", "TMS", "UTM", "WAF"));
        f("search_text", "string", "검색 텍스트(소문자 결합)");
        f("src_asset_tags", "tags", "출발지 자산 태그", ipTypes);
        f("dst_asset_tags", "tags", "목적지 자산 태그", ipTypes);
        f("src_ti_hit", "bool", "출발지 유해 IP", ipTypes);
        f("dst_ti_hit", "bool", "목적지 유해 IP", ipTypes);
        f("new_peer", "peer", "처음 보는 목적지(출발지→목적지)", ipTypes, false, List.of(),
                "peer_first_seen 기준, 평가 창 안에서 처음 관측된 (출발지, 목적지) 쌍");

        AGGREGATE_FUNCS.put("count", List.of());
        List<String> distinct = new ArrayList<>();
        FIELDS.values().forEach(fd -> {
            if (Set.of("string", "ip", "int").contains(fd.type())) {
                distinct.add(fd.name());
            }
        });
        AGGREGATE_FUNCS.put("distinct_count", distinct);
        AGGREGATE_FUNCS.put("sum", List.of("event_count"));
    }

    public static int severityRank(String s) {
        int i = SEVERITIES.indexOf(s);
        return Math.max(i, 0);
    }

    private Fields() {
    }

    public static Map<String, Object> metaPayload() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("data_types", DATA_TYPES);
        List<Map<String, Object>> fs = new ArrayList<>();
        for (FieldDef f : FIELDS.values()) {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("name", f.name());
            d.put("type", f.type());
            d.put("label", f.label());
            d.put("ops", OPS_BY_TYPE.get(f.type()));
            d.put("available", new TreeSet<>(f.available()));
            d.put("nullable", f.nullable());
            d.put("enum", f.enumValues());
            d.put("note", f.note());
            fs.add(d);
        }
        m.put("fields", fs);
        m.put("op_labels", OP_LABELS);
        List<Map<String, Object>> et = new ArrayList<>();
        ENTITY_TYPES.forEach((t, flds) -> et.add(Map.of("type", t, "fields", flds)));
        m.put("entity_types", et);
        List<Map<String, Object>> ag = new ArrayList<>();
        AGGREGATE_FUNCS.forEach((k, v) -> ag.add(Map.of("func", k, "fields", v)));
        m.put("aggregate_funcs", ag);
        m.put("severities", SEVERITIES);
        m.put("statuses", STATUSES);
        m.put("node_types", NODE_TYPES);
        return m;
    }
}
