package com.scenarioalert.engine.singlerule;

import com.scenarioalert.engine.meta.Fields;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Snort 룰(2.x / 3.x 텍스트)을 단일룰 정의(Map)로 바꾼다. 입출력만 있는 순수 함수다.
 *
 * <p>이 시스템은 패킷이 아니라 보안장비 로그(detect.v_events)를 본다. 그래서 Snort 옵션 중 로그 필드로 옮길 수 있는 것만 옮기고,
 * 나머지는 항목별 notes 에 "무엇을 뺐는지"로 남긴다. 결과는 사람이 확인한 뒤 draft 로 저장한다 (바로 운영하지 않는다).
 *
 * <ul>
 *   <li>헤더: 프로토콜 → protocol, IP → src_ip/dst_ip (eq·cidr), $HOME_NET/$EXTERNAL_NET → src_internal/dst_internal,
 *       포트 → src_port/dst_port (eq·in·gte/lte), 부정(!)과 목록([..]), 양방향(&lt;&gt;)</li>
 *   <li>content → payload (nocase 면 contains, 아니면 대소문자 구분 정규식), |hex| 는 \xHH, http_uri → uri, http_method → url_method</li>
 *   <li>pcre → regex (i·s·m 플래그), 부정은 not 묶음</li>
 *   <li>threshold / detection_filter (track, count, seconds) → count 형 (count 합계, 임계치, 집계 창)</li>
 *   <li>msg → 이름, sid → ID, priority·classtype → 등급</li>
 * </ul>
 * 매칭 방식 "msg" 를 고르면 페이로드 대신 시그니처명(signature_name) = msg 로 찾는다 (장비가 이미 그 룰로 탐지해 로그를 남긴 경우).
 */
public final class SnortImporter {
    public static final String MATCH_CONTENT = "content";
    public static final String MATCH_MSG = "msg";
    public static final List<String> DEFAULT_DATA_TP = List.of("IDS", "IPS", "TMS");
    private static final List<String> HTTP_DATA_TP = List.of("WAF", "WEB");
    /** 포트 필드(dst_port)가 채워지는 데이터 유형 */
    private static final Set<String> PORT_DATA_TP = Fields.FIELDS.get("dst_port").available();
    /** 집계 창으로 쓸 수 있는 값 (1분~1일, 하루를 나누어떨어지게) */
    private static final int[] WINDOWS = {60, 120, 180, 240, 300, 360, 600, 720, 900, 1200, 1800, 3600, 7200, 10800,
            14400, 21600, 28800, 43200, 86400};
    private static final Set<String> ACTIONS = Set.of("alert", "log", "pass", "drop", "reject", "sdrop", "block", "rewrite");
    private static final Set<String> NET_PROTOCOLS = Set.of("tcp", "udp", "icmp");
    /** 조건으로 옮기지 않고 설명에만 남기는 옵션 (메모 없이 소비) */
    private static final Set<String> META_OPTIONS = Set.of("msg", "sid", "rev", "gid", "classtype", "priority",
            "reference", "metadata", "service", "target", "content", "pcre", "uricontent", "nocase", "threshold",
            "detection_filter");
    /** content 위치 지정자: 로그 문자열 전체에서 찾으므로 뺀다 */
    private static final Set<String> POSITION_MODIFIERS = Set.of("offset", "depth", "distance", "within", "fast_pattern",
            "rawbytes", "startswith", "endswith", "bufferlen");
    /** Snort3 sticky buffer / Snort2 content 수식어 → 로그 필드 */
    private static final Map<String, String> BUFFERS = new HashMap<>();

    static {
        BUFFERS.put("http_uri", "uri");
        BUFFERS.put("http_raw_uri", "uri");
        BUFFERS.put("http_method", "url_method");
        BUFFERS.put("pkt_data", "payload");
        BUFFERS.put("raw_data", "payload");
        BUFFERS.put("file_data", "payload");
        for (String b : List.of("http_header", "http_raw_header", "http_cookie", "http_raw_cookie", "http_client_body",
                "http_raw_body", "http_stat_code", "http_stat_msg", "http_param", "http_true_ip", "http_version",
                "js_data", "vba_data")) {
            BUFFERS.put(b, "payload");
        }
    }

    /** classtype 기본 우선순위 (snort classification.config) → 등급 */
    private static final Map<String, String> CLASSTYPE_SEVERITY = new HashMap<>();

    static {
        for (String c : List.of("attempted-admin", "attempted-user", "inappropriate-content", "policy-violation-high",
                "shellcode-detect", "successful-admin", "successful-user", "trojan-activity", "unsuccessful-user",
                "web-application-attack", "command-and-control", "exploit-kit", "malware-cnc", "credential-theft",
                "targeted-activity", "file-format", "social-engineering")) {
            CLASSTYPE_SEVERITY.put(c, "high");
        }
        for (String c : List.of("attempted-dos", "attempted-recon", "bad-unknown", "default-login-attempt",
                "denial-of-service", "misc-attack", "non-standard-protocol", "rpc-portmap-decode", "successful-dos",
                "successful-recon-largescale", "successful-recon-limited", "suspicious-filename-detect",
                "suspicious-login", "system-call-detect", "unusual-client-port-connection",
                "web-application-activity", "pup-activity", "coin-mining")) {
            CLASSTYPE_SEVERITY.put(c, "medium");
        }
        for (String c : List.of("icmp-event", "misc-activity", "network-scan", "not-suspicious", "protocol-command-decode",
                "string-detect", "unknown", "tcp-connection", "policy-violation")) {
            CLASSTYPE_SEVERITY.put(c, "low");
        }
    }

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}(/\\d{1,2})?$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9A-Fa-f:]+:[0-9A-Fa-f:.]*(/\\d{1,3})?$");
    private static final Pattern PORT = Pattern.compile("^\\d{1,5}$");
    private static final Pattern THRESH_KV = Pattern.compile("^\\s*(type|track|count|seconds)\\s+(\\S+)\\s*$");

    /** 변환 옵션. dataTp 가 비면 IDS·IPS·TMS. idPrefix 는 대문자로 시작. */
    public record Options(List<String> dataTp, String match, String idPrefix, List<String> excludeLists) {
        public Options {
            dataTp = dataTp == null || dataTp.isEmpty() ? DEFAULT_DATA_TP : List.copyOf(dataTp);
            match = MATCH_MSG.equals(match) ? MATCH_MSG : MATCH_CONTENT;
            idPrefix = idPrefix == null || idPrefix.isBlank() ? "SR_SNORT_" : idPrefix;
            excludeLists = excludeLists == null ? List.of() : List.copyOf(excludeLists);
        }
    }

    /**
     * 룰 하나의 변환 결과. definition 이 null 이면 skipped 에 이유가 있다.
     */
    public record Item(int line, String source, String sid, Map<String, Object> definition, List<String> notes,
                       String skipped) {
    }

    private SnortImporter() {
    }

    // ------------------------------------------------------------------ 입력 → 룰 문장

    /** 빈 줄·주석(#)을 빼고, 줄 끝 \ 로 이어진 줄을 합쳐 (시작 줄 번호, 룰 문장) 목록을 만든다. */
    static List<Map.Entry<Integer, String>> statements(String text) {
        List<Map.Entry<Integer, String>> out = new ArrayList<>();
        String[] lines = (text == null ? "" : text).replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        StringBuilder cur = null;
        int start = 0;
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i].strip();
            if (cur == null) {
                if (l.isEmpty() || l.startsWith("#")) {
                    continue;
                }
                cur = new StringBuilder();
                start = i + 1;
            }
            if (l.endsWith("\\")) {
                cur.append(l, 0, l.length() - 1).append(' ');
                continue;
            }
            cur.append(l);
            out.add(Map.entry(start, cur.toString().strip()));
            cur = null;
        }
        if (cur != null && !cur.isEmpty()) {
            out.add(Map.entry(start, cur.toString().strip()));
        }
        return out;
    }

    public static List<Item> convert(String text, Options opt) {
        List<Item> items = new ArrayList<>();
        Set<String> usedIds = new LinkedHashSet<>();
        for (Map.Entry<Integer, String> st : statements(text)) {
            items.add(convertOne(st.getKey(), st.getValue(), opt, usedIds));
        }
        return items;
    }

    // ------------------------------------------------------------------ 룰 하나

    private static final class Ctx {
        final List<String> notes = new ArrayList<>();
        final Set<String> ignored = new LinkedHashSet<>();
        final Set<String> fieldsUsed = new LinkedHashSet<>();

        void note(String s) {
            if (!notes.contains(s)) {
                notes.add(s);
            }
        }
    }

    /** content/pcre 하나 */
    private record Match(String field, String kind, boolean negated, String value, boolean nocase) {
    }

    static Item convertOne(int line, String src, Options opt, Set<String> usedIds) {
        int open = src.indexOf('(');
        int close = src.lastIndexOf(')');
        if (open < 0 || close < open) {
            return skip(line, src, null, "옵션 괄호 ( ... ) 를 찾을 수 없습니다");
        }
        List<String> header = splitHeader(src.substring(0, open).strip());
        if (header.isEmpty() || !ACTIONS.contains(header.get(0).toLowerCase(Locale.ROOT))) {
            return skip(line, src, null, "Snort 룰 형식이 아닙니다 (alert/drop/... 로 시작해야 합니다)");
        }
        List<String[]> options;
        try {
            options = splitOptions(src.substring(open + 1, close));
        } catch (IllegalArgumentException e) {
            return skip(line, src, null, e.getMessage());
        }
        String action = header.get(0).toLowerCase(Locale.ROOT);
        String sid = firstValue(options, "sid");
        if (action.equals("pass")) {
            return skip(line, src, sid, "pass 룰은 탐지 룰이 아니어서 가져오지 않습니다");
        }
        Ctx ctx = new Ctx();
        String proto = header.size() > 1 ? header.get(1).toLowerCase(Locale.ROOT) : "ip";
        boolean serviceHeader = header.size() == 2;
        if (header.size() != 7 && header.size() != 2) {
            return skip(line, src, sid, "헤더는 '동작 프로토콜 출발지 포트 방향 목적지 포트' 7개 항목이어야 합니다 (현재 "
                    + header.size() + "개)");
        }
        if (header.size() == 7 && !Set.of("->", "<>").contains(header.get(4))) {
            return skip(line, src, sid, "방향은 -> 또는 <> 여야 합니다: " + header.get(4));
        }

        // ---- 옵션 해석
        String msg = firstValue(options, "msg");
        List<Match> matches = new ArrayList<>();
        boolean snort3Sticky = serviceHeader || hasOption(options, "service") || stickyBeforeContent(options);
        String sticky = "payload";
        Map<String, String> threshold = null;
        boolean thresholdIsFilter = false;
        for (int i = 0; i < options.size(); i++) {
            String key = options.get(i)[0];
            String val = options.get(i)[1];
            switch (key) {
                case "content", "uricontent" -> {
                    boolean neg = val != null && val.startsWith("!");
                    String raw = neg ? val.substring(1).strip() : val;
                    String decoded = decodeContent(unquote(raw), ctx);
                    String field = key.equals("uricontent") ? "uri" : sticky;
                    boolean nocase = false;
                    // Snort2: content 뒤에 오는 수식어 (다음 content/pcre 전까지)
                    for (int j = i + 1; j < options.size(); j++) {
                        String k2 = options.get(j)[0];
                        if (k2.equals("content") || k2.equals("uricontent") || k2.equals("pcre")) {
                            break;
                        }
                        if (k2.equals("nocase")) {
                            nocase = true;
                        } else if (!snort3Sticky && BUFFERS.containsKey(k2)) {
                            field = bufferField(k2, ctx);
                        }
                    }
                    if (decoded == null) {
                        continue;
                    }
                    matches.add(new Match(field, "content", neg, decoded, nocase));
                }
                case "pcre" -> {
                    Match m = parsePcre(val, sticky, ctx);
                    if (m != null) {
                        matches.add(m);
                    }
                }
                case "threshold", "detection_filter" -> {
                    threshold = parseThreshold(val, ctx);
                    thresholdIsFilter = key.equals("detection_filter");
                }
                default -> {
                    if (BUFFERS.containsKey(key)) {
                        if (snort3Sticky) {
                            sticky = bufferField(key, ctx);
                        }
                    } else if (POSITION_MODIFIERS.contains(key)) {
                        ctx.ignored.add(key);
                    } else if (!META_OPTIONS.contains(key)) {
                        ctx.ignored.add(key);
                    }
                }
            }
        }
        if (!ctx.ignored.isEmpty()) {
            ctx.note("로그로는 확인할 수 없어 뺀 옵션: " + String.join(", ", ctx.ignored)
                    + " (조건이 원본보다 넓어집니다)");
        }

        // ---- 데이터 유형 (URI·HTTP 메서드는 WAF·WEB 로그에만 있다)
        List<String> dtp = new ArrayList<>(opt.dataTp());
        boolean httpFields = opt.match().equals(MATCH_CONTENT)
                && matches.stream().anyMatch(m -> m.field().equals("uri") || m.field().equals("url_method"));
        if (httpFields && !HTTP_DATA_TP.containsAll(dtp)) {
            dtp = new ArrayList<>(HTTP_DATA_TP);
            ctx.note("URI·HTTP 메서드 조건이 있어 데이터 유형을 WAF, WEB 으로 바꿨습니다");
        }
        boolean withPorts = dtp.stream().anyMatch(PORT_DATA_TP::contains);

        // ---- 조건
        List<Object> conds = new ArrayList<>();
        if (opt.match().equals(MATCH_MSG)) {
            if (msg == null || msg.isBlank()) {
                return skip(line, src, sid, "msg 가 없어 시그니처명으로 찾을 수 없습니다");
            }
            conds.add(cond("signature_name", "eq", msg));
            ctx.fieldsUsed.add("signature_name");
        } else {
            if (NET_PROTOCOLS.contains(proto)) {
                conds.add(cond("protocol", "eq", proto));
            } else if (!proto.equals("ip")) {
                ctx.note("프로토콜/서비스 '" + proto + "' 는 protocol 조건으로 옮기지 않았습니다");
            }
            if (header.size() == 7) {
                Object hc = headerConds(header, withPorts, ctx);
                if (hc != null) {
                    conds.add(hc);
                }
            }
            for (Match m : matches) {
                Object c = matchCond(m);
                conds.add(m.negated() ? Map.of("not", c) : c);
                ctx.fieldsUsed.add(m.field());
            }
            if (matches.isEmpty()) {
                ctx.note("content/pcre 가 없어 헤더 조건(IP·포트·프로토콜)만으로 찾습니다");
            }
        }

        // ---- 정의
        Map<String, Object> d = new LinkedHashMap<>();
        String id = makeId(opt.idPrefix(), sid, line, usedIds);
        d.put("id", id);
        String name = msg != null && !msg.isBlank() ? msg.strip() : "Snort sid " + (sid == null ? "없음" : sid);
        d.put("name", name.length() > 200 ? name.substring(0, 200) : name);
        d.put("description", description(src, sid, firstValue(options, "rev"), firstValue(options, "classtype")));

        String track = threshold == null ? "by_src" : threshold.getOrDefault("track", "by_src");
        String entityField = track.equals("by_dst") ? "dst_ip" : "src_ip";
        d.put("entity", Map.of("type", "host", "field", entityField));

        d.put("data_tp", dtp);
        d.put("filter", Map.of("all", conds));

        String ttype = threshold == null ? null : threshold.getOrDefault("type", thresholdIsFilter ? "threshold" : "");
        boolean counting = threshold != null && (thresholdIsFilter || Set.of("threshold", "both").contains(ttype))
                && threshold.containsKey("count");
        int seconds = threshold == null ? 60 : parseIntOr(threshold.get("seconds"), 60);
        String window = windowFor(seconds, threshold != null, ctx);
        if (counting) {
            int count = Math.max(1, parseIntOr(threshold.get("count"), 1));
            d.put("type", "count");
            d.put("aggregate", Map.of("func", "count"));
            d.put("window", window);
            d.put("threshold", count);
            ctx.note("threshold: " + window + " 집계 창 안 이벤트 수(event_count 합) " + count + " 이상 ("
                    + (entityField.equals("src_ip") ? "출발지" : "목적지") + " 기준). Snort 는 패킷 단위 이동 창입니다");
        } else {
            if (threshold != null && "limit".equals(ttype)) {
                ctx.note("threshold type limit 는 경보 횟수 제한이라 조건으로 옮기지 않았습니다 (경보 억제 시간으로 조정하세요)");
            }
            d.put("type", "signature");
            d.put("min_count", 1);
            d.put("window", window);
        }
        d.put("exclude_lists", opt.excludeLists());
        d.put("schedule", "1m");
        d.put("alert_on_hit", false);
        d.put("severity", severity(firstValue(options, "priority"), firstValue(options, "classtype")));
        d.put("suppress_for", "1h");
        return new Item(line, src, sid, d, ctx.notes, null);
    }

    // ------------------------------------------------------------------ 헤더

    private static Object headerConds(List<String> h, boolean withPorts, Ctx ctx) {
        String srcIp = h.get(2);
        String srcPort = h.get(3);
        String dstIp = h.get(5);
        String dstPort = h.get(6);
        if (!withPorts && !(srcPort.equalsIgnoreCase("any") && dstPort.equalsIgnoreCase("any"))) {
            ctx.note("고른 데이터 유형 로그에는 포트가 없어 포트 조건을 뺐습니다");
            srcPort = "any";
            dstPort = "any";
        }
        List<Object> fwd = new ArrayList<>();
        addIf(fwd, addr(srcIp, "src", ctx));
        addIf(fwd, port(srcPort, "src_port", ctx));
        addIf(fwd, addr(dstIp, "dst", ctx));
        addIf(fwd, port(dstPort, "dst_port", ctx));
        if (h.get(4).equals("<>")) {
            List<Object> rev = new ArrayList<>();
            addIf(rev, addr(srcIp, "dst", ctx));
            addIf(rev, port(srcPort, "dst_port", ctx));
            addIf(rev, addr(dstIp, "src", ctx));
            addIf(rev, port(dstPort, "src_port", ctx));
            if (fwd.isEmpty() && rev.isEmpty()) {
                return null;
            }
            return Map.of("any", List.of(Map.of("all", fwd), Map.of("all", rev)));
        }
        if (fwd.isEmpty()) {
            return null;
        }
        return fwd.size() == 1 ? fwd.get(0) : Map.of("all", fwd);
    }

    /** IP 지정 하나 → 조건 (없으면 null). side 는 src | dst. */
    static Object addr(String tok, String side, Ctx ctx) {
        tok = tok.strip();
        if (tok.equalsIgnoreCase("any")) {
            return null;
        }
        if (tok.startsWith("!")) {
            Object inner = addr(tok.substring(1), side, ctx);
            return inner == null ? null : Map.of("not", inner);
        }
        if (tok.startsWith("[") && tok.endsWith("]")) {
            List<Object> pos = new ArrayList<>();
            List<Object> neg = new ArrayList<>();
            for (String part : splitTopLevel(tok.substring(1, tok.length() - 1))) {
                part = part.strip();
                if (part.startsWith("!")) {
                    addIf(neg, addr(part.substring(1), side, ctx));
                } else {
                    addIf(pos, addr(part, side, ctx));
                }
            }
            List<Object> all = new ArrayList<>();
            if (!pos.isEmpty()) {
                all.add(pos.size() == 1 ? pos.get(0) : Map.of("any", pos));
            }
            for (Object n : neg) {
                all.add(Map.of("not", n));
            }
            return all.isEmpty() ? null : all.size() == 1 ? all.get(0) : Map.of("all", all);
        }
        String field = side + "_ip";
        if (tok.equals("$HOME_NET")) {
            return cond(side + "_internal", "eq", true);
        }
        if (tok.equals("$EXTERNAL_NET")) {
            return cond(side + "_internal", "eq", false);
        }
        if (tok.startsWith("$")) {
            ctx.note("주소 변수 " + tok + " 는 값을 알 수 없어 조건에서 뺐습니다 (필요하면 리스트·대역 조건으로 바꾸세요)");
            return null;
        }
        if (IPV4.matcher(tok).matches() || IPV6.matcher(tok).matches()) {
            if (tok.contains("/")) {
                return cond(field, "cidr", tok);
            }
            return cond(field, "eq", tok);
        }
        ctx.note("IP 형식을 알 수 없어 뺐습니다: " + tok);
        return null;
    }

    /** 포트 지정 하나 → 조건 (없으면 null). */
    static Object port(String tok, String field, Ctx ctx) {
        tok = tok.strip();
        if (tok.equalsIgnoreCase("any")) {
            return null;
        }
        if (tok.startsWith("!")) {
            Object inner = port(tok.substring(1), field, ctx);
            return inner == null ? null : Map.of("not", inner);
        }
        if (tok.startsWith("[") && tok.endsWith("]")) {
            List<String> parts = splitTopLevel(tok.substring(1, tok.length() - 1)).stream().map(String::strip).toList();
            if (parts.stream().allMatch(p -> PORT.matcher(p).matches())) {
                ctx.fieldsUsed.add(field);
                return cond(field, "in", parts.stream().map(Integer::parseInt).toList());
            }
            List<Object> pos = new ArrayList<>();
            List<Object> neg = new ArrayList<>();
            for (String p : parts) {
                if (p.startsWith("!")) {
                    addIf(neg, port(p.substring(1), field, ctx));
                } else {
                    addIf(pos, port(p, field, ctx));
                }
            }
            List<Object> all = new ArrayList<>();
            if (!pos.isEmpty()) {
                all.add(pos.size() == 1 ? pos.get(0) : Map.of("any", pos));
            }
            neg.forEach(n -> all.add(Map.of("not", n)));
            return all.isEmpty() ? null : all.size() == 1 ? all.get(0) : Map.of("all", all);
        }
        if (tok.startsWith("$")) {
            ctx.note("포트 변수 " + tok + " 는 값을 알 수 없어 조건에서 뺐습니다");
            return null;
        }
        if (tok.contains(":")) {
            String[] r = tok.split(":", -1);
            List<Object> c = new ArrayList<>();
            if (!r[0].isEmpty() && PORT.matcher(r[0]).matches()) {
                c.add(cond(field, "gte", Integer.parseInt(r[0])));
            }
            if (r.length > 1 && !r[1].isEmpty() && PORT.matcher(r[1]).matches()) {
                c.add(cond(field, "lte", Integer.parseInt(r[1])));
            }
            if (c.isEmpty()) {
                ctx.note("포트 범위 형식을 알 수 없어 뺐습니다: " + tok);
                return null;
            }
            ctx.fieldsUsed.add(field);
            return c.size() == 1 ? c.get(0) : Map.of("all", c);
        }
        if (PORT.matcher(tok).matches()) {
            ctx.fieldsUsed.add(field);
            return cond(field, "eq", Integer.parseInt(tok));
        }
        ctx.note("포트 형식을 알 수 없어 뺐습니다: " + tok);
        return null;
    }

    // ------------------------------------------------------------------ content / pcre

    /** content 값: \" \; \\ 이스케이프, |41 42| 16진 바이트. 결과는 ISO-8859-1 1바이트=1문자 (비ASCII 는 UTF-8 로 다시 읽는다). */
    static String decodeContent(String s, Ctx ctx) {
        if (s == null) {
            ctx.note("content 값을 읽을 수 없어 뺐습니다");
            return null;
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        boolean hex = false;
        StringBuilder hexBuf = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '|') {
                if (hex) {
                    String h = hexBuf.toString().replaceAll("\\s+", "");
                    if (h.length() % 2 != 0 || !h.matches("[0-9A-Fa-f]*")) {
                        ctx.note("16진 content 형식을 알 수 없어 뺐습니다: |" + hexBuf + "|");
                        return null;
                    }
                    for (int k = 0; k < h.length(); k += 2) {
                        out.write(Integer.parseInt(h.substring(k, k + 2), 16));
                    }
                    hexBuf.setLength(0);
                }
                hex = !hex;
                continue;
            }
            if (hex) {
                hexBuf.append(c);
                continue;
            }
            if (c == '\\' && i + 1 < s.length()) {
                c = s.charAt(++i);
            }
            byte[] b = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
            out.write(b, 0, b.length);
        }
        if (hex) {
            ctx.note("16진 content 의 | 가 닫히지 않아 뺐습니다");
            return null;
        }
        byte[] bytes = out.toByteArray();
        try {
            // UTF-8 로 읽히면 문자열로 (한글 등). ClickHouse 정규식은 UTF-8 문자 단위로 맞춘다.
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        } catch (java.nio.charset.CharacterCodingException e) {
            ctx.note("content 에 UTF-8 이 아닌 바이트가 있어 0x80 이상 바이트는 같은 번호의 문자로 찾습니다 (로그 저장 방식에 따라 안 맞을 수 있음)");
            return new String(bytes, StandardCharsets.ISO_8859_1);
        }
    }

    /** contains 로 그대로 찾을 수 있는 문자열인지 (제어 문자가 없음) */
    private static boolean printable(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) {
                return false;
            }
        }
        return true;
    }

    /** 문자열 → RE2 정규식 리터럴 (메타문자 이스케이프, 제어 문자는 \xHH) */
    static String reLiteral(String bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length(); i++) {
            char c = bytes.charAt(i);
            if (c < 0x20 || (c >= 0x7f && c <= 0xff)) {
                sb.append(String.format("\\x%02x", (int) c));
            } else if ("\\.^$|?*+()[]{}".indexOf(c) >= 0) {
                sb.append('\\').append(c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static Object matchCond(Match m) {
        if (m.kind().equals("pcre")) {
            return cond(m.field(), "regex", m.value());
        }
        if (m.nocase() && printable(m.value())) {
            return cond(m.field(), "contains", m.value());
        }
        String re = reLiteral(m.value());
        return cond(m.field(), "regex", m.nocase() ? "(?i)" + re : re);
    }

    private static Match parsePcre(String val, String field, Ctx ctx) {
        if (val == null) {
            ctx.note("pcre 값이 없어 뺐습니다");
            return null;
        }
        boolean neg = val.startsWith("!");
        String s = unquote(neg ? val.substring(1).strip() : val);
        if (s == null || s.length() < 2 || s.charAt(0) != '/' || s.lastIndexOf('/') == 0) {
            ctx.note("pcre 형식(/정규식/플래그)을 알 수 없어 뺐습니다: " + val);
            return null;
        }
        int end = s.lastIndexOf('/');
        String re = s.substring(1, end).replace("\\/", "/");
        String flags = s.substring(end + 1);
        StringBuilder inline = new StringBuilder();
        Set<Character> dropped = new LinkedHashSet<>();
        for (char f : flags.toCharArray()) {
            switch (f) {
                case 'i', 's', 'm' -> inline.append(f);
                case 'U' -> field = "uri";
                case 'M' -> field = "url_method";
                case 'H', 'D', 'P', 'C', 'K', 'S', 'Y', 'I' -> field = "payload";
                default -> dropped.add(f);
            }
        }
        if (!dropped.isEmpty()) {
            StringBuilder ds = new StringBuilder();
            dropped.forEach(ds::append);
            ctx.note("pcre 플래그 " + ds + " 는 옮기지 않았습니다");
        }
        String pattern = inline.isEmpty() ? re : "(?" + inline + ")" + re;
        return new Match(field, "pcre", neg, pattern, false);
    }

    private static String bufferField(String key, Ctx ctx) {
        String f = BUFFERS.get(key);
        if (f.equals("payload") && !Set.of("pkt_data", "raw_data", "file_data").contains(key)) {
            ctx.note(key + " 는 별도 필드가 없어 페이로드 전체에서 찾습니다");
        }
        return f;
    }

    private static boolean stickyBeforeContent(List<String[]> options) {
        for (String[] o : options) {
            if (o[0].equals("content") || o[0].equals("pcre")) {
                return false;
            }
            if (BUFFERS.containsKey(o[0])) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ threshold

    private static Map<String, String> parseThreshold(String val, Ctx ctx) {
        Map<String, String> m = new HashMap<>();
        if (val == null) {
            return m;
        }
        for (String part : val.split(",")) {
            Matcher mm = THRESH_KV.matcher(part);
            if (mm.matches()) {
                m.put(mm.group(1), mm.group(2).toLowerCase(Locale.ROOT));
            } else if (!part.isBlank()) {
                ctx.note("threshold 항목을 알 수 없어 뺐습니다: " + part.strip());
            }
        }
        return m;
    }

    private static String windowFor(int seconds, boolean fromThreshold, Ctx ctx) {
        int w = WINDOWS[WINDOWS.length - 1];
        for (int x : WINDOWS) {
            if (x >= seconds) {
                w = x;
                break;
            }
        }
        if (fromThreshold && w != seconds) {
            ctx.note("seconds " + seconds + " 는 집계 창 " + fmtDur(w) + " 로 맞췄습니다 (1분~1일, 하루를 나누어떨어지는 값)");
        }
        return fmtDur(w);
    }

    static String fmtDur(int sec) {
        if (sec % 86400 == 0) {
            return sec / 86400 + "d";
        }
        if (sec % 3600 == 0) {
            return sec / 3600 + "h";
        }
        return sec / 60 + "m";
    }

    // ------------------------------------------------------------------ 기타

    private static String severity(String priority, String classtype) {
        if (priority != null) {
            int p = parseIntOr(priority.strip(), 2);
            return p <= 1 ? "high" : p == 2 ? "medium" : "low";
        }
        if (classtype != null) {
            return CLASSTYPE_SEVERITY.getOrDefault(classtype.strip().toLowerCase(Locale.ROOT), "medium");
        }
        return "medium";
    }

    private static String makeId(String prefix, String sid, int line, Set<String> used) {
        String p = prefix.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9_]", "_");
        if (p.isEmpty() || !Character.isLetter(p.charAt(0))) {
            p = "SR_" + p;
        }
        String base = p + (sid != null && sid.strip().matches("\\d+") ? sid.strip() : "L" + line);
        if (base.length() > 60) {
            base = base.substring(0, 60);
        }
        String id = base;
        for (int n = 2; used.contains(id); n++) {
            id = base + "_" + n;
        }
        used.add(id);
        return id;
    }

    private static String description(String src, String sid, String rev, String classtype) {
        StringBuilder sb = new StringBuilder("Snort 룰에서 가져옴");
        List<String> meta = new ArrayList<>();
        if (sid != null) {
            meta.add("sid " + sid.strip());
        }
        if (rev != null) {
            meta.add("rev " + rev.strip());
        }
        if (classtype != null) {
            meta.add("classtype " + classtype.strip());
        }
        if (!meta.isEmpty()) {
            sb.append(" (").append(String.join(", ", meta)).append(")");
        }
        sb.append("\n원문: ").append(src);
        return sb.length() > 2000 ? sb.substring(0, 1997) + "..." : sb.toString();
    }

    private static Map<String, Object> cond(String field, String op, Object value) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("field", field);
        m.put("op", op);
        m.put("value", value);
        return m;
    }

    private static void addIf(List<Object> l, Object o) {
        if (o != null) {
            l.add(o);
        }
    }

    private static int parseIntOr(String s, int dflt) {
        try {
            return s == null ? dflt : Integer.parseInt(s.strip());
        } catch (NumberFormatException e) {
            return dflt;
        }
    }

    private static Item skip(int line, String src, String sid, String why) {
        return new Item(line, src, sid, null, List.of(), why);
    }

    private static boolean hasOption(List<String[]> options, String key) {
        return options.stream().anyMatch(o -> o[0].equals(key));
    }

    private static String firstValue(List<String[]> options, String key) {
        for (String[] o : options) {
            if (o[0].equals(key) && o[1] != null) {
                return key.equals("msg") ? unquoteOr(o[1]) : o[1].strip();
            }
        }
        return null;
    }

    private static String unquoteOr(String s) {
        String u = unquote(s);
        return u == null ? s.strip() : u.replace("\\\"", "\"").replace("\\;", ";").replace("\\\\", "\\");
    }

    /** "..." 의 바깥 따옴표를 벗긴다 (안쪽 이스케이프는 그대로). 따옴표가 없으면 null. */
    static String unquote(String s) {
        if (s == null) {
            return null;
        }
        s = s.strip();
        if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
            return s.substring(1, s.length() - 1);
        }
        return null;
    }

    /** 헤더를 공백으로 나누되 [...] 안의 공백은 유지 */
    static List<String> splitHeader(String h) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        int depth = 0;
        for (char c : h.toCharArray()) {
            if (c == '[') {
                depth++;
            } else if (c == ']') {
                depth--;
            }
            if (Character.isWhitespace(c) && depth <= 0) {
                if (!cur.isEmpty()) {
                    out.add(cur.toString());
                    cur.setLength(0);
                }
            } else {
                cur.append(c);
            }
        }
        if (!cur.isEmpty()) {
            out.add(cur.toString());
        }
        return out;
    }

    /** 대괄호 깊이 0 의 쉼표로 나눈다 */
    static List<String> splitTopLevel(String s) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        int depth = 0;
        for (char c : s.toCharArray()) {
            if (c == '[') {
                depth++;
            } else if (c == ']') {
                depth--;
            }
            if (c == ',' && depth == 0) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (!cur.isEmpty()) {
            out.add(cur.toString());
        }
        return out;
    }

    /** 옵션을 ; 로 나눈다 (따옴표 안, \; 는 나누지 않음). 각 항목은 [키(소문자), 값 또는 null]. */
    static List<String[]> splitOptions(String body) {
        List<String[]> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQ = false;
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c == '\\' && i + 1 < body.length()) {
                cur.append(c).append(body.charAt(++i));
                continue;
            }
            if (c == '"') {
                inQ = !inQ;
            }
            if (c == ';' && !inQ) {
                addOption(out, cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (inQ) {
            throw new IllegalArgumentException("옵션의 따옴표가 닫히지 않았습니다");
        }
        addOption(out, cur.toString());
        return out;
    }

    private static void addOption(List<String[]> out, String raw) {
        String s = raw.strip();
        if (s.isEmpty()) {
            return;
        }
        int colon = s.indexOf(':');
        if (colon < 0) {
            out.add(new String[]{s.toLowerCase(Locale.ROOT), null});
        } else {
            out.add(new String[]{s.substring(0, colon).strip().toLowerCase(Locale.ROOT), s.substring(colon + 1).strip()});
        }
    }
}
