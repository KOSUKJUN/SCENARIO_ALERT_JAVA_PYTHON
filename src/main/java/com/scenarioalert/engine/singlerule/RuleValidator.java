package com.scenarioalert.engine.singlerule;

import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.d3fend.D3fendService;
import com.scenarioalert.engine.common.Ip;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.meta.Fields;
import com.scenarioalert.engine.meta.Fields.FieldDef;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 단일룰 정의 검증 (설계안 4장). 정의는 Map(YAML/JSON) 그대로 받고, 오류(거부)와 경고(저장 가능)를 돌려준다.
 */
public final class RuleValidator {
    public static final Pattern RULE_ID_RE = Pattern.compile("^[A-Z][A-Z0-9_]{2,63}$");
    public static final Pattern LIST_ID_RE = Pattern.compile("^[a-z0-9][a-z0-9_\\-]{0,63}$");
    public static final Pattern TAG_RE = Pattern.compile("^[a-z0-9][a-z0-9_\\-]{0,63}$");
    public static final Set<String> LOWER_FIELDS = Set.of("action", "protocol", "net_direction");
    static final int MAX_CONDITIONS = 50;
    static final int MAX_DEPTH = 5;
    static final int MAX_IN_VALUES = 1000;
    private static final Pattern RE2_UNSUPPORTED = Pattern.compile("\\(\\?<?[=!]|\\\\[1-9]");
    private static final Set<String> ALLOWED_KEYS = Set.of(
            "id", "name", "description", "type", "entity", "data_tp", "filter", "aggregate", "window", "threshold",
            "min_count", "exclude_lists", "schedule", "alert_on_hit", "severity", "status", "suppress_for", "tags",
            "attack", "d3fend");

    private RuleValidator() {
    }

    public record Result(RuleValidation validation, ParsedRule parsed) {
    }

    /** 검증 실패 예외 (API 에서 422). */
    public static class RuleValidationException extends RuntimeException {
        public final RuleValidation result;

        public RuleValidationException(RuleValidation result) {
            super(result.summary());
            this.result = result;
        }
    }

    public static ParsedRule parse(Object defn, Predicate<String> listExists) {
        Result r = validate(defn, listExists);
        if (r.parsed() == null) {
            throw new RuleValidationException(r.validation());
        }
        return r.parsed();
    }

    // ---------------------------------------------------------------- 값
    private static String scalarProblem(String ftype, FieldDef fdef, Object v) {
        switch (ftype) {
            case "string" -> {
                if (!(v instanceof String s)) {
                    return "문자열이어야 합니다";
                }
                if (s.length() > 512) {
                    return "512자를 넘을 수 없습니다";
                }
                if (!fdef.enumValues().isEmpty()
                        && fdef.enumValues().stream().noneMatch(e -> e.equalsIgnoreCase(s))) {
                    return "허용 값: " + String.join(", ", fdef.enumValues());
                }
                return null;
            }
            case "int" -> {
                if (!Json.isInt(v) || ((Number) v).longValue() < 0 || ((Number) v).longValue() > (1L << 53)) {
                    return "0 이상의 정수여야 합니다";
                }
                return null;
            }
            case "ip" -> {
                if (!(v instanceof String s)) {
                    return "IP 문자열이어야 합니다";
                }
                return Ip.isIp(s) ? null : "IP 형식이 아닙니다: " + Json.repr(v);
            }
            case "bool", "peer" -> {
                return v instanceof Boolean ? null : "true 또는 false 여야 합니다";
            }
            default -> {
                return "지원하지 않는 값";
            }
        }
    }

    private static void checkValue(RuleValidation res, String path, String ftype, String fname, String op, Object value,
                                   Predicate<String> listExists) {
        FieldDef fdef = Fields.FIELDS.get(fname);
        switch (op) {
            case "eq", "ne", "gte", "lte" -> {
                String m = scalarProblem(ftype, fdef, value);
                if (m != null) {
                    res.err(path + ".value", m);
                }
                if ("peer".equals(ftype) && !Boolean.TRUE.equals(value) && "eq".equals(op)) {
                    res.err(path + ".value", "new_peer 는 true 만 쓸 수 있습니다");
                }
            }
            case "in", "not_in" -> {
                List<Object> vals = Json.asList(value);
                if (vals == null || vals.isEmpty()) {
                    res.err(path + ".value", "값 목록(1개 이상)이어야 합니다");
                    return;
                }
                if (vals.size() > MAX_IN_VALUES) {
                    res.err(path + ".value", "값은 " + MAX_IN_VALUES + "개까지입니다");
                }
                for (int i = 0; i < vals.size(); i++) {
                    String m = scalarProblem(ftype, fdef, vals.get(i));
                    if (m != null) {
                        res.err(path + ".value[" + i + "]", m);
                    }
                }
            }
            case "cidr" -> {
                if (!(value instanceof String s)) {
                    res.err(path + ".value", "CIDR 문자열이어야 합니다");
                    return;
                }
                if (Ip.normalizeCidr(s) == null) {
                    res.err(path + ".value", "CIDR 형식이 아닙니다: " + Json.repr(value));
                }
            }
            case "contains" -> {
                if (!(value instanceof String s) || s.isEmpty() || s.length() > 256) {
                    res.err(path + ".value", "1~256자 문자열이어야 합니다");
                }
            }
            case "regex" -> {
                if (!(value instanceof String s) || s.isEmpty() || s.length() > 512) {
                    res.err(path + ".value", "1~512자 정규식이어야 합니다");
                    return;
                }
                if (RE2_UNSUPPORTED.matcher(s).find()) {
                    res.err(path + ".value", "전후방 탐색과 역참조는 쓸 수 없습니다 (RE2)");
                    return;
                }
                try {
                    Pattern.compile(s);
                } catch (PatternSyntaxException e) {
                    res.err(path + ".value", "정규식 오류: " + e.getDescription());
                }
            }
            case "contains_list", "in_list", "not_in_list" -> {
                if (!(value instanceof String s) || !LIST_ID_RE.matcher(s).matches()) {
                    res.err(path + ".value", "리스트 ID 형식이 아닙니다 (소문자, 숫자, _, -)");
                } else if (listExists != null && !listExists.test(s)) {
                    res.err(path + ".value", "리스트가 없습니다: " + s);
                }
            }
            case "has_tag" -> {
                if (!(value instanceof String s) || !TAG_RE.matcher(s).matches()) {
                    res.err(path + ".value", "태그 형식이 아닙니다 (소문자, 숫자, _, -)");
                }
            }
            case "exists" -> {
                if (value != null && !Boolean.TRUE.equals(value)) {
                    res.err(path + ".value", "exists 는 값이 없거나 true 여야 합니다");
                }
            }
            default -> {
            }
        }
    }

    private record Used(String field, String path) {
    }

    private static void walk(RuleValidation res, Object node, String path, int depth, List<Used> used, int[] counter,
                             Predicate<String> listExists) {
        if (depth > MAX_DEPTH) {
            res.err(path, "조건 중첩은 " + MAX_DEPTH + "단계까지입니다");
            return;
        }
        Map<String, Object> m = Json.asMap(node);
        if (m == null) {
            res.err(path, "조건은 객체여야 합니다");
            return;
        }
        List<String> groups = new ArrayList<>();
        for (String k : List.of("all", "any", "not")) {
            if (m.containsKey(k)) {
                groups.add(k);
            }
        }
        if (!groups.isEmpty()) {
            if (m.size() != 1) {
                res.err(path, "묶음(all/any/not)에는 다른 키를 함께 쓸 수 없습니다");
                return;
            }
            String k = groups.get(0);
            if (k.equals("not")) {
                walk(res, m.get("not"), path + ".not", depth + 1, used, counter, listExists);
                return;
            }
            List<Object> items = Json.asList(m.get(k));
            if (items == null || items.isEmpty()) {
                res.err(path + "." + k, "조건 목록(1개 이상)이어야 합니다");
                return;
            }
            for (int i = 0; i < items.size(); i++) {
                walk(res, items.get(i), path + "." + k + "[" + i + "]", depth + 1, used, counter, listExists);
            }
            return;
        }
        Set<String> extra = new TreeSet<>(m.keySet());
        extra.removeAll(Set.of("field", "op", "value"));
        if (!extra.isEmpty()) {
            res.err(path, "알 수 없는 키: " + String.join(", ", extra));
            return;
        }
        counter[0]++;
        Object fname = m.get("field");
        Object op = m.get("op");
        if (!(fname instanceof String fn) || !Fields.FIELDS.containsKey(fn)) {
            res.err(path + ".field", "허용되지 않은 필드: " + Json.repr(fname));
            return;
        }
        String ftype = Fields.FIELDS.get(fn).type();
        List<String> ops = Fields.OPS_BY_TYPE.get(ftype);
        if (!(op instanceof String o) || !ops.contains(o)) {
            res.err(path + ".op", fn + "(" + ftype + ") 에 쓸 수 없는 연산자: " + Json.repr(op) + ". 가능: "
                    + String.join(", ", ops));
            return;
        }
        used.add(new Used(fn, path));
        checkValue(res, path, ftype, fn, o, m.get("value"), listExists);
    }

    // ---------------------------------------------------------------- 정의
    public static Result validate(Object defnObj, Predicate<String> listExists) {
        RuleValidation res = new RuleValidation();
        Map<String, Object> defn = Json.asMap(defnObj);
        if (defn == null) {
            res.err("", "정의는 객체여야 합니다");
            return new Result(res, null);
        }
        for (String k : new TreeSet<>(defn.keySet())) {
            if (!ALLOWED_KEYS.contains(k)) {
                res.err(k, "알 수 없는 항목입니다");
            }
        }
        Object rid = defn.get("id");
        if (!(rid instanceof String r) || !RULE_ID_RE.matcher(r).matches()) {
            res.err("id", "ID는 대문자로 시작하고 대문자·숫자·_ 로 3~64자여야 합니다 (예: SR_SMB_OUT_FANOUT)");
        }
        Object name = defn.get("name");
        if (!(name instanceof String n) || n.isBlank() || n.length() > 200) {
            res.err("name", "이름은 1~200자여야 합니다");
        }
        Object rtype = defn.get("type");
        if (!"signature".equals(rtype) && !"count".equals(rtype)) {
            res.err("type", "유형은 signature 또는 count 입니다");
        }

        String etype = null;
        String efield = null;
        Map<String, Object> entity = Json.asMap(defn.get("entity"));
        if (entity == null || !Set.of("type", "field").containsAll(entity.keySet())) {
            res.err("entity", "entity 는 {type, field} 입니다");
        } else {
            Object et = entity.get("type");
            Object ef = entity.get("field");
            etype = et instanceof String s ? s : null;
            efield = ef instanceof String s ? s : null;
            if (etype == null || !Fields.ENTITY_TYPES.containsKey(etype)) {
                res.err("entity.type", "대상 유형은 " + String.join(", ", Fields.ENTITY_TYPES.keySet()) + " 중 하나입니다");
            } else if (efield == null || !Fields.ENTITY_TYPES.get(etype).contains(efield)) {
                res.err("entity.field", etype + " 의 대상 필드는 " + String.join(", ", Fields.ENTITY_TYPES.get(etype))
                        + " 중 하나입니다");
            }
        }

        List<Object> dtp = Json.asList(defn.get("data_tp"));
        Set<String> dtpSet = new LinkedHashSet<>();
        if (dtp == null || dtp.isEmpty()) {
            res.err("data_tp", "데이터 유형(data_tp)은 필수입니다");
        } else {
            for (int i = 0; i < dtp.size(); i++) {
                Object d = dtp.get(i);
                if (!(d instanceof String ds) || !Fields.ALL.contains(ds)) {
                    res.err("data_tp[" + i + "]", "알 수 없는 데이터 유형: " + Json.repr(d));
                } else {
                    dtpSet.add(ds);
                }
            }
            if (new HashSet<>(dtp).size() != dtp.size()) {
                res.err("data_tp", "중복된 데이터 유형이 있습니다");
            }
        }

        List<Used> used = new ArrayList<>();
        int[] counter = {0};
        Object flt = defn.get("filter");
        if (flt == null) {
            res.err("filter", "조건(filter)은 필수입니다");
        } else {
            walk(res, flt, "filter", 1, used, counter, listExists);
            if (counter[0] > MAX_CONDITIONS) {
                res.err("filter", "조건은 " + MAX_CONDITIONS + "개까지입니다");
            }
        }

        // 데이터 유형별 필드 채움 여부 (3장 표)
        if (!dtpSet.isEmpty()) {
            List<Used> check = new ArrayList<>(used);
            if (efield != null && Fields.FIELDS.containsKey(efield)) {
                check.add(new Used(efield, "entity.field"));
            }
            Map<String, Object> agg = Json.asMap(defn.get("aggregate"));
            if (agg != null && agg.get("field") instanceof String af && Fields.FIELDS.containsKey(af)) {
                check.add(new Used(af, "aggregate.field"));
            }
            for (Used u : check) {
                Set<String> avail = Fields.FIELDS.get(u.field()).available();
                Set<String> missing = new TreeSet<>(dtpSet);
                missing.removeAll(avail);
                Set<String> inter = new HashSet<>(dtpSet);
                inter.retainAll(avail);
                if (inter.isEmpty()) {
                    res.err(u.path(), u.field() + " 은(는) 고른 데이터 유형(" + String.join(", ", new TreeSet<>(dtpSet))
                            + ") 모두에서 비어 있습니다");
                } else if (!missing.isEmpty()) {
                    res.warn(u.path(), u.field() + " 은(는) " + String.join(", ", missing)
                            + " 에서 비어 있어 해당 유형 이벤트는 조건에 맞지 않습니다");
                }
            }
        }

        String aggFunc = "count";
        String aggField = null;
        double threshold = 0.0;
        if ("count".equals(rtype)) {
            Map<String, Object> agg = Json.asMap(defn.get("aggregate"));
            if (agg == null || !Set.of("func", "field").containsAll(agg.keySet())) {
                res.err("aggregate", "카운트형은 aggregate {func, field} 가 필요합니다");
            } else {
                Object fn = agg.getOrDefault("func", "");
                if (!(fn instanceof String fs) || !Fields.AGGREGATE_FUNCS.containsKey(fs)) {
                    res.err("aggregate.func", "집계 함수는 " + String.join(", ", Fields.AGGREGATE_FUNCS.keySet())
                            + " 중 하나입니다");
                } else if (fs.equals("count")) {
                    Object af = agg.get("field");
                    if (af != null && !"".equals(af)) {
                        res.err("aggregate.field", "count 는 필드를 쓰지 않습니다 (event_count 합계)");
                    }
                } else {
                    aggFunc = fs;
                    Object af = agg.get("field");
                    if (!(af instanceof String afs) || !Fields.AGGREGATE_FUNCS.get(fs).contains(afs)) {
                        res.err("aggregate.field", fs + " 에 쓸 수 없는 필드: " + Json.repr(af));
                    } else {
                        aggField = afs;
                    }
                }
            }
            Object thr = defn.get("threshold");
            if (!Json.isNumber(thr) || ((Number) thr).doubleValue() <= 0) {
                res.err("threshold", "임계치는 0보다 큰 숫자여야 합니다");
            } else {
                threshold = ((Number) thr).doubleValue();
            }
            if (defn.containsKey("min_count")) {
                res.err("min_count", "min_count 는 시그니처형에만 씁니다");
            }
        } else if ("signature".equals(rtype)) {
            if (defn.containsKey("aggregate") || defn.containsKey("threshold")) {
                res.err("aggregate", "시그니처형은 aggregate/threshold 대신 min_count 를 씁니다");
            }
            Object mc = defn.getOrDefault("min_count", 1);
            if (!Json.isInt(mc) || ((Number) mc).longValue() < 1) {
                res.err("min_count", "min_count 는 1 이상의 정수입니다");
            } else {
                threshold = ((Number) mc).doubleValue();
            }
        }

        int windowSec = 0;
        int scheduleSec = 0;
        int suppressSec = 0;
        try {
            windowSec = Kst.parseDuration(defn.getOrDefault("window", ""));
            if (windowSec < 60 || windowSec > 86400 || 86400 % windowSec != 0) {
                res.err("window", "집계 창은 1분~1일이며 하루를 나누어떨어지게 해야 합니다 (예: 1m, 5m, 10m, 1h)");
            }
        } catch (IllegalArgumentException e) {
            res.err("window", e.getMessage());
        }
        try {
            scheduleSec = Kst.parseDuration(defn.getOrDefault("schedule", "1m"));
            if (scheduleSec < 60 || scheduleSec > 3600 || 3600 % scheduleSec != 0) {
                res.err("schedule", "평가 주기는 1분~1시간이며 1시간을 나누어떨어지게 해야 합니다");
            } else if (windowSec != 0 && windowSec % scheduleSec != 0) {
                res.err("schedule", "집계 창은 평가 주기의 배수여야 합니다");
            }
        } catch (IllegalArgumentException e) {
            res.err("schedule", e.getMessage());
        }
        try {
            suppressSec = Kst.parseDuration(defn.getOrDefault("suppress_for", "1h"));
            if (suppressSec > 7 * 86400) {
                res.err("suppress_for", "억제 시간은 7일 이하입니다");
            }
        } catch (IllegalArgumentException e) {
            res.err("suppress_for", e.getMessage());
        }

        List<String> excl = new ArrayList<>();
        Object exRaw = defn.getOrDefault("exclude_lists", List.of());
        List<Object> exList = Json.asList(exRaw);
        if (exList == null) {
            res.err("exclude_lists", "리스트 ID 목록이어야 합니다");
        } else {
            for (int i = 0; i < exList.size(); i++) {
                Object lid = exList.get(i);
                if (!(lid instanceof String ls) || !LIST_ID_RE.matcher(ls).matches()) {
                    res.err("exclude_lists[" + i + "]", "리스트 ID 형식이 아닙니다");
                } else if (listExists != null && !listExists.test(ls)) {
                    res.err("exclude_lists[" + i + "]", "리스트가 없습니다: " + ls);
                } else {
                    excl.add(ls);
                }
            }
        }

        // MITRE ATT&CK 기법 ID (형식만. 활성 버전에 있는지는 저장 때 Repo 가 AttackService 로 검사한다)
        String attackErr = AttackService.formatError(defn.get("attack"));
        if (attackErr != null) {
            res.err("attack", attackErr);
        }
        // 지정 대응방책: MITRE D3FEND 방어 기법 ID (형식만. 활성 버전에 있는지는 저장 때 Repo 가 D3fendService 로 검사한다)
        String d3fendErr = D3fendService.formatError(defn.get("d3fend"));
        if (d3fendErr != null) {
            res.err("d3fend", d3fendErr);
        }
        if (!(defn.getOrDefault("alert_on_hit", false) instanceof Boolean)) {
            res.err("alert_on_hit", "true 또는 false 입니다");
        }
        Object sev = defn.getOrDefault("severity", "medium");
        if (!(sev instanceof String ss) || !Fields.SEVERITIES.contains(ss)) {
            res.err("severity", "등급은 " + String.join(", ", Fields.SEVERITIES) + " 중 하나입니다");
        }
        Object st = defn.get("status");
        if (st != null && !Fields.STATUSES.contains(String.valueOf(st))) {
            res.err("status", "상태는 draft, silent, active, disabled 중 하나입니다");
        }
        Object desc = defn.get("description");
        if (desc != null && (!(desc instanceof String ds) || ds.length() > 2000)) {
            res.err("description", "설명은 2000자 이하 문자열입니다");
        }

        if (!res.ok()) {
            return new Result(res, null);
        }
        List<String> dtpOrdered = Fields.DATA_TYPES.stream().filter(dtpSet::contains).toList();
        boolean newPeer = used.stream().anyMatch(u -> u.field().equals("new_peer"));
        ParsedRule parsed = new ParsedRule((String) rid, (String) name, (String) rtype, etype, efield, dtpOrdered,
                Json.asMap(flt), aggFunc, aggField, windowSec, threshold, List.copyOf(excl), scheduleSec,
                Boolean.TRUE.equals(defn.get("alert_on_hit")), (String) sev, suppressSec, newPeer, defn);
        return new Result(res, parsed);
    }

    /** 조건 트리에서 참조한 리스트 ID. */
    public static Set<String> referencedLists(Object node) {
        Set<String> out = new TreeSet<>();
        Map<String, Object> m = Json.asMap(node);
        if (m == null) {
            return out;
        }
        for (String k : List.of("all", "any")) {
            List<Object> items = Json.asList(m.get(k));
            if (items != null) {
                items.forEach(it -> out.addAll(referencedLists(it)));
            }
        }
        if (m.containsKey("not")) {
            out.addAll(referencedLists(m.get("not")));
        }
        Object op = m.get("op");
        if (("contains_list".equals(op) || "in_list".equals(op) || "not_in_list".equals(op))
                && m.get("value") instanceof String v) {
            out.add(v);
        }
        return out;
    }
}
