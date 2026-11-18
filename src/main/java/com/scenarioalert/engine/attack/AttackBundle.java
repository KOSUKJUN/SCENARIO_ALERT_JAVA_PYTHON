package com.scenarioalert.engine.attack;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * MITRE ATT&CK STIX 2.1 번들(attack-stix-data 의 enterprise-attack-&lt;버전&gt;.json 등) 읽기. DB 를 쓰지 않는 순수 코드.
 * 번들은 수십 MB 라 객체 단위로 흘려 읽고, 탐지에 쓰는 객체만 남긴다:
 * 전술(TA), 기법·하위 기법(T), 완화(M), 그룹(G), 소프트웨어(S), 탐지 전략(DET) 과 기법을 향한 관계(mitigates, detects, uses).
 */
public final class AttackBundle {
    public static final Pattern TECHNIQUE_ID = Pattern.compile("^T\\d{4}(\\.\\d{3})?$");
    static final Map<String, String> TYPES = Map.of(
            "x-mitre-tactic", "tactic",
            "attack-pattern", "technique",
            "course-of-action", "mitigation",
            "intrusion-set", "group",
            "malware", "software",
            "tool", "software",
            "x-mitre-detection-strategy", "detection");
    /** 유형별 ID 접두어. 옛 번들의 기법 ID 를 단 완화(course-of-action T####) 같은 폐기 객체를 거른다. */
    static final Map<String, Pattern> ID_FORMAT = Map.of(
            "tactic", Pattern.compile("^TA\\d{4}$"),
            "technique", TECHNIQUE_ID,
            "mitigation", Pattern.compile("^M\\d{4}$"),
            "group", Pattern.compile("^G\\d{4}$"),
            "software", Pattern.compile("^S\\d{4}$"),
            "detection", Pattern.compile("^DET\\d{4}$"));
    static final Set<String> KEEP_RELATIONS = Set.of("mitigates", "detects", "uses", "revoked-by");

    public record Obj(String type, String attackId, String stixId, String name, String parentId, String shortname,
                      Integer ord, String description, String url, List<String> tactics, Map<String, Object> extra,
                      boolean deprecated, boolean revoked, String revokedBy, LocalDateTime modified) {
    }

    /** 관계: src(완화·탐지 전략·그룹·소프트웨어) → dst(기법). */
    public record Rel(String relType, String srcType, String srcId, String dstId, String description) {
    }

    public record Bundle(String domain, String version, String name, LocalDateTime releasedAt, String specVersion,
                         List<Obj> objects, List<Rel> relations) {
        public Map<String, Integer> counts() {
            Map<String, Integer> c = new LinkedHashMap<>();
            for (String t : List.of("tactic", "technique", "mitigation", "group", "software", "detection")) {
                c.put(t, 0);
            }
            for (Obj o : objects) {
                if (!o.revoked() && !o.deprecated()) {
                    c.merge(o.type(), 1, Integer::sum);
                }
            }
            c.put("subtechnique", (int) objects.stream()
                    .filter(o -> o.type().equals("technique") && o.parentId() != null && !o.revoked() && !o.deprecated()).count());
            c.put("relations", relations.size());
            return c;
        }
    }

    private record RawRel(String type, String source, String target, String description) {
    }

    private AttackBundle() {
    }

    /**
     * @param versionOverride 번들에 x-mitre-collection 이 없을 때(옛 mitre/cti 번들) 쓸 버전. 있으면 번들 값과 같아야 한다.
     */
    public static Bundle parse(InputStream in, String versionOverride) throws IOException {
        Map<String, JsonNode> keep = new LinkedHashMap<>();
        List<RawRel> rels = new ArrayList<>();
        JsonNode collection = null;
        JsonNode matrix = null;
        boolean isBundle = false;
        try (JsonParser p = Json.MAPPER.getFactory().createParser(in)) {
            p.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);  // 호출한 쪽이 나머지 바이트로 sha256 을 마저 낸다
            if (p.nextToken() != JsonToken.START_OBJECT) {
                throw ApiException.badRequest("STIX 번들(JSON 객체)이 아닙니다");
            }
            while (p.nextToken() == JsonToken.FIELD_NAME) {
                String field = p.currentName();
                JsonToken t = p.nextToken();
                if (field.equals("type")) {
                    isBundle = "bundle".equals(p.getText());
                } else if (field.equals("objects") && t == JsonToken.START_ARRAY) {
                    while (p.nextToken() == JsonToken.START_OBJECT) {
                        JsonNode o = Json.MAPPER.readTree(p);
                        String type = o.path("type").asText();
                        switch (type) {
                            case "x-mitre-collection" -> collection = o;
                            case "x-mitre-matrix" -> {
                                if (matrix == null) {
                                    matrix = o;
                                }
                            }
                            case "relationship" -> {
                                String rt = o.path("relationship_type").asText();
                                if (KEEP_RELATIONS.contains(rt)) {
                                    rels.add(new RawRel(rt, o.path("source_ref").asText(), o.path("target_ref").asText(),
                                            o.hasNonNull("description") ? o.get("description").asText() : null));
                                }
                            }
                            default -> {
                                if (TYPES.containsKey(type)) {
                                    keep.put(o.path("id").asText(), o);
                                }
                            }
                        }
                    }
                } else {
                    p.skipChildren();
                }
            }
        }
        if (!isBundle) {
            throw ApiException.badRequest("STIX 번들이 아닙니다 (type 이 bundle 이어야 합니다)");
        }
        String version = collection == null ? null : collection.path("x_mitre_version").asText(null);
        if (versionOverride != null && !versionOverride.isBlank()) {
            if (version != null && !version.equals(versionOverride.trim())) {
                throw ApiException.badRequest("번들의 버전은 " + version + " 입니다 (입력: " + versionOverride + ")");
            }
            version = versionOverride.trim();
        }
        if (version == null || !version.matches("^\\d{1,3}(\\.\\d{1,3}){0,2}$")) {
            throw ApiException.badRequest("ATT&CK 버전을 알 수 없습니다. 번들에 x-mitre-collection 이 없으면 버전을 직접 입력하세요");
        }
        String domain = matrix == null ? null : mitreId(matrix);
        if (domain == null) {
            for (JsonNode o : keep.values()) {
                if (o.path("type").asText().equals("attack-pattern") && o.path("x_mitre_domains").size() > 0) {
                    domain = o.path("x_mitre_domains").get(0).asText();
                    break;
                }
            }
        }
        if (domain == null || !domain.matches("^[a-z]+-attack$")) {
            throw ApiException.badRequest("ATT&CK 도메인(enterprise-attack 등)을 알 수 없습니다");
        }
        Map<String, Integer> tacticOrder = new HashMap<>();
        if (matrix != null) {
            int i = 0;
            for (JsonNode r : matrix.path("tactic_refs")) {
                tacticOrder.put(r.asText(), i++);
            }
        }

        // stix id -> (유형, ATT&CK ID)
        Map<String, String[]> idOf = new HashMap<>();
        for (Map.Entry<String, JsonNode> e : keep.entrySet()) {
            String type = TYPES.get(e.getValue().path("type").asText());
            String aid = mitreId(e.getValue());
            if (aid != null && ID_FORMAT.get(type).matcher(aid).matches()) {
                idOf.put(e.getKey(), new String[]{type, aid});
            }
        }
        Map<String, String> revokedBy = new HashMap<>();
        Map<String, Rel> relations = new LinkedHashMap<>();
        for (RawRel r : rels) {
            String[] src = idOf.get(r.source());
            String[] dst = idOf.get(r.target());
            if (src == null || dst == null) {
                continue;
            }
            if (r.type().equals("revoked-by")) {
                revokedBy.put(r.source(), dst[1]);
                continue;
            }
            if (!dst[0].equals("technique")) {
                continue;
            }
            boolean ok = switch (r.type()) {
                case "mitigates" -> src[0].equals("mitigation");
                case "detects" -> src[0].equals("detection");
                case "uses" -> src[0].equals("group") || src[0].equals("software");
                default -> false;
            };
            if (ok) {
                relations.putIfAbsent(r.type() + "|" + src[0] + "|" + src[1] + "|" + dst[1],
                        new Rel(r.type(), src[0], src[1], dst[1], r.description()));
            }
        }

        List<Obj> objects = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Map.Entry<String, JsonNode> e : keep.entrySet()) {
            String[] ti = idOf.get(e.getKey());
            if (ti == null || !seen.add(ti[0] + "|" + ti[1])) {
                continue;
            }
            JsonNode o = e.getValue();
            String type = ti[0];
            String aid = ti[1];
            List<String> tactics = null;
            String parent = null;
            Map<String, Object> extra = new LinkedHashMap<>();
            if (type.equals("technique")) {
                tactics = new ArrayList<>();
                for (JsonNode k : o.path("kill_chain_phases")) {
                    if (k.path("kill_chain_name").asText().startsWith("mitre-")) {
                        tactics.add(k.path("phase_name").asText());
                    }
                }
                parent = aid.contains(".") ? aid.substring(0, aid.indexOf('.')) : null;
                putList(extra, "platforms", o.path("x_mitre_platforms"));
            } else if (type.equals("software")) {
                extra.put("kind", o.path("type").asText());
                putList(extra, "platforms", o.path("x_mitre_platforms"));
                putList(extra, "aliases", o.path("x_mitre_aliases"));
            } else if (type.equals("group")) {
                putList(extra, "aliases", o.path("aliases"));
            }
            objects.add(new Obj(type, aid, e.getKey(), trim(o.path("name").asText(""), 300), parent,
                    type.equals("tactic") ? o.path("x_mitre_shortname").asText(null) : null,
                    type.equals("tactic") ? tacticOrder.get(e.getKey()) : null,
                    o.hasNonNull("description") ? o.get("description").asText() : null,
                    mitreUrl(o), tactics, extra.isEmpty() ? null : extra,
                    o.path("x_mitre_deprecated").asBoolean(false), o.path("revoked").asBoolean(false),
                    revokedBy.get(e.getKey()), time(o.path("modified").asText(null))));
        }
        if (objects.stream().noneMatch(o -> o.type().equals("technique"))) {
            throw ApiException.badRequest("기법(attack-pattern)이 없는 번들입니다");
        }
        String name = collection == null ? domain : collection.path("name").asText(domain);
        return new Bundle(domain, version, trim(name, 100),
                collection == null ? null : time(collection.path("modified").asText(null)),
                collection == null ? null : collection.path("x_mitre_attack_spec_version").asText(null),
                objects, new ArrayList<>(relations.values()));
    }

    static String mitreId(JsonNode o) {
        for (JsonNode r : o.path("external_references")) {
            if (r.path("source_name").asText().startsWith("mitre-") && r.hasNonNull("external_id")) {
                return r.get("external_id").asText();
            }
        }
        return null;
    }

    static String mitreUrl(JsonNode o) {
        for (JsonNode r : o.path("external_references")) {
            if (r.path("source_name").asText().startsWith("mitre-") && r.hasNonNull("url")) {
                return trim(r.get("url").asText(), 300);
            }
        }
        return null;
    }

    private static void putList(Map<String, Object> m, String k, JsonNode arr) {
        if (arr.isArray() && arr.size() > 0) {
            List<String> l = new ArrayList<>();
            arr.forEach(x -> l.add(x.asText()));
            m.put(k, l);
        }
    }

    private static String trim(String s, int n) {
        return s == null || s.length() <= n ? s : s.substring(0, n);
    }

    static LocalDateTime time(String iso) {
        if (iso == null || iso.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.ofInstant(Instant.parse(iso), Kst.ZONE);
        } catch (RuntimeException e) {
            return null;
        }
    }
}
