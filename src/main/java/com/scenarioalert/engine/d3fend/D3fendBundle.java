package com.scenarioalert.engine.d3fend;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.scenarioalert.engine.attack.AttackBundle;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * MITRE D3FEND 공식 릴리스 읽기. DB 를 쓰지 않는 순수 코드. 한 버전은 두 파일이다.
 * <ul>
 *   <li>d3fend.json (JSON-LD 온톨로지): 버전, 전술, 방어 기법(D3-xxx: 이름·정의·설명·상위 기법·전술), ATT&amp;CK 완화(M)와의 관계</li>
 *   <li>d3fend-full-mappings.csv (D3FEND 가 추론한 매핑): ATT&amp;CK 기법 ↔ 방어 기법 (디지털 아티팩트를 통한 근거)</li>
 * </ul>
 */
public final class D3fendBundle {
    /** 방어 기법 ID. 분석 기법(D3A-) 은 대응방책이 아니라서 받지 않는다. */
    public static final Pattern TECHNIQUE_ID = Pattern.compile("^D3-[A-Z0-9]{1,16}$");
    static final Pattern MITIGATION_IRI = Pattern.compile("^d3f:(M\\d{4})$");
    static final int MAX_VIA = 3;

    public record Tactic(String name, int ord, String definition) {
    }

    public record Technique(String id, String iri, String name, String tactic, String parentId, int depth, String definition,
                            String kbArticle, List<String> synonyms) {
    }

    /** ATT&CK 기법 → 방어 기법. via: [{def_rel, def_artifact, off_rel, off_artifact}] */
    public record Mapping(String attackId, String d3fId, String attackDomain, String attackName, List<Map<String, Object>> via) {
    }

    public record MitigationLink(String mitigationId, String mitigationName, String d3fId) {
    }

    public record Ontology(String version, LocalDateTime releasedAt, List<Tactic> tactics, List<Technique> techniques,
                           List<MitigationLink> mitigations) {
    }

    public record Bundle(Ontology ontology, List<Mapping> mappings, int skippedMappingRows) {
        public String version() {
            return ontology.version();
        }

        public Map<String, Integer> counts() {
            Map<String, Integer> c = new LinkedHashMap<>();
            c.put("tactic", ontology.tactics().size());
            c.put("technique", ontology.techniques().size());
            c.put("top_technique", (int) ontology.techniques().stream().filter(t -> t.parentId() == null).count());
            c.put("mapping", mappings.size());
            c.put("attack_technique", (int) mappings.stream().map(Mapping::attackId).distinct().count());
            c.put("mapped_technique", (int) mappings.stream().map(Mapping::d3fId).distinct().count());
            c.put("mitigation_link", ontology.mitigations().size());
            return c;
        }
    }

    private D3fendBundle() {
    }

    // ---------------------------------------------------------------- 온톨로지 (d3fend.json)

    public static Ontology parseOntology(InputStream in, String versionOverride) throws IOException {
        JsonNode root;
        try (JsonParser p = Json.MAPPER.getFactory().createParser(in)) {
            p.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
            root = Json.MAPPER.readTree(p);
        }
        JsonNode graph = root == null ? null : root.get("@graph");
        if (graph == null || !graph.isArray()) {
            throw ApiException.badRequest("D3FEND 온톨로지(d3fend.json, JSON-LD)가 아닙니다: @graph 가 없습니다");
        }
        Map<String, JsonNode> byIri = new HashMap<>();
        String version = null;
        LocalDateTime released = null;
        List<Tactic> tactics = new ArrayList<>();
        Set<String> tacticIris = new LinkedHashSet<>();
        for (JsonNode n : graph) {
            String iri = text(n.get("@id"));
            if (iri == null) {
                continue;
            }
            byIri.put(iri, n);
            Set<String> types = values(n.get("@type"));
            if (types.contains("owl:Ontology")) {
                version = text(n.get("owl:versionInfo"));
                released = time(n.get("d3f:release-date"));
            } else if (types.contains("d3f:DefensiveTactic") && iri.startsWith("d3f:")) {
                String name = text(n.get("rdfs:label"));
                if (name != null) {
                    tacticIris.add(iri);
                    tactics.add(new Tactic(name, n.path("d3f:display-order").asInt(99), text(n.get("d3f:definition"))));
                }
            }
        }
        if (versionOverride != null && !versionOverride.isBlank()) {
            version = versionOverride.trim();
        }
        if (version == null || !version.matches("^\\d+\\.\\d+(\\.\\d+)?([.-][A-Za-z0-9]+)*$")) {
            throw ApiException.badRequest("온톨로지에 버전(owl:versionInfo)이 없거나 형식이 아닙니다: " + version);
        }
        tactics.sort((a, b) -> Integer.compare(a.ord(), b.ord()));

        // 방어 기법: d3fend-id 가 D3- 로 시작하는 노드. 상위 = subClassOf 중 다른 방어 기법, 전술 = 자신이나 조상의 d3f:enables
        Map<String, JsonNode> techByIri = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> e : byIri.entrySet()) {
            String id = text(e.getValue().get("d3f:d3fend-id"));
            if (id != null && TECHNIQUE_ID.matcher(id).matches()) {
                techByIri.put(e.getKey(), e.getValue());
            }
        }
        Map<String, String> parentIri = new HashMap<>();
        Map<String, String> ownTactic = new HashMap<>();
        for (Map.Entry<String, JsonNode> e : techByIri.entrySet()) {
            for (String s : values(e.getValue().get("rdfs:subClassOf"))) {
                if (techByIri.containsKey(s) && !s.equals(e.getKey())) {
                    parentIri.put(e.getKey(), s);
                    break;
                }
            }
            for (String s : values(e.getValue().get("d3f:enables"))) {
                if (tacticIris.contains(s)) {
                    ownTactic.put(e.getKey(), byIri.get(s).path("rdfs:label").asText());
                    break;
                }
            }
        }
        List<Technique> techniques = new ArrayList<>();
        for (Map.Entry<String, JsonNode> e : techByIri.entrySet()) {
            JsonNode n = e.getValue();
            String tactic = null;
            int depth = 0;
            Set<String> seen = new LinkedHashSet<>();
            for (String cur = e.getKey(); cur != null && seen.add(cur); cur = parentIri.get(cur)) {
                if (tactic == null) {
                    tactic = ownTactic.get(cur);
                }
                if (!cur.equals(e.getKey())) {
                    depth++;
                }
            }
            if (tactic == null) {
                continue;  // 전술에 닿지 않는 기법(예: D3-ARMA, 분석 기법 아래에 걸린 모델)은 대응방책이 아니다
            }
            String pIri = parentIri.get(e.getKey());
            techniques.add(new Technique(text(n.get("d3f:d3fend-id")), e.getKey().replaceFirst("^d3f:", ""), text(n.get("rdfs:label")),
                    tactic, pIri == null ? null : text(techByIri.get(pIri).get("d3f:d3fend-id")), depth,
                    text(n.get("d3f:definition")), text(n.get("d3f:kb-article")), List.copyOf(values(n.get("d3f:synonym")))));
        }
        techniques.sort((a, b) -> a.id().compareTo(b.id()));

        List<MitigationLink> mitigations = new ArrayList<>();
        for (Map.Entry<String, JsonNode> e : new TreeMap<>(byIri).entrySet()) {
            var m = MITIGATION_IRI.matcher(e.getKey());
            if (!m.matches()) {
                continue;
            }
            for (String rel : values(e.getValue().get("d3f:related"))) {
                JsonNode t = techByIri.get(rel);
                if (t != null) {
                    mitigations.add(new MitigationLink(m.group(1), text(e.getValue().get("rdfs:label")), text(t.get("d3f:d3fend-id"))));
                }
            }
        }
        if (techniques.isEmpty()) {
            throw ApiException.badRequest("온톨로지에 방어 기법(D3-xxx)이 없습니다");
        }
        return new Ontology(version, released, tactics, techniques, mitigations);
    }

    // ---------------------------------------------------------------- 매핑 (d3fend-full-mappings.csv)

    /** 매핑 CSV 를 읽는다. 방어 기법은 이름(query_def_tech_label)으로 온톨로지와 잇는다. SPARTA 등 ATT&CK 밖의 행은 건너뛴다. */
    public static Bundle parseMappings(Ontology ont, InputStream in) throws IOException {
        Map<String, String> idByName = new HashMap<>();
        ont.techniques().forEach(t -> idByName.put(t.name(), t.id()));
        Reader r = new InputStreamReader(in, StandardCharsets.UTF_8);
        CsvReader csv = new CsvReader(r);
        List<String> header = csv.next();
        if (header == null) {
            throw ApiException.badRequest("매핑 CSV 가 비어 있습니다");
        }
        if (!header.isEmpty() && header.get(0).startsWith("﻿")) {
            header.set(0, header.get(0).substring(1));
        }
        Map<String, Integer> ix = new HashMap<>();
        for (int i = 0; i < header.size(); i++) {
            ix.put(header.get(i).trim(), i);
        }
        for (String need : List.of("query_def_tech_label", "off_tech_id", "framework_root_iri")) {
            if (!ix.containsKey(need)) {
                throw ApiException.badRequest("D3FEND 매핑 CSV(d3fend-full-mappings.csv)가 아닙니다: " + need + " 열이 없습니다");
            }
        }
        Map<String, Mapping> out = new LinkedHashMap<>();
        int skipped = 0;
        for (List<String> row = csv.next(); row != null; row = csv.next()) {
            if (row.size() < header.size()) {
                if (row.size() > 1) {
                    skipped++;
                }
                continue;
            }
            String root = col(row, ix, "framework_root_iri");
            String domain = root.endsWith("#ATTACKEnterpriseTechnique") ? "enterprise" : root.endsWith("#ATTACKICSTechnique") ? "ics" : null;
            String attackId = col(row, ix, "off_tech_id");
            String d3f = idByName.get(col(row, ix, "query_def_tech_label"));
            if (domain == null || d3f == null || !AttackBundle.TECHNIQUE_ID.matcher(attackId).matches()) {
                skipped++;
                continue;
            }
            String attackName = emptyToNull(col(row, ix, "off_tech_label"));
            Mapping m = out.computeIfAbsent(attackId + "|" + d3f, k -> new Mapping(attackId, d3f, domain, attackName, new ArrayList<>()));
            if (m.via().size() < MAX_VIA) {
                Map<String, Object> v = Json.obj("def_tech", emptyToNull(col(row, ix, "def_tech_label")),
                        "def_rel", emptyToNull(col(row, ix, "def_artifact_rel_label")),
                        "def_artifact", emptyToNull(col(row, ix, "def_artifact_label")),
                        "off_rel", emptyToNull(col(row, ix, "off_artifact_rel_label")),
                        "off_artifact", emptyToNull(col(row, ix, "off_artifact_label")));
                if (!m.via().contains(v)) {
                    m.via().add(v);
                }
            }
        }
        return new Bundle(ont, List.copyOf(out.values()), skipped);
    }

    private static String col(List<String> row, Map<String, Integer> ix, String k) {
        Integer i = ix.get(k);
        return i == null || i >= row.size() ? "" : row.get(i).trim();
    }

    private static String emptyToNull(String s) {
        return s == null || s.isEmpty() ? null : s;
    }

    /** RFC 4180 CSV (따옴표 안의 쉼표·줄바꿈·"" 처리). 행 단위로 흘려 읽는다. */
    static final class CsvReader {
        private final Reader in;
        private int peeked = -2;

        CsvReader(Reader in) {
            this.in = in;
        }

        private int read() throws IOException {
            if (peeked != -2) {
                int c = peeked;
                peeked = -2;
                return c;
            }
            return in.read();
        }

        List<String> next() throws IOException {
            List<String> row = new ArrayList<>();
            StringBuilder f = new StringBuilder();
            boolean quoted = false;
            boolean any = false;
            while (true) {
                int c = read();
                if (c == -1) {
                    if (!any) {
                        return null;
                    }
                    row.add(f.toString());
                    return row;
                }
                any = true;
                if (quoted) {
                    if (c == '"') {
                        int n = read();
                        if (n == '"') {
                            f.append('"');
                        } else {
                            quoted = false;
                            peeked = n;
                        }
                    } else {
                        f.append((char) c);
                    }
                } else if (c == '"') {
                    quoted = true;
                } else if (c == ',') {
                    row.add(f.toString());
                    f.setLength(0);
                } else if (c == '\n') {
                    row.add(f.toString());
                    return row;
                } else if (c != '\r') {
                    f.append((char) c);
                }
            }
        }
    }

    // ---------------------------------------------------------------- JSON-LD 도우미

    static String text(JsonNode n) {
        if (n == null || n.isNull()) {
            return null;
        }
        if (n.isTextual() || n.isNumber() || n.isBoolean()) {
            return n.asText();
        }
        if (n.isObject()) {
            if (n.has("@value")) {
                return n.get("@value").asText();
            }
            if (n.has("@id")) {
                return n.get("@id").asText();
            }
        }
        if (n.isArray() && !n.isEmpty()) {
            return text(n.get(0));
        }
        return null;
    }

    /** 값 하나 또는 배열 → 문자열 집합 ({"@id": ...} 와 {"@value": ...} 를 푼다). */
    static Set<String> values(JsonNode n) {
        Set<String> out = new LinkedHashSet<>();
        if (n == null || n.isNull()) {
            return out;
        }
        if (n.isArray()) {
            n.forEach(x -> {
                String s = text(x);
                if (s != null) {
                    out.add(s);
                }
            });
        } else {
            String s = text(n);
            if (s != null) {
                out.add(s);
            }
        }
        return out;
    }

    static LocalDateTime time(JsonNode n) {
        String s = text(n);
        if (s == null) {
            return null;
        }
        try {
            Instant i = OffsetDateTime.parse(s).toInstant();
            return LocalDateTime.ofInstant(i, Kst.ZONE);
        } catch (RuntimeException e) {
            return null;
        }
    }
}
