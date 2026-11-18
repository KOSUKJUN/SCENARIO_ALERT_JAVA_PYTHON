package com.scenarioalert.engine.d3fend;

import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.d3fend.D3fendBundle.Bundle;
import com.scenarioalert.engine.d3fend.D3fendBundle.Mapping;
import com.scenarioalert.engine.d3fend.D3fendBundle.Ontology;
import com.scenarioalert.engine.d3fend.D3fendBundle.Technique;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** D3FEND 릴리스 읽기(온톨로지 + 매핑 CSV), CSV 파서, 대응 기법 ID 형식 검사 (DB 없음). */
class D3fendBundleTest {
    static final Path FIXTURES = Path.of("src/test/resources/d3fend");

    static Bundle load(String version) throws IOException {
        try (InputStream o = Files.newInputStream(FIXTURES.resolve(version).resolve("d3fend.json"));
             InputStream m = Files.newInputStream(FIXTURES.resolve(version).resolve("d3fend-full-mappings.csv"))) {
            return D3fendBundle.parseMappings(D3fendBundle.parseOntology(o, null), m);
        }
    }

    static Technique tech(Ontology o, String id) {
        return o.techniques().stream().filter(t -> t.id().equals(id)).findFirst().orElseThrow();
    }

    @Test
    void parsesOntologyHierarchyAndTactics() throws IOException {
        Bundle b = load("1.6.0");
        Ontology o = b.ontology();
        assertEquals("1.6.0", b.version());
        assertNotNull(o.releasedAt());
        assertEquals(List.of("Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"),
                o.tactics().stream().map(D3fendBundle.Tactic::name).toList());
        assertTrue(o.techniques().size() > 200, "방어 기법 수: " + o.techniques().size());
        assertTrue(o.techniques().stream().allMatch(t -> t.id().startsWith("D3-")), "분석 기법(D3A-)은 받지 않는다");
        // D3-PT Process Termination ⊂ D3-PE Process Eviction (전술 Evict 를 상위에서 물려받는다)
        Technique pt = tech(o, "D3-PT");
        assertEquals("Process Termination", pt.name());
        assertEquals("D3-PE", pt.parentId());
        assertEquals("Evict", pt.tactic());
        assertEquals(1, pt.depth());
        Technique pe = tech(o, "D3-PE");
        assertNull(pe.parentId());
        assertEquals(0, pe.depth());
        assertEquals("Isolate", tech(o, "D3-NI").tactic());
        assertTrue(o.techniques().stream().allMatch(t -> t.tactic() != null), "모든 방어 기법은 전술이 있다");
        // ATT&CK 완화 M ↔ D3FEND (d3f:related)
        assertTrue(o.mitigations().stream().anyMatch(m -> m.mitigationId().equals("M1042") && m.d3fId().startsWith("D3-")));
    }

    @Test
    void parsesMappingsByLabelAndKeepsAttackDomain() throws IOException {
        Bundle b = load("1.6.0");
        Set<String> forT1190 = new TreeSet<>();
        for (Mapping m : b.mappings()) {
            if (m.attackId().equals("T1190")) {
                forT1190.add(m.d3fId());
                assertEquals("enterprise", m.attackDomain());
                assertEquals("Exploit Public-Facing Application", m.attackName());
                assertTrue(!m.via().isEmpty() && m.via().size() <= D3fendBundle.MAX_VIA);
            }
        }
        assertTrue(forT1190.containsAll(Set.of("D3-ITF", "D3-NI")), forT1190.toString());
        Map<String, Integer> c = b.counts();
        assertEquals(b.mappings().size(), c.get("mapping"));
        assertTrue(c.get("attack_technique") > 10);
    }

    @Test
    void versionOverrideAndRejectsWrongFiles() throws IOException {
        try (InputStream o = Files.newInputStream(FIXTURES.resolve("1.5.0/d3fend.json"))) {
            assertEquals("1.5.0-local", D3fendBundle.parseOntology(o, "1.5.0-local").version());
        }
        assertThrows(ApiException.class, () -> D3fendBundle.parseOntology(
                new ByteArrayInputStream("{\"type\":\"bundle\",\"objects\":[]}".getBytes(StandardCharsets.UTF_8)), null));
        Ontology ont;
        try (InputStream o = Files.newInputStream(FIXTURES.resolve("1.6.0/d3fend.json"))) {
            ont = D3fendBundle.parseOntology(o, null);
        }
        ApiException e = assertThrows(ApiException.class, () -> D3fendBundle.parseMappings(ont,
                new ByteArrayInputStream("a,b,c\n1,2,3\n".getBytes(StandardCharsets.UTF_8))));
        assertTrue(e.getMessage().contains("query_def_tech_label"));
    }

    @Test
    void csvReaderHandlesQuotesCommasAndNewlines() throws IOException {
        D3fendBundle.CsvReader r = new D3fendBundle.CsvReader(new StringReader("a,\"b,1\",\"say \"\"hi\"\"\"\r\n\"multi\nline\",,x\nlast"));
        assertEquals(List.of("a", "b,1", "say \"hi\""), r.next());
        assertEquals(List.of("multi\nline", "", "x"), r.next());
        assertEquals(List.of("last"), r.next());
        assertNull(r.next());
    }

    @Test
    void formatErrorAndIds() {
        assertNull(D3fendService.formatError(null));
        assertNull(D3fendService.formatError(List.of("D3-PT", "D3-NI")));
        assertNotNull(D3fendService.formatError("D3-PT"));
        assertNotNull(D3fendService.formatError(List.of("T1190")));
        assertNotNull(D3fendService.formatError(List.of("D3A-BLRL")));
        assertNotNull(D3fendService.formatError(List.of("D3-PT", "D3-PT")));
        assertEquals(List.of("D3-PT"), D3fendService.ids(List.of("D3-PT", "bad", 3, "D3-PT")));
        assertTrue(D3fendService.VERSION_ORDER.compare("1.10.0", "1.6.0") > 0);
        assertTrue(D3fendService.VERSION_ORDER.compare("0.13.0-BETA-1", "1.0.0") < 0);
    }

    /** 기본 룰·순서도의 지정 대응방책은 모두 테스트 릴리스(= 공식 릴리스의 기법 전부)에 있어야 한다. */
    @Test
    void builtinDesignatedCountermeasuresExist() throws IOException {
        Ontology o = load("1.6.0").ontology();
        Set<String> known = new TreeSet<>();
        o.techniques().forEach(t -> known.add(t.id()));
        Set<String> used = new TreeSet<>();
        Pattern yaml = Pattern.compile("(?m)^d3fend:\\s*\\[(.*)]\\s*$");
        for (Path f : TestFiles.list("rules/builtin/single", ".yaml")) {
            Matcher m = yaml.matcher(TestFiles.read(f));
            if (m.find()) {
                for (String s : m.group(1).split(",")) {
                    used.add(s.trim());
                }
            }
        }
        for (Path f : TestFiles.list("rules/builtin/scenarios", ".json")) {
            for (Object n : Json.asList(Json.loadMap(TestFiles.read(f)).get("nodes"))) {
                used.addAll(Json.strings(Json.asMap(n).get("d3fend")));
            }
        }
        assertTrue(used.size() >= 10, used.toString());
        used.forEach(id -> assertNull(D3fendService.formatError(List.of(id)), id));
        Set<String> missing = new TreeSet<>(used);
        missing.removeAll(known);
        assertTrue(missing.isEmpty(), "D3FEND 에 없는 지정 대응방책: " + missing);
    }
}
