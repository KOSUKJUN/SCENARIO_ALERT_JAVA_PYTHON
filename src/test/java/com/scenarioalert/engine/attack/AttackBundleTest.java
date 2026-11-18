package com.scenarioalert.engine.attack;

import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.attack.AttackBundle.Bundle;
import com.scenarioalert.engine.attack.AttackBundle.Obj;
import com.scenarioalert.engine.attack.AttackDiff.Ref;
import com.scenarioalert.engine.attack.AttackDiff.Tech;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Json;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ATT&CK STIX 번들 읽기, 버전 비교, 기법 ID 형식 검사 (DB 없음). */
class AttackBundleTest {
    static final Path FIXTURES = Path.of("src/test/resources/attack");

    static Bundle load(String version) throws IOException {
        try (InputStream in = Files.newInputStream(FIXTURES.resolve("enterprise-attack-mini-" + version + ".json"))) {
            return AttackBundle.parse(in, null);
        }
    }

    static Obj obj(Bundle b, String type, String id) {
        return b.objects().stream().filter(o -> o.type().equals(type) && o.attackId().equals(id)).findFirst().orElse(null);
    }

    @Test
    void parsesOfficialBundleStructure() throws IOException {
        Bundle b = load("20.1");
        assertEquals("enterprise-attack", b.domain());
        assertEquals("20.1", b.version());
        assertEquals("Enterprise ATT&CK", b.name());
        assertNotNull(b.releasedAt());
        assertEquals(15, b.counts().get("tactic"));

        Obj t = obj(b, "technique", "T1190");
        assertEquals("Exploit Public-Facing Application", t.name());
        assertEquals(List.of("initial-access"), t.tactics());
        assertNull(t.parentId());
        assertEquals("https://attack.mitre.org/techniques/T1190", t.url());

        Obj sub = obj(b, "technique", "T1059.004");
        assertEquals("T1059", sub.parentId());
        assertNotNull(obj(b, "technique", "T1059"), "상위 기법도 남아 있어야 한다");

        // 전술 순서는 매트릭스의 tactic_refs 순서 (정찰이 처음)
        Obj recon = obj(b, "tactic", "TA0043");
        assertEquals("reconnaissance", recon.shortname());
        assertEquals(0, recon.ord());

        // 관계는 기법을 향한 것만, 출발 유형이 맞는 것만
        assertTrue(b.relations().stream().anyMatch(r -> r.relType().equals("mitigates") && r.srcId().startsWith("M")
                && r.dstId().equals("T1190")));
        assertTrue(b.relations().stream().anyMatch(r -> r.relType().equals("detects") && r.srcId().startsWith("DET")));
        assertTrue(b.relations().stream().anyMatch(r -> r.relType().equals("uses") && r.srcType().equals("group")));
        assertTrue(b.relations().stream().allMatch(r -> AttackBundle.TECHNIQUE_ID.matcher(r.dstId()).matches()));
        // 소프트웨어 종류(malware/tool)
        assertTrue(b.objects().stream().filter(o -> o.type().equals("software"))
                .allMatch(o -> Set.of("malware", "tool").contains(o.extra().get("kind"))));
    }

    @Test
    void everyBuiltinTechniqueExistsInFixture() throws IOException {
        Bundle b = load("20.1");
        Set<String> live = new TreeSet<>();
        b.objects().stream().filter(o -> o.type().equals("technique") && !o.revoked() && !o.deprecated())
                .forEach(o -> live.add(o.attackId()));
        Set<String> used = builtinTechniques();
        assertFalse(used.isEmpty());
        for (String id : used) {
            assertTrue(live.contains(id), "기본 룰·순서도가 참조하는 기법이 ATT&CK 20.1 에 없음: " + id);
        }
    }

    static Set<String> builtinTechniques() throws IOException {
        Set<String> used = new TreeSet<>();
        Pattern p = Pattern.compile("(?m)^attack:\\s*\\[(.*)]\\s*$");
        for (Path f : TestFiles.builtinRules()) {
            Matcher m = p.matcher(Files.readString(f, StandardCharsets.UTF_8));
            if (m.find()) {
                for (String s : m.group(1).split(",")) {
                    used.add(s.trim());
                }
            }
        }
        for (Path f : TestFiles.builtinScenarios()) {
            for (Object n : Json.asList(Json.loadMap(Files.readString(f, StandardCharsets.UTF_8)).get("nodes"))) {
                used.addAll(AttackService.ids(Json.asMap(n).get("attack")));
            }
        }
        return used;
    }

    @Test
    void realDiffBetween19And20() throws IOException {
        Map<String, Object> d = AttackDiff.diff(techs(load("19.2")), techs(load("20.1")));
        @SuppressWarnings("unchecked")
        Map<String, Object> s = (Map<String, Object>) d.get("summary");
        assertEquals(8, s.get("added"), String.valueOf(d.get("added")));   // 픽스처에 넣은 20.1 신규 기법 (T1685 상위 기법 제외)
        assertEquals(0, s.get("removed"));
        assertEquals(0, s.get("revoked"));
    }

    static Map<String, Tech> techs(Bundle b) {
        Map<String, Tech> m = new HashMap<>();
        b.objects().stream().filter(o -> o.type().equals("technique")).forEach(o -> m.put(o.attackId(),
                new Tech(o.attackId(), o.name(), o.tactics(), o.deprecated(), o.revoked(), o.revokedBy(), o.modified())));
        return m;
    }

    @Test
    void diffDetectsRevokedDeprecatedRenamedAndTactics() {
        LocalDateTime t0 = LocalDateTime.of(2026, 1, 1, 0, 0);
        Map<String, Tech> from = Map.of(
                "T1000", new Tech("T1000", "Old Name", List.of("execution"), false, false, null, t0),
                "T1001", new Tech("T1001", "Going Away", List.of("execution"), false, false, null, t0),
                "T1002", new Tech("T1002", "Deprecated Soon", List.of("discovery"), false, false, null, t0),
                "T1003", new Tech("T1003", "Moves Tactic", List.of("discovery"), false, false, null, t0),
                "T1004", new Tech("T1004", "Removed", List.of("discovery"), false, false, null, t0));
        Map<String, Tech> to = Map.of(
                "T1000", new Tech("T1000", "New Name", List.of("execution"), false, false, null, t0.plusDays(1)),
                "T1001", new Tech("T1001", "Going Away", List.of("execution"), false, true, "T1005", t0),
                "T1002", new Tech("T1002", "Deprecated Soon", List.of("discovery"), true, false, null, t0),
                "T1003", new Tech("T1003", "Moves Tactic", List.of("discovery", "stealth"), false, false, null, t0),
                "T1005", new Tech("T1005", "Replacement", List.of("execution"), false, false, null, t0));
        Map<String, Object> d = AttackDiff.diff(from, to);
        assertEquals(Map.of("added", 1, "removed", 1, "revoked", 1, "deprecated", 1, "renamed", 1, "tactics_changed", 1,
                "updated", 1), d.get("summary"));
        assertEquals("T1005", ((Map<?, ?>) ((List<?>) d.get("revoked")).get(0)).get("revoked_by"));
        assertEquals("Replacement", ((Map<?, ?>) ((List<?>) d.get("revoked")).get(0)).get("revoked_by_name"));

        Map<String, List<Ref>> refs = Map.of(
                "T1000", List.of(new Ref("rule", "SR_A", "A", "active", null)),
                "T1001", List.of(new Ref("scenario", "SC_B", "B", "active", "경보 노드 a1")),
                "T1002", List.of(new Ref("rule", "SR_C", "C", "silent", null)),
                "T1004", List.of(new Ref("rule", "SR_D", "D", "draft", null)));
        List<Map<String, Object>> imp = AttackDiff.impact(refs, to);
        assertEquals(List.of("T1001:revoked", "T1002:deprecated", "T1004:missing"),
                imp.stream().map(m -> m.get("technique") + ":" + m.get("status")).toList());
        assertEquals("T1005 Replacement", imp.get(0).get("replacement"));
    }

    @Test
    void techniqueIdFormat() {
        assertNull(AttackService.formatError(null));
        assertNull(AttackService.formatError(List.of("T1190", "T1059.004")));
        assertNotNull(AttackService.formatError("T1190"));
        assertNotNull(AttackService.formatError(List.of("T190")));
        assertNotNull(AttackService.formatError(List.of("t1190")));
        assertNotNull(AttackService.formatError(List.of("T1059.4")));
        assertNotNull(AttackService.formatError(List.of("T1190", "T1190")));
        assertNotNull(AttackService.formatError(java.util.Collections.nCopies(21, "T1190")));
        assertEquals(List.of("T1190"), AttackService.ids(List.of("T1190", "bad", 3, "T1190")));
    }

    @Test
    void rejectsNonBundles() {
        assertThrows(ApiException.class, () -> AttackBundle.parse(stream("{\"type\":\"identity\",\"objects\":[]}"), null));
        assertThrows(ApiException.class, () -> AttackBundle.parse(stream("{\"type\":\"bundle\",\"objects\":[]}"), null));
        assertThrows(ApiException.class, () -> AttackBundle.parse(stream("[1,2]"), null));
    }

    /** 가져오기는 읽은 뒤 같은 스트림으로 파일 전체의 sha256 을 낸다. 파서가 스트림을 닫으면 안 된다. */
    @Test
    void parseLeavesStreamOpen() throws IOException {
        byte[] data = Files.readAllBytes(FIXTURES.resolve("enterprise-attack-mini-20.1.json"));
        boolean[] closed = {false};
        InputStream in = new java.io.FilterInputStream(new ByteArrayInputStream(data)) {
            @Override
            public void close() throws IOException {
                closed[0] = true;
                super.close();
            }
        };
        AttackBundle.parse(in, null);
        assertFalse(closed[0]);
    }

    @Test
    void versionOverrideMustMatchBundle() throws IOException {
        try (InputStream in = Files.newInputStream(FIXTURES.resolve("enterprise-attack-mini-20.1.json"))) {
            assertThrows(ApiException.class, () -> AttackBundle.parse(in, "19.0"));
        }
    }

    @Test
    void versionOrder() {
        List<String> v = Stream.of("9.0", "20.1", "19.2", "20.0", "10.1").sorted(AttackService.VERSION_ORDER).toList();
        assertEquals(List.of("9.0", "10.1", "19.2", "20.0", "20.1"), v);
    }

    static InputStream stream(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }
}
