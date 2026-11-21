package com.scenarioalert.engine.it;

import com.scenarioalert.engine.InitService;
import com.scenarioalert.engine.TestFiles;
import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.d3fend.D3fendService;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.sample.SampleDataService;
import com.scenarioalert.engine.scenario.ScenarioCodeStore;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.scenarioalert.engine.common.Db.p;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M5: REST API 권한, 순서도 저장 → 시나리오별 Python 코드 생성 → 시뮬레이션, 단일룰 컴파일.
 * 관리 화면(web/)이 쓰는 응답 모양을 확인한다.
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "app.mode=test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiIT {
    @LocalServerPort int port;
    @Autowired Db db;
    @Autowired InitService init;
    @Autowired SampleDataService samples;
    @Autowired ScenarioCodeStore codeStore;
    @Autowired AttackService attack;
    @Autowired D3fendService d3fend;
    @Autowired ClickHouse ch;
    final HttpClient http = HttpClient.newHttpClient();

    record Res(int status, Object body) {
        @SuppressWarnings("unchecked")
        Map<String, Object> map() {
            return (Map<String, Object>) body;
        }
    }

    Res call(String method, String path, String token, Object body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1" + path))
                .header("Content-Type", "application/json")
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(Json.dump(body), StandardCharsets.UTF_8));
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new Res(r.statusCode(), r.body().isEmpty() ? null : Json.load(r.body()));
    }

    String login(String user, String pw) throws Exception {
        Res r = call("POST", "/auth/login", null, Map.of("username", user, "password", pw));
        assertEquals(200, r.status(), String.valueOf(r.body()));
        return (String) r.map().get("token");
    }

    @BeforeAll
    void setup() {
        init.waitReady(120);
        init.applyClickHouse(true);
        samples.seedReference();
        ItSupport.loadAttack(db, attack);
        ItSupport.loadD3fend(db, d3fend);
        init.loadBuiltin("active");
        db.txRun(() -> {
            db.execute("DELETE FROM scenario_rule_refs WHERE scenario_id='SC_API_TEST'", Map.of());
            db.execute("DELETE FROM scenario_versions WHERE scenario_id='SC_API_TEST'", Map.of());
            db.execute("DELETE FROM scenarios WHERE scenario_id='SC_API_TEST'", Map.of());
        });
    }

    @Test
    void rolesAreEnforced() throws Exception {
        assertEquals(401, call("GET", "/scenarios", null, null).status());
        assertEquals(401, call("POST", "/auth/login", null, Map.of("username", "admin", "password", "wrong")).status());
        String viewer = login("viewer", "viewer123");
        assertEquals(200, call("GET", "/scenarios", viewer, null).status());
        assertEquals(403, call("GET", "/alerts", viewer, null).status());
        assertEquals(403, call("POST", "/scenarios/validate", viewer, Map.of("graph", Map.of())).status());
        assertEquals(401, call("POST", "/hooks/case-verdict", null, Map.of("verdict", "benign")).status());
        Res me = call("GET", "/auth/me", login("author", "author123"), null);
        assertEquals("author", me.map().get("role"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void scenarioSaveGeneratesPythonPerVersion() throws Exception {
        String author = login("author", "author123");
        Map<String, Object> graph = Json.loadMap("""
                {"id": "SC_API_TEST", "name": "API 시험 순서도", "entity_type": "host", "suppress_for": "1h",
                 "nodes": [{"id": "n0", "type": "start", "pos": [0, 0]},
                           {"id": "n1", "type": "rule", "rule_id": "SR_SMB_OUT_FANOUT", "pos": [100, 0]},
                           {"id": "a1", "type": "alert", "severity": "high", "title": "시험 \\"따옴표\\"\\n줄바꿈 {{entity}}",
                            "pos": [200, 0]}],
                 "edges": [{"from": "n0", "to": "n1"}, {"from": "n1", "to": "a1"}]}""");
        // 저장 전 코드 미리보기
        Res pre = call("POST", "/scenarios/codegen", author, Map.of("graph", graph));
        assertEquals(true, pre.map().get("ok"));
        assertTrue(((String) pre.map().get("python_code")).contains("def evaluate(hits, asset_tags):"));
        // 생성 → v1 코드
        Res c1 = call("POST", "/scenarios", author, Map.of("graph", graph, "change_note", "생성"));
        assertEquals(201, c1.status(), String.valueOf(c1.body()));
        Res code1 = call("GET", "/scenarios/SC_API_TEST/code", author, null);
        assertEquals(1, ((Number) code1.map().get("version")).intValue());
        String py1 = (String) code1.map().get("python_code");
        assertTrue(py1.contains("VERSION = 1") && py1.contains("SR_SMB_OUT_FANOUT"));
        assertTrue(Files.isRegularFile(codeStore.root().resolve("SC_API_TEST/v1.py")));
        // 수정 → v2 코드 (새 파일)
        ((List<Map<String, Object>>) (List<?>) graph.get("nodes")).get(2).put("severity", "critical");
        Res u = call("PUT", "/scenarios/SC_API_TEST", author, Map.of("graph", graph, "change_note", "등급 상향"));
        assertEquals(200, u.status(), String.valueOf(u.body()));
        Res code2 = call("GET", "/scenarios/SC_API_TEST/code", author, null);
        assertEquals(2, ((Number) code2.map().get("version")).intValue());
        assertNotEquals(code1.map().get("code_sha256"), code2.map().get("code_sha256"));
        assertTrue(Files.isRegularFile(codeStore.root().resolve("SC_API_TEST/v2.py")));
        assertEquals(py1, call("GET", "/scenarios/SC_API_TEST/code?version=1", author, null).map().get("python_code"));
        // 버전 이력과 차이
        List<Object> vs = (List<Object>) call("GET", "/scenarios/SC_API_TEST/versions", author, null).body();
        assertEquals(2, vs.size());
        Map<String, Object> diff = (Map<String, Object>) ((Map<String, Object>) vs.get(0)).get("diff");
        assertEquals(List.of("a1"), diff.get("nodes_changed"));
        // 시뮬레이션: 생성 코드를 실제로 돌린다 (히트가 없어도 노드 상태가 나와야 한다)
        Res sim = call("POST", "/scenarios/simulate", author, Map.of("graph", graph, "org_id", "ORG001", "entity", "10.10.250.250"));
        assertEquals(200, sim.status(), String.valueOf(sim.body()));
        assertEquals(true, sim.map().get("ok"));
        Map<String, Object> ns = (Map<String, Object>) sim.map().get("node_status");
        assertEquals("reached", ((Map<String, Object>) ns.get("n0")).get("status"));
        assertEquals("no_hit", ((Map<String, Object>) ns.get("n1")).get("reason"));
        // 잘못된 그래프는 노드 ID 와 함께 거부
        graph.put("edges", List.of(Map.of("from", "n0", "to", "n1")));
        Res bad = call("PUT", "/scenarios/SC_API_TEST", author, Map.of("graph", graph));
        assertEquals(422, bad.status());
        assertFalse(((List<Object>) bad.map().get("errors")).isEmpty());
    }

    @Test
    @SuppressWarnings("unchecked")
    void ruleCompileAndHealth() throws Exception {
        String author = login("author", "author123");
        Map<String, Object> rule = Json.loadMap("""
                {"id": "SR_API_TMP", "name": "임시", "type": "signature", "entity": {"type": "host", "field": "src_ip"},
                 "data_tp": ["IDS"], "window": "5m", "filter": {"all": [{"field": "payload", "op": "contains", "value": "x'y"}]}}""");
        Res c = call("POST", "/single-rules/compile", author, Map.of("definition", rule));
        assertEquals(true, c.map().get("ok"), String.valueOf(c.body()));
        assertTrue(((String) c.map().get("sql")).contains("INSERT INTO detect.rule_hits"));
        Res meta = call("GET", "/meta/fields", author, null);
        assertFalse(((List<Object>) meta.map().get("fields")).isEmpty());
        Res h = call("GET", "/health", null, null);
        assertEquals("ok", h.map().get("status"), String.valueOf(h.body()));
        assertTrue(String.valueOf(h.map().get("python")).startsWith("ok"));
        Map<String, Object> cnt = db.row("SELECT COUNT(*) AS n FROM single_rules WHERE rule_id='SR_API_TMP'", p());
        assertEquals(0L, Db.lng(cnt, "n"), "compile 은 저장하지 않는다");
    }

    @Test
    @SuppressWarnings("unchecked")
    void snortImportPreviewsThenCreatesDraft() throws Exception {
        db.txRun(() -> {
            db.execute("DELETE FROM single_rule_versions WHERE rule_id LIKE 'SR_ITSNORT_%'", Map.of());
            db.execute("DELETE FROM single_rules WHERE rule_id LIKE 'SR_ITSNORT_%'", Map.of());
        });
        String text = """
                alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"IT SSH 대입"; threshold: type both, track by_dst, count 30, seconds 60; sid:42;)
                pass tcp any any -> any any (msg:"skip"; sid:43;)
                """;
        assertEquals(403, call("POST", "/single-rules/import/snort", login("viewer", "viewer123"), Map.of("text", text)).status());
        String author = login("author", "author123");
        assertEquals(400, call("POST", "/single-rules/import/snort", author, Map.of("text", text, "id_prefix", "bad")).status());
        Res r = call("POST", "/single-rules/import/snort", author, Map.of("text", text, "id_prefix", "SR_ITSNORT_"));
        assertEquals(200, r.status(), String.valueOf(r.body()));
        assertEquals(2, ((Number) r.map().get("total")).intValue());
        assertEquals(1, ((Number) r.map().get("convertible")).intValue());
        List<Map<String, Object>> items = (List<Map<String, Object>>) r.map().get("items");
        Map<String, Object> ok = items.get(0);
        assertEquals(true, ok.get("ok"), String.valueOf(ok));
        assertEquals(false, ok.get("exists"));
        assertTrue(((String) ok.get("sql")).contains("INSERT INTO detect.rule_hits"));
        assertTrue(String.valueOf(items.get(1).get("skipped")).contains("pass"));
        // 미리보기는 저장하지 않는다
        assertEquals(0L, Db.lng(db.row("SELECT COUNT(*) AS n FROM single_rules WHERE rule_id='SR_ITSNORT_42'", p()), "n"));
        // 고른 정의를 그대로 만들면 draft
        Res c = call("POST", "/single-rules", author, Map.of("definition", ok.get("definition"), "change_note", "Snort 룰 가져오기"));
        assertEquals(201, c.status(), String.valueOf(c.body()));
        assertEquals("draft", ((Map<String, Object>) c.map().get("rule")).get("status"));
        Res again = call("POST", "/single-rules/import/snort", author, Map.of("text", text, "id_prefix", "SR_ITSNORT_"));
        assertEquals(true, ((List<Map<String, Object>>) again.map().get("items")).get(0).get("exists"));
    }

    // ------------------------------------------------------------------ 로그 수집원 → 기관
    String orgOfEvent(String eventCd) {
        List<Map<String, Object>> r = ch.query("SELECT org_id, log_source FROM detect.v_events WHERE event_id = {e:String}",
                Map.of("e", eventCd));
        return r.isEmpty() ? null : String.valueOf(r.get(0).get("org_id"));
    }

    /** 운영 원본에는 기관 컬럼이 없다: 로그 수집원(_asset_id) 매핑으로 기관을 정하고, 매핑이 없으면 UNASSIGNED 로 탐지한다. */
    @Test
    @SuppressWarnings("unchecked")
    void logSourceMappingDecidesOrg() throws Exception {
        String asset = "IT_NEW_LOGSRC";
        db.txRun(() -> db.execute("DELETE FROM log_sources WHERE asset_id=:a", p("a", asset)));
        ch.reloadDictionaries(List.of("dict_log_sources"));
        String eventCd = "it-logsrc-" + System.nanoTime();
        Map<String, Object> e = new java.util.LinkedHashMap<>();
        e.put("_event_cd", eventCd);
        e.put("_collect_time", com.scenarioalert.engine.common.Kst.fmt(com.scenarioalert.engine.common.Kst.now()));
        e.put("_data_type", "IPS");
        e.put("_asset_id", asset);
        e.put("src_ip", "10.10.250.1");
        e.put("dst_ip", "198.51.100.250");
        e.put("dst_port", 443);
        e.put("fields", Map.of("count", "3", "action", "allow"));
        samples.insertEvents(List.of(SampleDataService.toRow(e)));
        assertEquals("UNASSIGNED", orgOfEvent(eventCd), "매핑 없는 수집원");

        String viewer = login("viewer", "viewer123");
        Res ls = call("GET", "/log-sources", viewer, null);
        assertEquals(200, ls.status(), String.valueOf(ls.body()));
        assertTrue(((List<Map<String, Object>>) ls.map().get("items")).stream()
                .anyMatch(x -> SampleDataService.assetId("ORG001", "WAF").equals(x.get("asset_id"))), "테스트 수집원 매핑");
        assertTrue(((List<Map<String, Object>>) ls.map().get("unmapped")).stream().anyMatch(x -> asset.equals(x.get("asset_id"))),
                "최근 이벤트가 있는 미매핑 수집원이 보여야 한다");

        String admin = login("admin", "admin123");
        assertEquals(403, call("PUT", "/log-sources/" + asset, login("author", "author123"), Map.of("org_id", "ORG002")).status());
        assertEquals(400, call("PUT", "/log-sources/" + asset, admin, Map.of("org_id", "NO_SUCH_ORG")).status());
        assertEquals(400, call("PUT", "/log-sources/bad%20id", admin, Map.of("org_id", "ORG002")).status());
        assertEquals(200, call("PUT", "/log-sources/" + asset, admin, Map.of("org_id", "ORG002", "description", "IT")).status());
        assertEquals("ORG002", orgOfEvent(eventCd), "매핑하면 그 기관 (딕셔너리 다시 읽음)");
        assertTrue(Db.lng(db.row("SELECT COUNT(*) AS n FROM audit_log WHERE action='log_source.save' AND target=:a",
                p("a", asset)), "n") > 0, "감사 로그");
        assertEquals(200, call("DELETE", "/log-sources/" + asset, admin, null).status());
        assertEquals("UNASSIGNED", orgOfEvent(eventCd));
        assertEquals(404, call("DELETE", "/log-sources/" + asset, admin, null).status());
    }

    // ------------------------------------------------------------------ MITRE ATT&CK
    Res upload(String token, byte[] data, String name) throws Exception {
        String boundary = "----attack" + System.nanoTime();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + name
                + "\"\r\nContent-Type: application/json\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(data);
        out.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/attack/versions/import"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary).header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofByteArray(out.toByteArray())).build();
        HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new Res(r.statusCode(), r.body().isEmpty() ? null : Json.load(r.body()));
    }

    @Test
    @SuppressWarnings("unchecked")
    void attackVersionsAndReferences() throws Exception {
        String admin = login("admin", "admin123");
        String author = login("author", "author123");
        String viewer = login("viewer", "viewer123");
        Res v = call("GET", "/attack/versions", viewer, null);
        assertEquals(200, v.status());
        assertEquals(Map.of("enterprise-attack", "20.1"), v.map().get("active"));
        assertEquals(2, ((List<Object>) v.map().get("versions")).size());

        // 가져오기: admin 만, 같은 파일은 다시 넣지 않고, 같은 버전의 다른 파일은 거부, 번들이 아니면 거부
        byte[] mini = Files.readAllBytes(ItSupport.ATTACK_FIXTURES.resolve("enterprise-attack-mini-19.2.json"));
        assertEquals(403, upload(viewer, mini, "a.json").status());
        Res again = upload(admin, mini, "enterprise-attack-mini-19.2.json");
        assertEquals(200, again.status(), String.valueOf(again.body()));
        assertEquals("already_imported", again.map().get("status"));
        byte[] changed = (new String(mini, StandardCharsets.UTF_8) + "\n ").getBytes(StandardCharsets.UTF_8);
        assertEquals(409, upload(admin, changed, "changed.json").status());
        assertEquals(400, upload(admin, "{\"type\":\"bundle\",\"objects\":[]}".getBytes(StandardCharsets.UTF_8), "e.json").status());

        // 버전 비교 (19.2 → 20.1: 기법 추가만) 와 현재 룰·순서도 영향 (없음)
        Res d = call("GET", "/attack/versions/enterprise-attack/20.1/diff?from=19.2", viewer, null);
        assertEquals(200, d.status(), String.valueOf(d.body()));
        assertEquals(8, ((Map<String, Object>) d.map().get("summary")).get("added"));
        assertEquals(List.of(), d.map().get("impact"));

        // 활성 버전 바꾸기 (admin 만), 활성 버전 삭제 거부, 비활성 버전 삭제 후 다시 가져오기 (활성화는 하지 않는다)
        assertEquals(200, call("POST", "/attack/versions/enterprise-attack/19.2/activate", admin, null).status());
        assertEquals(Map.of("enterprise-attack", "19.2"), call("GET", "/attack/versions", viewer, null).map().get("active"));
        assertEquals(409, call("DELETE", "/attack/versions/enterprise-attack/19.2", admin, null).status());
        assertEquals(403, call("POST", "/attack/versions/enterprise-attack/20.1/activate", author, null).status());
        assertEquals(200, call("POST", "/attack/versions/enterprise-attack/20.1/activate", admin, null).status());
        assertEquals(200, call("DELETE", "/attack/versions/enterprise-attack/19.2", admin, null).status());
        Res re = upload(admin, mini, "enterprise-attack-mini-19.2.json");
        assertEquals("imported", re.map().get("status"), String.valueOf(re.body()));
        assertEquals(false, re.map().get("is_active"));

        // 기법 상세: 전술, 완화, 탐지 전략, 커버리지(그 기법을 단 룰, 그 기법에 이르는 순서도)
        Res t = call("GET", "/attack/techniques/T1190", viewer, null);
        assertEquals(200, t.status(), String.valueOf(t.body()));
        assertEquals("Exploit Public-Facing Application", t.map().get("name"));
        assertEquals("TA0001", ((Map<String, Object>) ((List<Object>) t.map().get("tactics")).get(0)).get("id"));
        assertFalse(((List<Object>) t.map().get("mitigations")).isEmpty());
        assertFalse(((List<Object>) t.map().get("detections")).isEmpty());
        Map<String, Object> cov = (Map<String, Object>) t.map().get("coverage");
        assertTrue(((List<Map<String, Object>>) cov.get("rules")).stream().anyMatch(r -> "SR_PHP2SHELL_EXPLOIT".equals(r.get("id"))));
        assertTrue(((List<Map<String, Object>>) cov.get("scenarios")).stream().anyMatch(r -> "SC_PHP2SHELL".equals(r.get("id"))));
        assertEquals(404, call("GET", "/attack/techniques/T9999", viewer, null).status());
        List<Map<String, Object>> found = (List<Map<String, Object>>) call("GET", "/attack/techniques?q=T1059", viewer, null).body();
        assertTrue(found.stream().anyMatch(x -> "T1059.004".equals(x.get("id"))), String.valueOf(found));
        List<Map<String, Object>> byName = (List<Map<String, Object>>) call("GET", "/attack/techniques?q=brute", viewer, null).body();
        assertTrue(byName.stream().anyMatch(x -> "T1110".equals(x.get("id"))), String.valueOf(byName));

        // 매트릭스: 전술 순서(정찰 먼저)와 커버리지
        Res m = call("GET", "/attack/matrix", viewer, null);
        List<Map<String, Object>> tactics = (List<Map<String, Object>>) m.map().get("tactics");
        assertEquals(15, tactics.size());
        assertEquals("TA0043", tactics.get(0).get("id"));
        assertTrue(((Number) ((Map<String, Object>) m.map().get("summary")).get("covered")).intValue() >= 10, String.valueOf(m.map().get("summary")));

        // 룰·순서도 저장 전 검사: 활성 버전에 없는 기법은 오류, 형식 오류도 오류
        Map<String, Object> defn = Json.loadYamlMap(Files.readString(TestFiles.ROOT
                .resolve("rules/builtin/single/SR_TI_HIT.yaml"), StandardCharsets.UTF_8));
        defn.put("attack", List.of("T1071", "T9999"));
        Res c = call("POST", "/single-rules/compile", author, Map.of("definition", defn));
        assertEquals(false, c.map().get("ok"));
        assertTrue(String.valueOf(c.map().get("errors")).contains("T9999"), String.valueOf(c.map().get("errors")));
        defn.put("attack", List.of("T71"));
        assertEquals(false, call("POST", "/single-rules/compile", author, Map.of("definition", defn)).map().get("ok"));
        defn.put("attack", List.of("T1110.001"));   // 테스트 번들에 있는 하위 기법
        Res okc = call("POST", "/single-rules/compile", author, Map.of("definition", defn));
        assertEquals(true, okc.map().get("ok"), String.valueOf(okc.map().get("errors")));
        Map<String, Object> graph = Json.loadMap("""
                {"id": "SC_API_ATTACK", "name": "ATT&CK 검사", "entity_type": "host",
                 "nodes": [{"id": "n0", "type": "start"}, {"id": "n1", "type": "rule", "rule_id": "SR_TI_HIT"},
                           {"id": "a1", "type": "alert", "severity": "low", "title": "t", "attack": ["T1071", "T9998"]}],
                 "edges": [{"from": "n0", "to": "n1"}, {"from": "n1", "to": "a1"}]}""");
        Res gv = call("POST", "/scenarios/validate", author, Map.of("graph", graph));
        assertEquals(false, gv.map().get("ok"));
        assertTrue(String.valueOf(gv.map().get("errors")).contains("T9998"), String.valueOf(gv.map().get("errors")));

        // 경보 목록의 기법 필터 형식 검사
        String analyst = login("analyst", "analyst123");
        assertEquals(200, call("GET", "/alerts?technique=T1190", analyst, null).status());
        assertEquals(400, call("GET", "/alerts?technique=1190", analyst, null).status());
    }

    /** D3FEND 릴리스 올리기: 온톨로지(ontology)와 매핑 CSV(mappings) 두 부분. null 이면 그 부분을 뺀다. */
    Res uploadD3fend(String token, byte[] ontology, byte[] mappings) throws Exception {
        String boundary = "----d3fend" + System.nanoTime();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Object[] part : new Object[][]{{"ontology", "d3fend.json", ontology}, {"mappings", "d3fend-full-mappings.csv", mappings}}) {
            if (part[2] == null) {
                continue;
            }
            out.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + part[0] + "\"; filename=\"" + part[1]
                    + "\"\r\nContent-Type: application/octet-stream\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            out.write((byte[]) part[2]);
            out.write("\r\n".getBytes(StandardCharsets.UTF_8));
        }
        out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/d3fend/versions/import"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary).header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofByteArray(out.toByteArray())).build();
        HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new Res(r.statusCode(), r.body().isEmpty() ? null : Json.load(r.body()));
    }

    @Test
    @SuppressWarnings("unchecked")
    void d3fendVersionsAndCountermeasures() throws Exception {
        String admin = login("admin", "admin123");
        String author = login("author", "author123");
        String viewer = login("viewer", "viewer123");
        Res v = call("GET", "/d3fend/versions", viewer, null);
        assertEquals(200, v.status());
        assertEquals("1.6.0", v.map().get("active"));
        assertEquals(2, ((List<Object>) v.map().get("versions")).size());

        // 가져오기: admin 만, 두 파일 모두 필요, 같은 파일은 다시 넣지 않고, 같은 버전의 다른 파일은 거부
        byte[] ont = Files.readAllBytes(ItSupport.D3FEND_FIXTURES.resolve("1.5.0/d3fend.json"));
        byte[] map = Files.readAllBytes(ItSupport.D3FEND_FIXTURES.resolve("1.5.0/d3fend-full-mappings.csv"));
        assertEquals(403, uploadD3fend(viewer, ont, map).status());
        assertEquals(422, uploadD3fend(admin, ont, null).status());   // 매핑 CSV 부분이 없다
        Res again = uploadD3fend(admin, ont, map);
        assertEquals(200, again.status(), String.valueOf(again.body()));
        assertEquals("already_imported", again.map().get("status"));
        byte[] changed = (new String(map, StandardCharsets.UTF_8) + "\n").getBytes(StandardCharsets.UTF_8);
        assertEquals(409, uploadD3fend(admin, ont, changed).status());
        assertEquals(400, uploadD3fend(admin, "{\"@graph\": []}".getBytes(StandardCharsets.UTF_8), map).status());

        // 버전 비교 (1.5.0 → 1.6.0): 기법 목록은 같고 정의가 갱신됨. 지정 대응방책 영향 없음
        Res d = call("GET", "/d3fend/versions/1.6.0/diff?from=1.5.0", viewer, null);
        assertEquals(200, d.status(), String.valueOf(d.body()));
        Map<String, Object> sum = (Map<String, Object>) d.map().get("summary");
        assertEquals(0, sum.get("removed"));
        assertTrue(((Number) sum.get("updated")).intValue() > 0, String.valueOf(sum));
        assertEquals(List.of(), d.map().get("impact"));

        // 활성 버전 바꾸기 (admin 만), 활성 버전 삭제 거부, 비활성 버전 삭제 후 다시 가져오기 (활성화는 하지 않는다)
        assertEquals(403, call("POST", "/d3fend/versions/1.5.0/activate", author, null).status());
        assertEquals(200, call("POST", "/d3fend/versions/1.5.0/activate", admin, null).status());
        assertEquals("1.5.0", call("GET", "/d3fend/versions", viewer, null).map().get("active"));
        assertEquals(409, call("DELETE", "/d3fend/versions/1.5.0", admin, null).status());
        assertEquals(200, call("POST", "/d3fend/versions/1.6.0/activate", admin, null).status());
        assertEquals(200, call("DELETE", "/d3fend/versions/1.5.0", admin, null).status());
        Res re = uploadD3fend(admin, ont, map);
        assertEquals("imported", re.map().get("status"), String.valueOf(re.body()));
        assertEquals(false, re.map().get("is_active"));
        assertTrue(db.rows("SELECT action FROM audit_log WHERE action LIKE 'd3fend.%'").size() >= 4);

        // 기법 상세: 전술(상위에서 물려받음), 상위 기법, 이 기법이 막는 ATT&CK 기법
        Res t = call("GET", "/d3fend/techniques/D3-PT", viewer, null);
        assertEquals(200, t.status(), String.valueOf(t.body()));
        assertEquals("Process Termination", t.map().get("name"));
        assertEquals("Evict", t.map().get("tactic"));
        assertEquals("D3-PE", ((Map<String, Object>) ((List<Object>) t.map().get("ancestors")).get(0)).get("id"));
        assertTrue(((List<Map<String, Object>>) t.map().get("attack")).stream().anyMatch(a -> "T1505.003".equals(a.get("id"))));
        assertEquals(404, call("GET", "/d3fend/techniques/D3-NOPE", viewer, null).status());
        List<Map<String, Object>> found = (List<Map<String, Object>>) call("GET", "/d3fend/techniques?q=isolation", viewer, null).body();
        assertTrue(found.stream().anyMatch(x -> "D3-NI".equals(x.get("id"))), String.valueOf(found));
        Map<String, Map<String, Object>> lk = (Map<String, Map<String, Object>>) call("POST", "/d3fend/techniques/lookup", viewer,
                Map.of("ids", List.of("D3-NI", "D3-ZZZ"))).body();
        assertEquals(Set.of("D3-NI"), lk.keySet());

        // 매트릭스: 전술 7개 (Model → Restore), 기법은 상위 아래에 하위가 이어진다
        Res m = call("GET", "/d3fend/matrix", viewer, null);
        List<Map<String, Object>> tactics = (List<Map<String, Object>>) m.map().get("tactics");
        assertEquals(List.of("Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"),
                tactics.stream().map(x -> x.get("name")).toList());
        List<Map<String, Object>> evict = (List<Map<String, Object>>) tactics.get(5).get("techniques");
        int pe = -1;
        for (int i = 0; i < evict.size(); i++) {
            if ("D3-PE".equals(evict.get(i).get("id"))) {
                pe = i;
            }
        }
        assertTrue(pe >= 0 && evict.subList(pe, evict.size()).stream().anyMatch(x -> "D3-PT".equals(x.get("id"))));

        // 대응방책: 경보의 ATT&CK 기법 → 전술별 권고(격리·퇴출·복구 먼저), 지정은 맨 앞, ATT&CK 완화(M) 연계
        Res cm = call("POST", "/d3fend/countermeasures", viewer,
                Map.of("attack", List.of("T1190", "T1059.004"), "d3fend", List.of("D3-PT")));
        assertEquals(200, cm.status(), String.valueOf(cm.body()));
        List<Map<String, Object>> groups = (List<Map<String, Object>>) cm.map().get("tactics");
        List<String> order = groups.stream().map(g -> String.valueOf(g.get("tactic"))).toList();
        assertEquals("Isolate", order.get(0), String.valueOf(order));
        Map<String, Object> ev = groups.stream().filter(g -> "Evict".equals(g.get("tactic"))).findFirst().orElseThrow();
        Map<String, Object> first = ((List<Map<String, Object>>) ev.get("techniques")).get(0);
        assertEquals("D3-PT", first.get("id"));
        assertEquals(true, first.get("designated"));
        Map<String, Object> iso = ((List<Map<String, Object>>) groups.get(0).get("techniques")).stream()
                .filter(x -> "D3-NI".equals(x.get("id"))).findFirst().orElseThrow();
        assertTrue(((List<Object>) iso.get("attack")).contains("T1190"));
        assertFalse(((List<Object>) cm.map().get("attack_mitigations")).isEmpty(), String.valueOf(cm.map().get("attack_mitigations")));
        assertEquals(400, call("POST", "/d3fend/countermeasures", viewer, Map.of("attack",
                java.util.stream.IntStream.range(1000, 1060).mapToObj(i -> "T" + i).toList())).status());

        // 연계 현황: 단일룰과 순서도 경보 노드마다 ATT&CK 기법·지정 대응방책
        Res links = call("GET", "/d3fend/links", viewer, null);
        assertEquals(200, links.status());
        assertTrue(((Number) ((Map<String, Object>) links.map().get("summary")).get("total")).intValue() > 20);

        // 저장 전 검사: 활성 버전에 없는 대응 기법은 오류, 형식 오류도 오류, 있는 기법은 통과
        Map<String, Object> defn = Json.loadYamlMap(Files.readString(TestFiles.ROOT
                .resolve("rules/builtin/single/SR_TI_HIT.yaml"), StandardCharsets.UTF_8));
        defn.put("d3fend", List.of("D3-OTF", "D3-NOPE"));
        Res c = call("POST", "/single-rules/compile", author, Map.of("definition", defn));
        assertEquals(false, c.map().get("ok"));
        assertTrue(String.valueOf(c.map().get("errors")).contains("D3-NOPE"), String.valueOf(c.map().get("errors")));
        defn.put("d3fend", List.of("T1071"));
        assertEquals(false, call("POST", "/single-rules/compile", author, Map.of("definition", defn)).map().get("ok"));
        defn.put("d3fend", List.of("D3-OTF", "D3-DNSDL"));
        Res okc = call("POST", "/single-rules/compile", author, Map.of("definition", defn));
        assertEquals(true, okc.map().get("ok"), String.valueOf(okc.map().get("errors")));
        Map<String, Object> graph = Json.loadMap("""
                {"id": "SC_API_D3FEND", "name": "D3FEND 검사", "entity_type": "host",
                 "nodes": [{"id": "n0", "type": "start"}, {"id": "n1", "type": "rule", "rule_id": "SR_TI_HIT"},
                           {"id": "a1", "type": "alert", "severity": "low", "title": "t", "d3fend": ["D3-NI", "D3-ZZZ"]}],
                 "edges": [{"from": "n0", "to": "n1"}, {"from": "n1", "to": "a1"}]}""");
        Res gv = call("POST", "/scenarios/validate", author, Map.of("graph", graph));
        assertEquals(false, gv.map().get("ok"));
        assertTrue(String.valueOf(gv.map().get("errors")).contains("D3-ZZZ"), String.valueOf(gv.map().get("errors")));
    }

    // ------------------------------------------------------------------ ATT&CK·D3FEND 버전 내보내기 패키지
    record Bin(int status, byte[] body, String disposition) {
    }

    Bin download(String path, String token) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1" + path))
                .header("Authorization", "Bearer " + token).GET().build();
        HttpResponse<byte[]> r = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        return new Bin(r.statusCode(), r.body(), r.headers().firstValue("Content-Disposition").orElse(""));
    }

    Res uploadPackage(String path, String token, byte[] data, String name) throws Exception {
        String boundary = "----pkg" + System.nanoTime();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + name
                + "\"\r\nContent-Type: application/zip\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(data);
        out.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1" + path))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary).header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofByteArray(out.toByteArray())).build();
        HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new Res(r.statusCode(), r.body().isEmpty() ? null : Json.load(r.body()));
    }

    static Map<String, byte[]> unzip(byte[] zip) throws Exception {
        Map<String, byte[]> m = new java.util.LinkedHashMap<>();
        try (java.util.zip.ZipInputStream z = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(zip))) {
            for (java.util.zip.ZipEntry e; (e = z.getNextEntry()) != null; ) {
                m.put(e.getName(), z.readAllBytes());
            }
        }
        return m;
    }

    static byte[] rezip(Map<String, byte[]> entries) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (java.util.zip.ZipOutputStream z = new java.util.zip.ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                z.putNextEntry(new java.util.zip.ZipEntry(e.getKey()));
                z.write(e.getValue());
                z.closeEntry();
            }
        }
        return out.toByteArray();
    }

    /** 패키지 안 데이터 파일(manifest 제외)만: 다시 내보낸 내용이 처음과 같은지 비교한다. */
    static Map<String, String> dataFiles(byte[] zip) throws Exception {
        Map<String, String> m = new java.util.TreeMap<>();
        unzip(zip).forEach((k, v) -> {
            if (!"manifest.json".equals(k)) {
                m.put(k, new String(v, StandardCharsets.UTF_8));
            }
        });
        return m;
    }

    @Test
    @SuppressWarnings("unchecked")
    void attackExportPackageRoundTrip() throws Exception {
        String admin = login("admin", "admin123");
        String viewer = login("viewer", "viewer123");
        assertEquals(403, download("/attack/versions/enterprise-attack/19.2/export", viewer).status());
        assertEquals(404, download("/attack/versions/enterprise-attack/9.9/export", admin).status());
        Bin ex = download("/attack/versions/enterprise-attack/19.2/export", admin);
        assertEquals(200, ex.status(), new String(ex.body(), StandardCharsets.UTF_8));
        assertTrue(ex.disposition().contains("attack_enterprise-attack_19.2.zip"), ex.disposition());
        Map<String, byte[]> files = unzip(ex.body());
        assertEquals(Set.of("manifest.json", "attack_objects.jsonl", "attack_relations.jsonl"), files.keySet());
        Map<String, Object> manifest = Json.loadMap(new String(files.get("manifest.json"), StandardCharsets.UTF_8));
        assertEquals("attack", manifest.get("kind"));
        Map<String, Object> mv = (Map<String, Object>) manifest.get("version");
        Map<String, Object> before = db.row("SELECT source_sha256, source_file, counts FROM attack_versions "
                + "WHERE domain='enterprise-attack' AND version='19.2'", Map.of());
        assertEquals(before.get("source_sha256"), mv.get("source_sha256"));
        long objs = db.rows("SELECT 1 FROM attack_objects WHERE domain='enterprise-attack' AND version='19.2'").size();
        long rels = db.rows("SELECT 1 FROM attack_relations WHERE domain='enterprise-attack' AND version='19.2'").size();
        assertEquals(objs, ((Number) ((Map<String, Object>) ((Map<String, Object>) manifest.get("tables")).get("attack_objects")).get("rows")).longValue());

        // 이 서버에서 지우고 패키지로 다시 가져오면 원본 sha256·건수·행이 그대로다 (다른 서버로 옮긴 것과 같다)
        assertEquals(200, call("DELETE", "/attack/versions/enterprise-attack/19.2", admin, null).status());
        assertEquals(403, uploadPackage("/attack/versions/import-package", viewer, ex.body(), "p.zip").status());
        Res im = uploadPackage("/attack/versions/import-package", admin, ex.body(), "attack_enterprise-attack_19.2.zip");
        assertEquals(200, im.status(), String.valueOf(im.body()));
        assertEquals("imported", im.map().get("status"));
        assertEquals("19.2", im.map().get("version"));
        assertEquals(false, im.map().get("is_active"));
        Map<String, Object> after = db.row("SELECT source_sha256, source_file, counts, imported_by FROM attack_versions "
                + "WHERE domain='enterprise-attack' AND version='19.2'", Map.of());
        assertEquals(before.get("source_sha256"), after.get("source_sha256"));
        assertEquals(before.get("source_file"), after.get("source_file"));
        assertEquals(Json.load(String.valueOf(before.get("counts"))), Json.load(String.valueOf(after.get("counts"))));
        assertEquals("admin", after.get("imported_by"));
        assertEquals(objs, db.rows("SELECT 1 FROM attack_objects WHERE domain='enterprise-attack' AND version='19.2'").size());
        assertEquals(rels, db.rows("SELECT 1 FROM attack_relations WHERE domain='enterprise-attack' AND version='19.2'").size());
        assertEquals(dataFiles(ex.body()), dataFiles(download("/attack/versions/enterprise-attack/19.2/export", admin).body()));
        Res t = call("GET", "/attack/techniques/T1190?domain=enterprise-attack&version=19.2", viewer, null);
        assertEquals(200, t.status(), String.valueOf(t.body()));
        assertFalse(((List<Object>) t.map().get("mitigations")).isEmpty());

        // 같은 패키지·같은 원본 번들은 다시 넣지 않는다
        assertEquals("already_imported", uploadPackage("/attack/versions/import-package", admin, ex.body(), "p.zip").map().get("status"));
        byte[] mini = Files.readAllBytes(ItSupport.ATTACK_FIXTURES.resolve("enterprise-attack-mini-19.2.json"));
        assertEquals("already_imported", upload(admin, mini, "enterprise-attack-mini-19.2.json").map().get("status"));

        // 손상·변조·다른 종류·zip 아님은 거부 (아무것도 넣지 않는다)
        Map<String, byte[]> bad = new java.util.LinkedHashMap<>(files);
        bad.put("attack_relations.jsonl", (new String(files.get("attack_relations.jsonl"), StandardCharsets.UTF_8) + "{}\n")
                .getBytes(StandardCharsets.UTF_8));
        Res tampered = uploadPackage("/attack/versions/import-package", admin, rezip(bad), "p.zip");
        assertEquals(400, tampered.status());
        assertTrue(String.valueOf(tampered.body()).contains("sha256"), String.valueOf(tampered.body()));
        Map<String, byte[]> extra = new java.util.LinkedHashMap<>(files);
        extra.put("evil.py", new byte[]{1});
        assertEquals(400, uploadPackage("/attack/versions/import-package", admin, rezip(extra), "p.zip").status());
        byte[] d3 = download("/d3fend/versions/1.6.0/export", admin).body();
        assertEquals(400, uploadPackage("/attack/versions/import-package", admin, d3, "d.zip").status());
        assertEquals(400, uploadPackage("/attack/versions/import-package", admin, mini, "x.zip").status());
        assertEquals(2, db.rows("SELECT 1 FROM attack_versions WHERE domain='enterprise-attack'").size());
        assertEquals(Map.of("enterprise-attack", "20.1"), call("GET", "/attack/versions", viewer, null).map().get("active"));
        assertFalse(db.rows("SELECT 1 FROM audit_log WHERE action='attack.export'").isEmpty());
    }

    @Test
    void d3fendExportPackageRoundTrip() throws Exception {
        String admin = login("admin", "admin123");
        String viewer = login("viewer", "viewer123");
        assertEquals(403, download("/d3fend/versions/1.5.0/export", viewer).status());
        Bin ex = download("/d3fend/versions/1.5.0/export", admin);
        assertEquals(200, ex.status(), new String(ex.body(), StandardCharsets.UTF_8));
        assertTrue(ex.disposition().contains("d3fend_1.5.0.zip"), ex.disposition());
        assertEquals(Set.of("manifest.json", "d3fend_tactics.jsonl", "d3fend_techniques.jsonl", "d3fend_attack_map.jsonl",
                "d3fend_mitigation_map.jsonl"), unzip(ex.body()).keySet());
        Map<String, Object> before = db.row("SELECT source_sha256, source_files, counts FROM d3fend_versions WHERE version='1.5.0'", Map.of());
        Map<String, Long> n = new java.util.TreeMap<>();
        for (String tb : List.of("d3fend_tactics", "d3fend_techniques", "d3fend_attack_map", "d3fend_mitigation_map")) {
            n.put(tb, (long) db.rows("SELECT 1 FROM " + tb + " WHERE version='1.5.0'").size());
        }

        assertEquals(200, call("DELETE", "/d3fend/versions/1.5.0", admin, null).status());
        Res im = uploadPackage("/d3fend/versions/import-package", admin, ex.body(), "d3fend_1.5.0.zip");
        assertEquals(200, im.status(), String.valueOf(im.body()));
        assertEquals("imported", im.map().get("status"));
        assertEquals(false, im.map().get("is_active"));
        Map<String, Object> after = db.row("SELECT source_sha256, source_files, counts FROM d3fend_versions WHERE version='1.5.0'", Map.of());
        assertEquals(before.get("source_sha256"), after.get("source_sha256"));
        assertEquals(Json.load(String.valueOf(before.get("source_files"))), Json.load(String.valueOf(after.get("source_files"))));
        for (Map.Entry<String, Long> e : n.entrySet()) {
            assertEquals(e.getValue(), (long) db.rows("SELECT 1 FROM " + e.getKey() + " WHERE version='1.5.0'").size(), e.getKey());
        }
        assertEquals(dataFiles(ex.body()), dataFiles(download("/d3fend/versions/1.5.0/export", admin).body()));
        Res t = call("GET", "/d3fend/techniques/D3-PT?version=1.5.0", viewer, null);
        assertEquals(200, t.status(), String.valueOf(t.body()));
        assertEquals("Process Termination", t.map().get("name"));

        assertEquals("already_imported", uploadPackage("/d3fend/versions/import-package", admin, ex.body(), "p.zip").map().get("status"));
        byte[] ont = Files.readAllBytes(ItSupport.D3FEND_FIXTURES.resolve("1.5.0/d3fend.json"));
        byte[] map = Files.readAllBytes(ItSupport.D3FEND_FIXTURES.resolve("1.5.0/d3fend-full-mappings.csv"));
        assertEquals("already_imported", uploadD3fend(admin, ont, map).map().get("status"));
        byte[] atk = download("/attack/versions/enterprise-attack/20.1/export", admin).body();
        assertEquals(400, uploadPackage("/d3fend/versions/import-package", admin, atk, "a.zip").status());
        assertEquals(2, db.rows("SELECT 1 FROM d3fend_versions").size());
        assertEquals("1.6.0", call("GET", "/d3fend/versions", viewer, null).map().get("active"));
    }

    // ------------------------------------------------------------------ 시나리오 그룹 (V6)
    @Test
    @SuppressWarnings("unchecked")
    void scenarioGroupsAssignRenameDelete() throws Exception {
        String author = login("author", "author123");
        String viewer = login("viewer", "viewer123");
        db.txRun(() -> db.execute("DELETE FROM scenario_groups WHERE name LIKE 'IT 그룹%'", Map.of()));
        assertEquals(403, call("POST", "/scenario-groups", viewer, Map.of("name", "IT 그룹 A")).status());
        Res c = call("POST", "/scenario-groups", author, Map.of("name", "IT 그룹 A"));
        assertEquals(201, c.status(), String.valueOf(c.body()));
        long gid = ((Number) c.map().get("group_id")).longValue();
        assertTrue(String.valueOf(c.map().get("grp_cd")).matches("SG\\d{3,}"), "자동 그룹 코드: " + c.body());
        assertEquals(400, call("POST", "/scenario-groups", author, Map.of("name", "IT 그룹 X", "grp_cd", "잘못된 코드")).status());
        assertEquals(409, call("POST", "/scenario-groups", author, Map.of("name", "IT 그룹 A")).status());
        assertEquals(400, call("POST", "/scenario-groups", author, Map.of("name", " ")).status());

        // 버전은 그대로, 목록에 group_id
        Map<String, Object> sc0 = (Map<String, Object>) call("GET", "/scenarios/SC_SMB_WORM", author, null).map().get("scenario");
        int before = ((Number) sc0.get("version")).intValue();
        Res a = call("PUT", "/scenario-groups/assign", author, Map.of("group_id", gid, "scenario_ids", List.of("SC_SMB_WORM")));
        assertEquals(200, a.status(), String.valueOf(a.body()));
        List<Map<String, Object>> list = (List<Map<String, Object>>) call("GET", "/scenarios", viewer, null).body();
        Map<String, Object> smb = list.stream().filter(s -> "SC_SMB_WORM".equals(s.get("scenario_id"))).findFirst().orElseThrow();
        assertEquals(gid, ((Number) smb.get("group_id")).longValue());
        assertEquals(before, ((Number) smb.get("version")).intValue());
        Res gl = call("GET", "/scenario-groups", viewer, null);
        Map<String, Object> g = ((List<Map<String, Object>>) gl.map().get("groups")).stream()
                .filter(x -> ((Number) x.get("group_id")).longValue() == gid).findFirst().orElseThrow();
        assertEquals(1, ((Number) g.get("scenario_count")).intValue());
        assertEquals(404, call("PUT", "/scenario-groups/assign", author,
                Map.of("group_id", gid, "scenario_ids", List.of("SC_NOT_THERE"))).status());

        Res rn = call("PUT", "/scenario-groups/" + gid, author, Map.of("name", "IT 그룹 B", "grp_cd", "IT_GRP_B"));
        assertEquals("IT 그룹 B", rn.map().get("name"));
        assertEquals("IT_GRP_B", rn.map().get("grp_cd"));
        // 그룹을 지우면 미분류가 된다
        assertEquals(200, call("DELETE", "/scenario-groups/" + gid, author, null).status());
        list = (List<Map<String, Object>>) call("GET", "/scenarios", viewer, null).body();
        smb = list.stream().filter(s -> "SC_SMB_WORM".equals(s.get("scenario_id"))).findFirst().orElseThrow();
        assertEquals(null, smb.get("group_id"));
        assertEquals(404, call("DELETE", "/scenario-groups/" + gid, author, null).status());
    }
}
