package com.scenarioalert.engine.it;

import com.scenarioalert.engine.InitService;
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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

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
}
