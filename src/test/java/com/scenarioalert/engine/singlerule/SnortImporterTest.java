package com.scenarioalert.engine.singlerule;

import com.scenarioalert.engine.singlerule.SnortImporter.Item;
import com.scenarioalert.engine.singlerule.SnortImporter.Options;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Snort 룰 → 단일룰 정의 변환. 변환 결과는 단일룰 검증기와 컴파일러를 그대로 통과해야 한다. IP 는 문서용 대역만 쓴다. */
class SnortImporterTest {
    static final Options DEFAULT = new Options(null, null, null, List.of("false_positive_hosts"));

    static Item one(String rule) {
        return one(rule, DEFAULT);
    }

    static Item one(String rule, Options opt) {
        List<Item> items = SnortImporter.convert(rule, opt);
        assertEquals(1, items.size());
        return items.get(0);
    }

    /** 검증기 통과 + 실시간 SQL 로 컴파일된다 */
    static void assertValid(Item it) {
        assertNotNull(it.definition(), () -> "건너뜀: " + it.skipped());
        RuleValidator.Result r = RuleValidator.validate(it.definition(), RuleCompilerTest.FAKE::containsKey);
        assertTrue(r.validation().ok(), () -> "검증 실패: " + r.validation().errorMaps() + " / " + it.definition());
        RuleCompiler.compileRealtime(r.parsed(), RuleCompilerTest.LOADER);
    }

    @SuppressWarnings("unchecked")
    static List<Object> conds(Item it) {
        return (List<Object>) ((Map<String, Object>) it.definition().get("filter")).get("all");
    }

    static Map<String, Object> c(String field, String op, Object value) {
        return Map.of("field", field, "op", op, "value", value);
    }

    @Test
    void basicContentRuleBecomesSignatureRule() {
        Item it = one("alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:\"SMB IPC$ share access\"; flow:to_server,established; "
                + "content:\"IPC$\"; nocase; classtype:attempted-recon; sid:1000001; rev:2;)");
        assertValid(it);
        Map<String, Object> d = it.definition();
        assertEquals("SR_SNORT_1000001", d.get("id"));
        assertEquals("SMB IPC$ share access", d.get("name"));
        assertEquals("signature", d.get("type"));
        assertEquals(1, d.get("min_count"));
        assertEquals("medium", d.get("severity"));
        assertEquals(List.of("IDS", "IPS", "TMS"), d.get("data_tp"));
        assertEquals(List.of("false_positive_hosts"), d.get("exclude_lists"));
        assertEquals(Map.of("type", "host", "field", "src_ip"), d.get("entity"));
        assertEquals(List.of(
                c("protocol", "eq", "tcp"),
                Map.of("all", List.of(c("src_internal", "eq", false), c("dst_internal", "eq", true), c("dst_port", "eq", 445))),
                c("payload", "contains", "IPC$")), conds(it));
        assertTrue(String.valueOf(d.get("description")).contains("sid 1000001, rev 2, classtype attempted-recon"));
        assertTrue(it.notes().stream().anyMatch(n -> n.contains("flow")), it.notes()::toString);
    }

    @Test
    void caseSensitiveAndHexContentBecomeRegex() {
        Item it = one("alert tcp any any -> any any (msg:\"hex\"; content:\"MZ|90 00|a.b\"; sid:7;)");
        assertValid(it);
        assertEquals(List.of(c("protocol", "eq", "tcp"), c("payload", "regex", "MZ\\x90\\x00a\\.b")), conds(it));
    }

    @Test
    void negatedContentAndPcre() {
        Item it = one("alert tcp any any -> any 80 (msg:\"x\"; content:!\"healthcheck\"; nocase; "
                + "pcre:\"/\\/admin\\/[a-z]+\\.php/i\"; sid:8;)");
        assertValid(it);
        List<Object> cs = conds(it);
        assertEquals(Map.of("not", c("payload", "contains", "healthcheck")), cs.get(2));
        assertEquals(c("payload", "regex", "(?i)/admin/[a-z]+\\.php"), cs.get(3));
    }

    @Test
    void thresholdBecomesCountRule() {
        Item it = one("alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:\"SSH brute force\"; flags:S; "
                + "threshold: type both, track by_dst, count 30, seconds 90; priority:1; sid:9;)");
        assertValid(it);
        Map<String, Object> d = it.definition();
        assertEquals("count", d.get("type"));
        assertEquals(Map.of("func", "count"), d.get("aggregate"));
        assertEquals(30, d.get("threshold"));
        assertEquals("2m", d.get("window"));
        assertEquals(Map.of("type", "host", "field", "dst_ip"), d.get("entity"));
        assertEquals("high", d.get("severity"));
        assertTrue(it.notes().stream().anyMatch(n -> n.contains("seconds 90")), it.notes()::toString);
    }

    @Test
    void detectionFilterAlsoCounts() {
        Item it = one("alert tcp any any -> any 25 (msg:\"smtp\"; detection_filter:track by_src, count 5, seconds 60; sid:10;)");
        assertValid(it);
        assertEquals("count", it.definition().get("type"));
        assertEquals("1m", it.definition().get("window"));
        assertEquals(5, it.definition().get("threshold"));
    }

    @Test
    void addressListsNegationCidrAndPortRanges() {
        Item it = one("alert udp [192.0.2.0/24,!192.0.2.5] any -> 198.51.100.7 [1024:,!3389] (msg:\"x\"; sid:11;)");
        assertValid(it);
        Object header = conds(it).get(1);
        assertEquals(Map.of("all", List.of(
                Map.of("all", List.of(c("src_ip", "cidr", "192.0.2.0/24"), Map.of("not", c("src_ip", "eq", "192.0.2.5")))),
                c("dst_ip", "eq", "198.51.100.7"),
                Map.of("all", List.of(c("dst_port", "gte", 1024), Map.of("not", c("dst_port", "eq", 3389)))))), header);
    }

    @Test
    void portListUsesIn() {
        Item it = one("alert tcp any any -> any [6881,6969] (msg:\"p2p\"; sid:12;)");
        assertValid(it);
        assertEquals(c("dst_port", "in", List.of(6881, 6969)), conds(it).get(1));
    }

    @Test
    void bidirectionalHeaderMatchesBothWays() {
        Item it = one("alert tcp $HOME_NET any <> 203.0.113.9 any (msg:\"x\"; sid:13;)");
        assertValid(it);
        assertEquals(Map.of("any", List.of(
                Map.of("all", List.of(c("src_internal", "eq", true), c("dst_ip", "eq", "203.0.113.9"))),
                Map.of("all", List.of(c("dst_internal", "eq", true), c("src_ip", "eq", "203.0.113.9"))))), conds(it).get(1));
    }

    @Test
    void httpUriMovesToWafWeb() {
        // Snort2: content 뒤 http_uri 수식어
        Item s2 = one("alert tcp any any -> any 80 (msg:\"uri\"; content:\"/wp-login.php\"; http_uri; sid:14;)");
        assertValid(s2);
        assertEquals(List.of("WAF", "WEB"), s2.definition().get("data_tp"));
        // WAF·WEB 로그에는 포트가 없어 dst_port 조건은 빠진다
        assertEquals(List.of(c("protocol", "eq", "tcp"), c("uri", "regex", "/wp-login\\.php")), conds(s2));
        assertTrue(s2.notes().stream().anyMatch(n -> n.contains("포트 조건을 뺐습니다")), s2.notes()::toString);
        // Snort3: sticky buffer 가 content 앞에
        Item s3 = one("alert http (msg:\"uri3\"; http_uri; content:\"/cgi-bin/\"; nocase; http_method; content:\"POST\"; sid:15;)");
        assertValid(s3);
        assertEquals(List.of(c("uri", "contains", "/cgi-bin/"), c("url_method", "regex", "POST")), conds(s3));
    }

    @Test
    void msgModeMatchesSignatureName() {
        Item it = one("alert tcp any any -> any 445 (msg:\"ET EXPLOIT Possible ETERNALBLUE\"; content:\"|ff|SMB\"; sid:2024218;)",
                new Options(List.of("IDS"), "msg", "SR_ET_", List.of()));
        assertValid(it);
        assertEquals("SR_ET_2024218", it.definition().get("id"));
        assertEquals(List.of(c("signature_name", "eq", "ET EXPLOIT Possible ETERNALBLUE")), conds(it));
    }

    @Test
    void koreanContentStaysReadable() {
        Item it = one("alert tcp any any -> any any (msg:\"한글\"; content:\"관리자 로그인\"; nocase; sid:16;)");
        assertValid(it);
        assertEquals(c("payload", "contains", "관리자 로그인"), conds(it).get(1));
    }

    @Test
    void multipleRulesCommentsContinuationsAndDuplicates() {
        String text = """
                # 주석은 건너뜀
                alert tcp any any -> any 80 (msg:"a"; \\
                  content:"x"; sid:100;)

                pass tcp any any -> any any (msg:"skip"; sid:101;)
                alert tcp any any -> any 81 (msg:"dup"; sid:100;)
                not a rule
                alert tcp any any -> any 82 (msg:"nosid";)
                """;
        List<Item> items = SnortImporter.convert(text, DEFAULT);
        assertEquals(5, items.size());
        assertEquals(2, items.get(0).line());
        assertEquals("SR_SNORT_100", items.get(0).definition().get("id"));
        assertNull(items.get(1).definition());
        assertTrue(items.get(1).skipped().contains("pass"));
        assertEquals("SR_SNORT_100_2", items.get(2).definition().get("id"));
        assertNull(items.get(3).definition());
        assertEquals("SR_SNORT_L8", items.get(4).definition().get("id"));
        items.stream().filter(i -> i.definition() != null).forEach(SnortImporterTest::assertValid);
    }

    @Test
    void escapedQuotesAndSemicolonsInsideOptions() {
        Item it = one("alert tcp any any -> any any (msg:\"a \\\"quoted\\\" msg; with semicolon\"; content:\"a\\;b\"; nocase; sid:17;)");
        assertValid(it);
        assertEquals("a \"quoted\" msg; with semicolon", it.definition().get("name"));
        assertEquals(c("payload", "contains", "a;b"), conds(it).get(1));
    }

    @Test
    void unsupportedOptionsAreListedInNotes() {
        Item it = one("alert tcp any any -> any any (msg:\"x\"; content:\"abc\"; offset:4; depth:10; byte_test:4,>,1000,0; "
                + "flowbits:set,foo; sid:18;)");
        assertValid(it);
        String notes = String.join(" | ", it.notes());
        for (String k : List.of("offset", "depth", "byte_test", "flowbits")) {
            assertTrue(notes.contains(k), notes);
        }
    }

    @Test
    void brokenRulesAreSkippedWithReason() {
        assertFalse(one("alert tcp any any -> any any msg:x").skipped().isEmpty());
        assertTrue(one("alert tcp any any => any any (msg:\"x\"; sid:1;)").skipped().contains("방향"));
        assertTrue(one("alert tcp any any -> any any (msg:\"x; sid:1;)").skipped().contains("따옴표"));
    }
}
