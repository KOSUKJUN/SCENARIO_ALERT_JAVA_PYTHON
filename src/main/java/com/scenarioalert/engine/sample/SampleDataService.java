package com.scenarioalert.engine.sample;

import com.scenarioalert.engine.auth.AuthService;
import com.scenarioalert.engine.ch.ClickHouse;
import com.scenarioalert.engine.ch.ClickHouse.Purpose;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 테스트용 샘플 데이터 (개발·테스트 환경 전용. 운영 ClickHouse 에서 실행하지 않는다).
 * <ul>
 * <li>기준 데이터: 기관 3곳(두 기관은 내부 대역이 겹침), 자산·태그, 리스트, 시그니처 분류 매핑, 사용자</li>
 * <li>이벤트: codlog.log_integrated_success_all 에 정상 트래픽 + 시나리오별 공격 패턴 + 반례</li>
 * <li>실제 기관명·IP 는 쓰지 않는다. 문서용 대역(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)과 사설 대역만 쓴다.</li>
 * </ul>
 */
@Component
public class SampleDataService {
    public static final List<String> COLUMNS = List.of("event_id", "mgr_time", "event_time", "inst_id", "data_tp", "log",
            "product", "s_info", "d_info", "s_port", "d_port", "protocol", "action", "mstatus", "direction", "method",
            "attack", "risk", "count", "uri", "url_method", "payload");

    // ---------------------------------------------------------------- 기준 데이터
    record Org(String id, String name, List<String> cidrs) {
    }

    record Asset(String org, String ip, String purpose, String os, boolean sensitive, List<String> tags) {
    }

    record ListDef(String id, String kind, String desc, List<String[]> items) {
    }

    static final List<Org> ORGS = List.of(
            new Org("ORG001", "테스트기관A (병원)", List.of("10.10.0.0/16", "172.16.10.0/24")),
            new Org("ORG002", "테스트기관B (대학)", List.of("10.10.0.0/16", "10.20.0.0/16")),  // ORG001 과 대역 겹침
            new Org("ORG003", "테스트기관C (공단)", List.of("192.168.50.0/24")));

    static final List<Asset> ASSETS = List.of(
            new Asset("ORG001", "10.10.1.50", "영상 검사 장비", "Windows 7", true, List.of("legacy_os", "medical_device")),
            new Asset("ORG001", "10.10.1.60", "로비 무인 안내기", "Windows 7 Embedded", false, List.of("kiosk", "legacy_os")),
            new Asset("ORG001", "10.10.2.10", "메일 서버", "Rocky Linux 9", true, List.of("mailserver")),
            new Asset("ORG001", "10.10.3.20", "홈페이지 웹서버", "Ubuntu 22.04", false, List.of("webserver")),
            new Asset("ORG001", "10.10.4.5", "부서 파일서버", "Windows Server 2019", true, List.of("fileserver")),
            new Asset("ORG001", "10.10.1.99", "백업 서버", "Windows Server 2022", true, List.of("backup")),
            new Asset("ORG002", "10.10.1.50", "연구실 PC", "Windows 11", false, List.of()),  // 같은 IP, 다른 기관
            new Asset("ORG002", "10.20.3.20", "학과 웹서버", "Ubuntu 20.04", false, List.of("webserver")),
            new Asset("ORG003", "192.168.50.10", "민원 웹서버", "Rocky Linux 8", true, List.of("webserver")));

    private static String[] it(String v) {
        return new String[]{v, null};
    }

    private static String[] it(String v, String m) {
        return new String[]{v, m};
    }

    static final List<ListDef> LISTS = List.of(
            new ListDef("smb_allowed_sources", "ip", "SMB 다수 접근 예외 (백업·배포 서버)", List.<String[]>of(it("10.10.1.99"))),
            new ListDef("threat_ip", "ip", "유해 IP (테스트용 문서 대역)",
                    List.<String[]>of(it("203.0.113.66"), it("203.0.113.67"), it("198.51.100.200"))),
            new ListDef("threat_domains", "domain", "유해 도메인", List.<String[]>of(it("bad-c2.example"), it("update-check.invalid"))),
            new ListDef("wannacry_killswitch_domains", "domain", "WannaCry 킬스위치 도메인",
                    List.<String[]>of(it("iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"), it("ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com"))),
            new ListDef("coinmining_pools", "domain", "채굴 풀 도메인", List.<String[]>of(it("pool.minexmr.example"), it("xmr-pool.invalid"))),
            new ListDef("false_positive_hosts", "ip", "오탐 처리된 대상 (경보 화면에서 추가)", List.<String[]>of()),
            new ListDef("signature_map", "signature_map", "시그니처 분류 매핑 (데이터유형|시그니처명 → 분류)", List.of(
                    it("*|ET EXPLOIT Possible ETERNALBLUE MS17-010", "ransomware_wannacry"),
                    it("*|WannaCry Ransomware SMB Propagation", "ransomware_wannacry"),
                    it("*|SMB ADMIN$ Share Access", "smb_admin_share"),
                    it("*|SMB C$ Share Access", "smb_admin_share"),
                    it("*|SSH Brute Force Attempt", "bruteforce"),
                    it("*|SMTP AUTH Brute Force", "bruteforce"),
                    it("*|SMTP AUTH Login Success", "auth_success"),
                    it("*|AnyDesk Remote Access", "remote_tool"),
                    it("*|TeamViewer Remote Session", "remote_tool"),
                    it("*|Trojan.Generic C2 Beacon", "malware"),
                    it("*|Cobalt Strike Beacon", "malware"),
                    it("*|Stratum Mining Protocol", "coinminer"),
                    it("*|XMRig Miner Login", "coinminer"),
                    // 사고 사례(docs/cases.md)에서 가져온 장비 탐지명 → 분류. 탐지명은 코드가 아니라 이 리스트에만 둔다.
                    it("*|HISC_WannaCry 랜섬웨어(PAT)", "ransomware_wannacry"),
                    it("*|워너크라이 킬스위치 접속 시도 탐지", "ransomware_wannacry"),
                    it("*|SMB IPC$ Share Unicode Access-1", "smb_admin_share"),
                    it("*|SMB IPC$ Share Access", "smb_admin_share"),
                    it("*|Utorrent", "p2p"),
                    it("*|BitTorrent DHT Ping", "p2p"),
                    it("*|HISC_원격제어 프로그램 탐지", "remote_tool"),
                    it("*|암호화폐 채굴 악성코드 감염 탐지", "coinminer"),
                    it("*|SSH Login Successful", "auth_success"))));

    static final String[][] USERS = {{"admin", "admin123", "admin"}, {"author", "author123", "author"},
            {"analyst", "analyst123", "analyst"}, {"viewer", "viewer123", "viewer"}};

    private final Db db;
    private final ClickHouse ch;

    public SampleDataService(Db db, ClickHouse ch) {
        this.db = db;
        this.ch = ch;
    }

    public void seedReference() {
        db.txRun(() -> {
            for (String[] u : USERS) {
                if (db.row("SELECT 1 AS x FROM users WHERE username=:u", p("u", u[0])) == null) {
                    db.execute("INSERT INTO users (username, password_hash, role) VALUES (:u, :p, :r)",
                            p("u", u[0], "p", AuthService.hashPassword(u[1]), "r", u[2]));
                }
            }
            for (Org o : ORGS) {
                db.execute("INSERT INTO orgs (org_id, name) VALUES (:o, :n) ON DUPLICATE KEY UPDATE name=VALUES(name)",
                        p("o", o.id(), "n", o.name()));
                for (String c : o.cidrs()) {
                    db.execute("INSERT IGNORE INTO org_cidrs (org_id, cidr) VALUES (:o, :c)", p("o", o.id(), "c", c));
                }
            }
            for (Asset a : ASSETS) {
                asset(a.org(), a.ip(), a.purpose(), a.os(), a.sensitive(), a.tags(), "import");
            }
            for (ListDef l : LISTS) {
                db.execute("INSERT INTO lists (list_id, kind, scope_org_id, description) VALUES (:l, :k, NULL, :d) "
                        + "ON DUPLICATE KEY UPDATE description=VALUES(description)", p("l", l.id(), "k", l.kind(), "d", l.desc()));
                for (String[] i : l.items()) {
                    db.execute("INSERT IGNORE INTO list_items (list_id, value, mapped_value) VALUES (:l, :v, :m)",
                            p("l", l.id(), "v", i[0], "m", i[1]));
                }
            }
        });
    }

    private void asset(String org, String ip, String purpose, String os, boolean sens, List<String> tags, String source) {
        db.execute("INSERT INTO assets (org_id, ip, purpose, os, holds_sensitive, source) VALUES (:o, :ip, :p, :os, :h, :s) "
                        + "ON DUPLICATE KEY UPDATE purpose=VALUES(purpose), os=VALUES(os), holds_sensitive=VALUES(holds_sensitive)",
                p("o", org, "ip", ip, "p", purpose, "os", os, "h", sens, "s", source));
        for (String t : tags) {
            db.execute("INSERT IGNORE INTO asset_tags (org_id, ip, tag) VALUES (:o, :ip, :t)", p("o", org, "ip", ip, "t", t));
        }
    }

    // ---------------------------------------------------------------- 이벤트 생성
    static final Map<String, String> PRODUCTS = Map.ofEntries(Map.entry("FIREWALL", "TestFW"), Map.entry("IPS", "TestIPS"),
            Map.entry("IDS", "TestIDS"), Map.entry("TMS", "TestTMS"), Map.entry("UTM", "TestUTM"), Map.entry("WAF", "TestWAF"),
            Map.entry("DDos", "TestDDoS"), Map.entry("DPX", "TestDPX"), Map.entry("APT", "TestAPT"), Map.entry("VPN", "TestVPN"),
            Map.entry("WEB", "TestWEB"), Map.entry("WFILTER", "TestWF"));
    static final Set<String> HAS_DPORT = Set.of("DDos", "FIREWALL", "IPS", "TMS");
    static final Set<String> HAS_SPORT = Set.of("DDos", "FIREWALL", "IPS");
    static final Set<String> NO_COUNT = Set.of("TMS", "VPN", "WAF");
    static final Set<String> NO_ATTACK = Set.of("APT", "DPX", "IDS", "VPN");
    static final Set<String> NO_METHOD = Set.of("APT", "VPN");
    static final Set<String> NO_DIRECTION = Set.of("APT", "VPN", "WEB");
    static final Set<String> HAS_PAYLOAD = Set.of("DDos", "IDS", "IPS", "TMS", "UTM", "WAF");

    /** 이벤트 한 행의 선택 항목. */
    static final class Ev {
        Integer dport;
        Integer sport;
        String direction = "";
        String action = "allow";
        String method = "";
        String attack = "";
        String payload = "";
        Integer count;
        String uri = "";
        String urlMethod = "";
        String protocol = "tcp";
        String risk = "low";

        Ev dport(Integer v) { dport = v; return this; }
        Ev dir(String v) { direction = v; return this; }
        Ev action(String v) { action = v; return this; }
        Ev method(String v) { method = v; return this; }
        Ev attack(String v) { attack = v; return this; }
        Ev payload(String v) { payload = v; return this; }
        Ev count(Integer v) { count = v; return this; }
        Ev uri(String v) { uri = v; return this; }
        Ev urlMethod(String v) { urlMethod = v; return this; }
        Ev risk(String v) { risk = v; return this; }
    }

    private static Ev o() {
        return new Ev();
    }

    private static String v6(String ip) {
        return ip == null ? null : (ip.contains(":") ? ip : "::ffff:" + ip);
    }

    /** 유형별 채움 규칙(설계안 3장 표)을 지켜 이벤트 한 행을 만든다. */
    static Map<String, Object> ev(String org, String dtp, LocalDateTime t, String src, String dst, Ev e, Random r) {
        LocalDateTime mgr = t.plus(300 + r.nextInt(2201), ChronoUnit.MILLIS);
        if (dtp.equals("WFILTER")) {
            src = null;
            dst = null;
        }
        boolean aptLike = dtp.equals("APT") || dtp.equals("WFILTER");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("event_id", UUID.randomUUID().toString());
        m.put("mgr_time", Kst.fmt(mgr));
        m.put("event_time", dtp.equals("APT") ? null : Kst.fmt(t));
        m.put("inst_id", org);
        m.put("data_tp", dtp);
        m.put("log", dtp.toLowerCase());
        m.put("product", PRODUCTS.get(dtp));
        m.put("s_info", v6(src));
        m.put("d_info", v6(dst));
        m.put("s_port", HAS_SPORT.contains(dtp) ? (e.sport != null ? e.sport : 30000 + r.nextInt(35001)) : null);
        m.put("d_port", HAS_DPORT.contains(dtp) ? e.dport : null);
        m.put("protocol", e.protocol);
        m.put("action", aptLike ? "" : e.action);
        m.put("mstatus", aptLike ? e.action : "");
        m.put("direction", NO_DIRECTION.contains(dtp) ? "" : e.direction);
        m.put("method", NO_METHOD.contains(dtp) ? "" : e.method);
        m.put("attack", NO_ATTACK.contains(dtp) ? "" : e.attack);
        m.put("risk", e.risk);
        m.put("count", NO_COUNT.contains(dtp) ? null : (e.count != null ? e.count : 1));
        m.put("uri", e.uri);
        m.put("url_method", e.urlMethod);
        m.put("payload", HAS_PAYLOAD.contains(dtp) ? e.payload : "");
        return m;
    }

    public int insertEvents(List<Map<String, Object>> rows) {
        for (int i = 0; i < rows.size(); i += 20000) {
            ch.insert("codlog.log_integrated_success_all", COLUMNS, rows.subList(i, Math.min(rows.size(), i + 20000)), Purpose.ADMIN);
        }
        return rows.size();
    }

    private static <T> T pick(Random r, List<T> xs) {
        return xs.get(r.nextInt(xs.size()));
    }

    private static List<String> sample(Random r, List<String> pool, int n) {
        List<String> copy = new ArrayList<>(pool);
        Collections.shuffle(copy, r);
        return copy.subList(0, n);
    }

    private static List<String> ext(Random r, int n) {
        List<String> pool = new ArrayList<>();
        for (int i = 1; i < 254; i++) {
            pool.add("198.51.100." + i);
        }
        return sample(r, pool, n);
    }

    private static List<String> extMixed(Random r, int n) {
        List<String> pool = new ArrayList<>();
        for (int i = 1; i < 200; i++) {
            if (i != 200) {
                pool.add("198.51.100." + i);
            }
        }
        for (int i = 1; i < 254; i++) {
            pool.add("192.0.2." + i);
        }
        return sample(r, pool, n);
    }

    // ---- 시나리오 패턴. 각 함수는 (기준 시각, 대상 IP, 기관, rng) → 이벤트 목록.
    static List<Map<String, Object>> smbOut(LocalDateTime t0, String host, String org, Random r, int n, boolean wannacry) {
        List<Map<String, Object>> out = new ArrayList<>();
        List<String> dsts = extMixed(r, n);
        for (int i = 0; i < dsts.size(); i++) {
            String dtp = pick(r, List.of("FIREWALL", "FIREWALL", "IPS", "TMS"));
            out.add(ev(org, dtp, t0.plusSeconds(i * 7L), host, dsts.get(i), o().dport(445).dir("outbound")
                    .action(pick(r, List.of("deny", "block", "allow"))).method("SMB Connection Attempt"), r));
        }
        if (wannacry) {
            out.add(ev(org, "IDS", t0.plusSeconds(n * 7L + 20), host, "203.0.113.10", o().dir("outbound").action("alert")
                    .method("ET EXPLOIT Possible ETERNALBLUE MS17-010").payload("SMB1 Trans2 SESSION_SETUP").risk("high"), r));
        }
        return out;
    }

    static List<Map<String, Object>> smbIn(LocalDateTime t0, String host, String org, Random r) {
        List<Map<String, Object>> out = new ArrayList<>();
        List<String> pool = new ArrayList<>();
        for (int i = 2; i < 250; i++) {
            pool.add("10.10.5." + i);
        }
        List<String> dsts = sample(r, pool, 12);
        for (int i = 0; i < dsts.size(); i++) {
            out.add(ev(org, "FIREWALL", t0.plusSeconds(i * 10L), host, dsts.get(i), o().dport(445).dir("internal"), r));
        }
        return out;
    }

    static List<Map<String, Object>> smbSig(LocalDateTime t0, String host, String org, Random r) {
        return List.of(ev(org, "IDS", t0, host, "10.10.4.30", o().dir("internal").action("alert")
                .method("SMB ADMIN$ Share Access").payload("\\\\10.10.4.30\\ADMIN$").risk("medium"), r));
    }

    static List<Map<String, Object>> remoteScan(LocalDateTime t0, String host, String org, Random r) {
        List<Map<String, Object>> out = new ArrayList<>();
        List<String> dsts = extMixed(r, 12);
        for (int i = 0; i < dsts.size(); i++) {
            out.add(ev(org, "FIREWALL", t0.plusSeconds(i * 9L), host, dsts.get(i),
                    o().dport(pick(r, List.of(3389, 3389, 22, 5900))).dir("outbound").action("deny"), r));
        }
        return out;
    }

    static List<Map<String, Object>> bruteforce(LocalDateTime t0, String server, String org, Random r) {
        List<Map<String, Object>> out = new ArrayList<>();
        List<String> attackers = ext(r, 3);
        for (int i = 0; i < 40; i++) {
            out.add(ev(org, pick(r, List.of("FIREWALL", "IPS")), t0.plusSeconds(i * 5L), pick(r, attackers), server,
                    o().dport(pick(r, List.of(25, 587))).dir("inbound").method("SMTP AUTH Brute Force").attack("Brute Force"), r));
        }
        return out;
    }

    static List<Map<String, Object>> authSuccess(LocalDateTime t0, String server, String org, Random r) {
        return List.of(ev(org, "IDS", t0, "198.51.100.23", server, o().dir("inbound").action("alert").method("SMTP Response")
                .payload("235 2.7.0 Authentication successful").risk("medium"), r));
    }

    static List<Map<String, Object>> remoteTool(LocalDateTime t0, String host, String org, Random r) {
        return List.of(ev(org, "FIREWALL", t0, host, "192.0.2.80", o().dport(6568).dir("outbound"), r),
                ev(org, "IDS", t0.plusSeconds(20), host, "192.0.2.80", o().dir("outbound").action("alert")
                        .method("AnyDesk Remote Access").risk("medium"), r));
    }

    static List<Map<String, Object>> tiContact(LocalDateTime t0, String host, String org, Random r) {
        return List.of(ev(org, "FIREWALL", t0, host, "203.0.113.66", o().dport(443).dir("outbound"), r));
    }

    static List<Map<String, Object>> coinminer(LocalDateTime t0, String host, String org, Random r, int spanMin) {
        List<Map<String, Object>> out = new ArrayList<>();
        int n = 12;
        for (int i = 0; i < n; i++) {
            out.add(ev(org, "IDS", t0.plusSeconds((long) i * spanMin * 60 / n), host, "198.51.100.150", o().dir("outbound")
                    .action("alert").method("Stratum Mining Protocol")
                    .payload("{\"method\":\"login\",\"params\":{\"agent\":\"XMRig/6.20\"}} pool.minexmr.example"), r));
        }
        return out;
    }

    static List<Map<String, Object>> wafBurst(LocalDateTime t0, String server, String org, Random r) {
        List<Map<String, Object>> out = new ArrayList<>();
        int n = 320;
        int spanSec = 45;
        for (int i = 0; i < n; i++) {
            out.add(ev(org, "WAF", t0.plus((long) i * spanSec * 1000 / n, ChronoUnit.MILLIS), "203.0.113.45", server,
                    o().dir("inbound").action("block").method("WAF Rule 942100")
                            .attack(pick(r, List.of("SQL Injection", "XSS", "Path Traversal")))
                            .uri(pick(r, List.of("/board/view.php?id=1' or '1'='1", "/search?q=<script>", "/../../etc/passwd")))
                            .urlMethod("GET").payload("GET /board/view.php"), r));
        }
        return out;
    }

    static List<Map<String, Object>> newOutbound(LocalDateTime t0, String server, String org, Random r) {
        return List.of(ev(org, "FIREWALL", t0, server, "198.51.100.77", o().dport(4444).dir("outbound"), r));
    }

    // ---- 사고 사례(docs/cases.md) 패턴
    /** 한 외부 출발지가 45초 안에 WAF 공격 n건. 1분 창 안에 들어가도록 t0 는 분 경계 직후여야 한다. */
    static List<Map<String, Object>> wafSrcBurst(LocalDateTime t0, String attacker, String server, String org, Random r, int n) {
        List<Map<String, Object>> out = new ArrayList<>();
        int spanSec = 45;
        for (int i = 0; i < n; i++) {
            out.add(ev(org, "WAF", t0.plus((long) i * spanSec * 1000 / n, ChronoUnit.MILLIS), attacker, server,
                    o().dir("inbound").action("block").method("WAF Rule 920350")
                            .attack(pick(r, List.of("Error Handling", "SQL Injection", "Scanner Detection")))
                            .uri(pick(r, List.of("/index.php?id=1'", "/.env", "/wp-login.php", "/cgi-bin/test")))
                            .urlMethod("GET").payload("GET /index.php"), r));
        }
        return out;
    }

    /** WannaCry 킬스위치 도메인 접속 (TMS, 페이로드에 도메인). */
    static List<Map<String, Object>> killswitch(LocalDateTime t0, String host, String org, Random r) {
        return List.of(ev(org, "TMS", t0, host, "203.0.113.80", o().dport(80).dir("outbound").action("alert")
                .method("워너크라이 킬스위치 접속 시도 탐지")
                .payload("GET / HTTP/1.1 Host: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com").risk("high"), r));
    }

    /** 내부 → 내부(파일서버) WannaCry 시그니처. */
    static List<Map<String, Object>> wannacryInternal(LocalDateTime t0, String host, String dst, String org, Random r) {
        return List.of(ev(org, "IDS", t0, host, dst, o().dir("internal").action("alert")
                .method("HISC_WannaCry 랜섬웨어(PAT)").payload("SMB1 Trans2 SESSION_SETUP").risk("high"), r));
    }

    /** 토렌트 포트 통신 n건 (+ P2P 시그니처 1건). */
    static List<Map<String, Object>> p2p(LocalDateTime t0, String host, String org, Random r, int n) {
        List<Map<String, Object>> out = new ArrayList<>();
        List<String> dsts = ext(r, 3);
        for (int i = 0; i < n - 1; i++) {
            out.add(ev(org, pick(r, List.of("FIREWALL", "IPS", "TMS")), t0.plusSeconds(i * 20L), host, pick(r, dsts),
                    o().dport(pick(r, List.of(6881, 6969))).dir("outbound").action(pick(r, List.of("allow", "deny"))), r));
        }
        out.add(ev(org, "IDS", t0.plusSeconds(n * 20L), host, dsts.get(0), o().dir("outbound").action("alert")
                .method("Utorrent").payload("BitTorrent protocol").risk("low"), r));
        return out;
    }

    /** 외부 출발지 srcs 개가 관리 포트(22)로 각 2회 접근. */
    static List<Map<String, Object>> adminPortMulti(LocalDateTime t0, String server, String org, Random r, int srcs) {
        List<Map<String, Object>> out = new ArrayList<>();
        List<String> attackers = ext(r, srcs);
        int i = 0;
        for (String a : attackers) {
            for (int k = 0; k < 2; k++) {
                out.add(ev(org, pick(r, List.of("FIREWALL", "IPS")), t0.plusSeconds(i++ * 8L), a, server,
                        o().dport(22).dir("inbound").action(pick(r, List.of("deny", "allow"))).method("SSH Connection"), r));
            }
        }
        return out;
    }

    static List<Map<String, Object>> sshSuccess(LocalDateTime t0, String server, String org, Random r) {
        return List.of(ev(org, "IDS", t0, "198.51.100.31", server, o().dir("inbound").action("alert")
                .method("SSH Login Successful").payload("Accepted password for root").risk("medium"), r));
    }

    static List<Map<String, Object>> smbIpcSig(LocalDateTime t0, String host, String org, Random r) {
        return List.of(ev(org, "IDS", t0, host, "10.10.4.31", o().dir("internal").action("alert")
                .method("SMB IPC$ Share Unicode Access-1").payload("\\\\10.10.4.31\\IPC$").risk("medium"), r));
    }

    record Scenario(String key, String title, String expect, String host, List<String> tags) {
    }

    static final List<Scenario> CATALOG = List.of(
            new Scenario("smb_worm_legacy", "SMB 웜 - 레거시 의료장비", "SC_SMB_WORM 긴급 (자산 조건)", "10.10.1.50",
                    List.of("legacy_os", "medical_device")),
            new Scenario("smb_worm_wannacry", "SMB 웜 - WannaCry 동반", "SC_SMB_WORM 긴급 (WannaCry 확인) + SR_WANNACRY_SIG 단독 경보",
                    "10.10.1.52", List.of()),
            new Scenario("smb_worm_plain", "SMB 웜 - 일반 PC", "SC_SMB_WORM 높음", "10.10.1.53", List.of()),
            new Scenario("smb_lateral", "SMB 내부 확산", "SC_SMB_LATERAL 높음", "10.10.1.70", List.of()),
            new Scenario("smb_fileserver", "파일서버 관리 공유 접근", "SC_SMB_LATERAL 낮음 (파일서버)", "10.10.4.5", List.of("fileserver")),
            new Scenario("remote_scan_kiosk", "무인 안내기의 외부 RDP 스캔", "SC_REMOTE_SCAN_OUT 긴급", "10.10.1.60",
                    List.of("kiosk", "legacy_os")),
            new Scenario("bruteforce_success", "메일 서버 대입 공격 후 인증 성공", "SC_BRUTEFORCE_SUCCESS 높음", "10.10.2.10",
                    List.of("mailserver")),
            new Scenario("remote_tool_malicious", "AnyDesk + 유해 IP 통신", "SC_REMOTE_TOOL_MALICIOUS 높음", "10.10.1.80", List.of()),
            new Scenario("coinminer", "코인 채굴 반복", "SC_COINMINER 중간 → 높음 상향", "10.10.1.90", List.of()),
            new Scenario("web_attack_success", "웹 공격 후 처음 보는 외부 접속", "SC_WEB_ATTACK_SUCCESS 긴급", "10.10.3.20",
                    List.of("webserver")),
            new Scenario("neg_below_threshold", "반례: 외부 445 목적지 19개 (임계치 바로 아래)", "경보 없음", "10.10.1.54", List.of()),
            new Scenario("neg_exception_list", "반례: 예외 리스트의 백업 서버", "경보 없음", "10.10.1.99", List.of("backup")),
            new Scenario("neg_out_of_window", "반례: 대입 공격 45분 뒤 인증 성공 (허용 30분 밖)", "SC_BRUTEFORCE_SUCCESS 없음",
                    "10.10.2.11", List.of("mailserver")),
            new Scenario("neg_ids_port", "반례: 포트 없는 IDS 의 SMB 트래픽", "경보 없음 (포트 룰은 IDS 미대상)", "10.10.1.55", List.of()),
            // ---- 사고 사례 기반 (docs/cases.md)
            new Scenario("waf_attacker", "[사례] WAF 공격 출발지 1,100건/분", "SC_WAF_ATTACKER 높음 (대상 = 공격자 IP 203.0.113.x)", "10.10.3.20",
                    List.of("webserver")),
            new Scenario("waf_attacker_burst", "[사례] WAF 공격 출발지 350건/분", "SC_WAF_ATTACKER 중간 (대상 = 공격자 IP 203.0.113.x)", "10.10.3.20",
                    List.of("webserver")),
            new Scenario("wannacry_device", "[사례] 의료장비의 WannaCry 킬스위치 접속", "SC_WANNACRY_HOST 높음 (자산) + SR_WANNACRY_SIG 단독 높음",
                    "10.10.6.30", List.of("legacy_os", "medical_device")),
            new Scenario("wannacry_spread", "[사례] 킬스위치 접속 + 외부 445 다수 접근", "SC_WANNACRY_HOST 긴급 + SC_SMB_WORM 긴급 + SR_WANNACRY_SIG 단독",
                    "10.10.6.31", List.of()),
            new Scenario("wannacry_fileserver", "[사례] 내부 → 파일서버 WannaCry 시그니처",
                    "출발지: SC_WANNACRY_HOST 중간 + 단독 높음 / 목적지 10.10.4.5(파일서버): SC_WANNACRY_HOST 높음", "10.10.6.32", List.of()),
            new Scenario("ti_contact_legacy", "[사례] 레거시 PC 의 유해 IP 통신", "SC_TI_CONTACT 중간", "10.10.7.11", List.of("legacy_os")),
            new Scenario("ti_contact_scan", "[사례] 유해 IP 통신 + 외부 원격포트 스캔", "SC_TI_CONTACT 높음 + SC_REMOTE_SCAN_OUT 높음", "10.10.7.10",
                    List.of()),
            new Scenario("p2p_usage", "[사례] 토렌트 이용", "SC_P2P_USAGE 낮음", "10.10.7.21", List.of()),
            new Scenario("p2p_malicious", "[사례] 토렌트 이용 + 유해 IP 통신", "SC_P2P_USAGE 높음 + SC_TI_CONTACT 낮음", "10.10.7.20", List.of()),
            new Scenario("exposed_admin_port", "[사례] 외부 다수 출발지의 SSH 접근", "SC_EXPOSED_ADMIN_PORT 중간", "10.10.8.11", List.of()),
            new Scenario("exposed_admin_port_success", "[사례] 외부 SSH 접근 + 로그인 성공", "SC_EXPOSED_ADMIN_PORT 긴급", "10.10.8.10",
                    List.of()),
            new Scenario("remote_tool_only", "[사례] AnyDesk 통신만 (악성 징후 없음)", "SC_REMOTE_TOOL_MALICIOUS 낮음", "10.10.1.86", List.of()),
            new Scenario("smb_ipc_kiosk", "[사례] 안내기의 SMB IPC$ 공유 접근", "SC_SMB_LATERAL 높음", "10.10.1.74", List.of("kiosk", "legacy_os")),
            new Scenario("neg_p2p_below", "반례: 토렌트 포트 3건 (임계치 5 미만)", "경보 없음", "10.10.7.22", List.of()),
            new Scenario("neg_admin_port_few", "반례: 외부 출발지 3개의 SSH 접근 (임계치 5 미만)", "경보 없음", "10.10.8.12", List.of()));

    public static List<Map<String, Object>> catalog() {
        return CATALOG.stream().map(s -> Json.obj("key", s.key(), "title", s.title(), "expect", s.expect(),
                "default_host", s.host())).toList();
    }

    private static Scenario byKey(String key) {
        return CATALOG.stream().filter(s -> s.key().equals(key)).findFirst()
                .orElseThrow(() -> new ApiException(400, "알 수 없는 시나리오: '" + key + "'"));
    }

    /** 공격 패턴 이벤트. live=true 면 시간 간격을 줄인다 (주입 직후 1~2분 안에 탐지되도록). */
    static List<Map<String, Object>> buildScenario(String key, LocalDateTime t0, String host, String org, Random r, boolean live) {
        Duration gap = live ? Duration.ofMinutes(1) : Duration.ofMinutes(10);
        List<Map<String, Object>> out = new ArrayList<>();
        switch (key) {
            case "smb_worm_legacy" -> out.addAll(smbOut(t0, host, org, r, 25, false));
            case "smb_worm_plain" -> out.addAll(smbOut(t0, host, org, r, 21, false));
            case "smb_worm_wannacry" -> out.addAll(smbOut(t0, host, org, r, 22, true));
            case "smb_lateral" -> out.addAll(smbIn(t0, host, org, r));
            case "smb_fileserver" -> out.addAll(smbSig(t0, host, org, r));
            case "remote_scan_kiosk" -> out.addAll(remoteScan(t0, host, org, r));
            case "bruteforce_success" -> {
                out.addAll(bruteforce(t0, host, org, r));
                out.addAll(authSuccess(t0.plusMinutes(4).plus(gap), host, org, r));
            }
            case "remote_tool_malicious" -> {
                out.addAll(remoteTool(t0, host, org, r));
                out.addAll(tiContact(t0.plus(gap.multipliedBy(2)), host, org, r));
            }
            case "coinminer" -> out.addAll(coinminer(t0, host, org, r, live ? 5 : 40));
            case "web_attack_success" -> {
                // 1분 창은 분 경계에 맞춰 평가하므로 폭증 구간이 한 분 안에 들어가야 한다
                LocalDateTime tb = t0.withSecond(2).withNano(0);
                out.addAll(wafBurst(tb, host, org, r));
                out.addAll(newOutbound(tb.plusSeconds(50).plus(gap.dividedBy(2)), host, org, r));
            }
            // ---- 사고 사례 기반 (docs/cases.md). 출발지가 외부인 WAF 사례는 공격자 IP 를 문서 대역에서 고른다.
            case "waf_attacker" -> out.addAll(wafSrcBurst(t0.withSecond(2).withNano(0), "203.0.113." + (50 + r.nextInt(150)),
                    host, org, r, 1100));
            case "waf_attacker_burst" -> out.addAll(wafSrcBurst(t0.withSecond(2).withNano(0),
                    "203.0.113." + (50 + r.nextInt(150)), host, org, r, 350));
            case "wannacry_device" -> out.addAll(killswitch(t0, host, org, r));
            case "wannacry_spread" -> {
                out.addAll(killswitch(t0, host, org, r));
                out.addAll(smbOut(t0.plus(gap), host, org, r, 22, false));
            }
            case "wannacry_fileserver" -> out.addAll(wannacryInternal(t0, host, "10.10.4.5", org, r));
            case "ti_contact_legacy" -> out.addAll(tiContact(t0, host, org, r));
            case "ti_contact_scan" -> {
                out.addAll(tiContact(t0, host, org, r));
                out.addAll(remoteScan(t0.plus(gap), host, org, r));
            }
            case "p2p_usage" -> out.addAll(p2p(t0, host, org, r, 8));
            case "p2p_malicious" -> {
                out.addAll(p2p(t0, host, org, r, 8));
                out.addAll(tiContact(t0.plus(gap.multipliedBy(2)), host, org, r));
            }
            case "exposed_admin_port" -> out.addAll(adminPortMulti(t0, host, org, r, 6));
            case "exposed_admin_port_success" -> {
                out.addAll(adminPortMulti(t0, host, org, r, 6));
                out.addAll(sshSuccess(t0.plus(gap.multipliedBy(2)), host, org, r));
            }
            case "remote_tool_only" -> out.addAll(remoteTool(t0, host, org, r));
            case "smb_ipc_kiosk" -> out.addAll(smbIpcSig(t0, host, org, r));
            case "neg_p2p_below" -> out.addAll(p2p(t0, host, org, r, 3));
            case "neg_admin_port_few" -> out.addAll(adminPortMulti(t0, host, org, r, 3));
            case "neg_below_threshold" -> out.addAll(smbOut(t0, host, org, r, 19, false));
            case "neg_exception_list" -> out.addAll(smbOut(t0, host, org, r, 30, false));
            case "neg_out_of_window" -> {
                out.addAll(bruteforce(t0, host, org, r));
                out.addAll(authSuccess(t0.plusMinutes(45), host, org, r));
            }
            case "neg_ids_port" -> {
                List<String> dsts = extMixed(r, 25);
                for (int i = 0; i < dsts.size(); i++) {
                    out.add(ev(org, "IDS", t0.plusSeconds(i * 6L), host, dsts.get(i), o().dport(445).dir("outbound")
                            .action("alert").method("SMB Traffic"), r));
                }
            }
            default -> throw new ApiException(400, "알 수 없는 시나리오: '" + key + "'");
        }
        return out;
    }

    // ---------------------------------------------------------------- 정상 트래픽
    static final List<String> NORMAL_SIGS = List.of("ET POLICY HTTP Outbound", "DNS Query", "TLS Client Hello",
            "ET INFO Windows Update");

    public static List<Map<String, Object>> background(LocalDateTime from, LocalDateTime to, Random r, int perMin) {
        List<Map<String, Object>> out = new ArrayList<>();
        Map<String, List<String>> clients = new LinkedHashMap<>();
        List<String> c1 = new ArrayList<>();
        for (int i = 100; i < 140; i++) {
            c1.add("10.10.1." + i);
        }
        List<String> c2 = new ArrayList<>();
        for (int i = 10; i < 40; i++) {
            c2.add("10.20.1." + i);
        }
        c2.add("10.10.1.50");
        List<String> c3 = new ArrayList<>();
        for (int i = 100; i < 120; i++) {
            c3.add("192.168.50." + i);
        }
        clients.put("ORG001", c1);
        clients.put("ORG002", c2);
        clients.put("ORG003", c3);
        List<String> stableExt = new ArrayList<>();
        for (int i = 200; i < 215; i++) {
            stableExt.add("192.0.2." + i);
        }
        Map<String, String> srv = Map.of("ORG001", "10.10.3.20", "ORG002", "10.20.3.20", "ORG003", "192.168.50.10");
        LocalDateTime t = from;
        while (t.isBefore(to)) {
            for (int k = 0; k < perMin; k++) {
                LocalDateTime ts = t.plus((long) (r.nextDouble() * 60000), ChronoUnit.MILLIS);
                if (!ts.isBefore(to)) {
                    continue;
                }
                String org = pick(r, List.of("ORG001", "ORG001", "ORG002", "ORG003"));
                String c = pick(r, clients.get(org));
                double kind = r.nextDouble();
                if (kind < 0.45) {
                    out.add(ev(org, pick(r, List.of("FIREWALL", "FIREWALL", "IPS", "TMS", "UTM")), ts, c, pick(r, stableExt),
                            o().dport(pick(r, List.of(443, 443, 80, 53))).dir("outbound").count(1 + r.nextInt(5)), r));
                } else if (kind < 0.6) {
                    out.add(ev(org, pick(r, List.of("IDS", "IPS")), ts, c, pick(r, stableExt), o().dport(443).dir("outbound")
                            .action("alert").method(pick(r, NORMAL_SIGS)).payload("GET / HTTP/1.1"), r));
                } else if (kind < 0.7) {
                    out.add(ev(org, "WAF", ts, pick(r, stableExt), srv.get(org), o().dir("inbound").method("WAF Normal")
                            .uri("/index.html").urlMethod("GET"), r));
                } else if (kind < 0.75) {
                    out.add(ev(org, "FIREWALL", ts, pick(r, stableExt), org.equals("ORG001") ? "10.10.2.10" : c,
                            o().dport(25).dir("inbound"), r));
                } else if (kind < 0.82) {
                    out.add(ev(org, "APT", ts, c, pick(r, stableExt), o().action("pass"), r));
                } else if (kind < 0.87) {
                    out.add(ev(org, "VPN", ts, pick(r, stableExt), c, o().action("login"), r));
                } else if (kind < 0.92) {
                    out.add(ev(org, "WEB", ts, pick(r, stableExt), c, o().uri("/").urlMethod("GET"), r));
                } else if (kind < 0.96) {
                    out.add(ev(org, "WFILTER", ts, null, null, o().action("allowed").method("Category: News"), r));
                } else {
                    out.add(ev(org, "DPX", ts, c, pick(r, stableExt), o().dir("outbound").method("HTTPS"), r));
                }
            }
            t = t.plusMinutes(1);
        }
        return out;
    }

    public int insertBackground(LocalDateTime from, LocalDateTime to, Long seed) {
        return insertEvents(background(from, to, seed == null ? new Random() : new Random(seed), 30));
    }

    // ---------------------------------------------------------------- 과거 데이터 적재 (초기화용)
    /** now 기준 과거 hours 시간 분량: 정상 트래픽 + 모든 시나리오(기관 ORG001) + 다른 기관 사례. */
    public Map<String, Object> loadHistory(LocalDateTime now, double hours) {
        Random r = new Random(7);
        LocalDateTime start = now.minusSeconds((long) (hours * 3600));
        List<Map<String, Object>> rows = new ArrayList<>(background(start, now.minusMinutes(1), r, 30));
        Duration span = Duration.between(start.plusMinutes(5), now.minusMinutes(55));
        Map<String, String> placed = new LinkedHashMap<>();
        for (int i = 0; i < CATALOG.size(); i++) {
            Scenario s = CATALOG.get(i);
            LocalDateTime t0 = start.plusMinutes(5).plus(span.multipliedBy(i).dividedBy(Math.max(1, CATALOG.size() - 1)));
            rows.addAll(buildScenario(s.key(), t0, s.host(), "ORG001", r, false));
            placed.put(s.key(), Kst.iso(t0));
        }
        // 기관 대역이 겹치는 다른 기관: 같은 IP 10.10.1.50 이 ORG002 에서는 태그 없는 PC → SC_SMB_WORM 높음
        LocalDateTime tOrg2 = start.plusMinutes(30);
        rows.addAll(smbOut(tOrg2, "10.10.1.50", "ORG002", r, 24, false));
        placed.put("org2_smb_worm_same_ip", Kst.iso(tOrg2));
        int n = insertEvents(rows);
        return Json.obj("events", n, "from", Kst.iso(start), "to", Kst.iso(now), "scenarios", placed);
    }

    public void seedKnownIncidents(Map<String, String> placed) {
        db.txRun(() -> {
            for (String key : List.of("smb_worm_legacy", "bruteforce_success", "web_attack_success")) {
                if (placed.containsKey(key)) {
                    Scenario s = byKey(key);
                    db.execute("INSERT INTO known_incidents (incident_id, org_id, entity, occurred_at, summary) VALUES "
                                    + "(:i, 'ORG001', :e, :t, :s) ON DUPLICATE KEY UPDATE occurred_at=VALUES(occurred_at)",
                            p("i", "INC-" + key, "e", s.host(), "t", Kst.parse(placed.get(key)), "s", s.title()));
                }
            }
        });
    }

    // ---------------------------------------------------------------- 지금 주입 (화면의 테스트 데이터 버튼)
    public Map<String, Object> injectNow(String key, String org, LocalDateTime now) {
        List<Scenario> targets = "all".equals(key) ? CATALOG : List.of(byKey(key));
        Random r = new Random();
        List<Map<String, Object>> result = new ArrayList<>();
        List<Map<String, Object>> rows = new ArrayList<>();
        db.txRun(() -> {
            for (Scenario s : targets) {
                // 같은 대상이면 억제 시간(6시간) 안에서 기존 경보 건수만 늘어나므로, 새 IP 에 같은 태그 자산을 만들어 쓴다
                String host;
                if (s.key().equals("neg_exception_list")) {
                    host = s.host();
                } else {
                    host = !org.equals("ORG003") ? "10.10." + (200 + r.nextInt(51)) + "." + (2 + r.nextInt(249))
                            : "192.168.50." + (150 + r.nextInt(101));
                    if (!s.tags().isEmpty()) {
                        asset(org, host, "[테스트] " + s.title(), "test", false, s.tags(), "incident_reply");
                    }
                }
                LocalDateTime t0;
                if (s.key().equals("web_attack_success") || s.key().startsWith("waf_")) {
                    t0 = now.withSecond(2).withNano(0);
                } else if (s.key().equals("bruteforce_success")) {
                    t0 = now.minusMinutes(6);
                } else {
                    t0 = now.minusMinutes(3);
                }
                List<Map<String, Object>> evs = buildScenario(s.key(), t0, host, org, r, true);
                rows.addAll(evs);
                result.add(Json.obj("scenario", s.key(), "host", host, "org_id", org, "events", evs.size(), "expect", s.expect()));
            }
        });
        ch.reloadDictionaries(List.of("dict_assets"));
        insertEvents(rows);
        return Json.obj("injected", result, "note", "1~2분 안에 히트와 경보가 생깁니다 (평가 주기 1분 + 지연 15초).");
    }
}
