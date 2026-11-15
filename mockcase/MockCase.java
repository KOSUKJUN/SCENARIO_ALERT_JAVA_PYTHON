import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 사고처리 시스템 모의 서버 (테스트용, 의존성 없는 단일 파일 Java).
 * <ul>
 * <li>POST /api/alerts      : 탐지 서버가 보내는 경보 접수 (Bearer 서비스 토큰). case_ref 를 돌려준다.</li>
 * <li>GET  /                : 접수한 경보 목록 화면. 종결 판정 버튼을 누르면 탐지 서버로 판정을 돌려준다.</li>
 * <li>GET  /api/cases       : 접수 목록 JSON</li>
 * <li>POST /api/fail?n=3    : 다음 n 건 접수를 일부러 실패시킨다 (재시도 확인용).</li>
 * </ul>
 * 메모리에만 저장한다.
 */
public class MockCase {
    static final String TOKEN = System.getenv().getOrDefault("CASE_SERVICE_TOKEN", "");
    static final String HOOK = System.getenv().getOrDefault("DETECT_HOOK_URL", "http://server:8000/api/v1/hooks/case-verdict");
    static final Map<String, Map<String, Object>> CASES = Collections.synchronizedMap(new LinkedHashMap<>());
    static final AtomicInteger SEQ = new AtomicInteger();
    static final AtomicInteger FAIL = new AtomicInteger();
    static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8090"));
        HttpServer s = HttpServer.create(new InetSocketAddress(port), 0);
        s.createContext("/", MockCase::route);
        s.start();
        System.out.println("mock case system on :" + port);
    }

    static void route(HttpExchange ex) throws IOException {
        try {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            if (method.equals("POST") && path.equals("/api/alerts")) {
                receive(ex);
            } else if (method.equals("POST") && path.equals("/api/fail")) {
                int n = Integer.parseInt(query(ex).getOrDefault("n", "3"));
                FAIL.set(n);
                send(ex, 200, "application/json", "{\"fail_next\": " + n + "}");
            } else if (method.equals("GET") && path.equals("/api/cases")) {
                List<Object> list;
                synchronized (CASES) {
                    list = new ArrayList<>(CASES.values());
                }
                send(ex, 200, "application/json", Mini.write(list));
            } else if (method.equals("POST") && path.startsWith("/cases/") && path.endsWith("/close")) {
                close(ex, path.substring(7, path.length() - 6), query(ex).getOrDefault("verdict", ""));
            } else if (method.equals("GET") && path.equals("/")) {
                send(ex, 200, "text/html; charset=utf-8", index());
            } else {
                send(ex, 404, "application/json", "{\"detail\": \"not found\"}");
            }
        } catch (RuntimeException e) {
            send(ex, 500, "application/json", "{\"detail\": " + Mini.write(String.valueOf(e.getMessage())) + "}");
        }
    }

    @SuppressWarnings("unchecked")
    static void receive(HttpExchange ex) throws IOException {
        if (!TOKEN.isEmpty() && !("Bearer " + TOKEN).equals(ex.getRequestHeaders().getFirst("Authorization"))) {
            send(ex, 401, "application/json", "{\"detail\": \"bad token\"}");
            return;
        }
        if (FAIL.get() > 0) {
            FAIL.decrementAndGet();
            send(ex, 503, "application/json", "{\"detail\": \"일부러 실패 (재시도 확인용)\"}");
            return;
        }
        Map<String, Object> payload = (Map<String, Object>) Mini.parse(new String(ex.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8));
        String aid = String.valueOf(payload.getOrDefault("alert_id", ""));
        String now = LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS).toString();
        synchronized (CASES) {
            for (Map<String, Object> c : CASES.values()) {
                if (aid.equals(c.get("alert_id"))) {
                    c.put("payload", payload);
                    c.put("updates", ((Integer) c.get("updates")) + 1);
                    c.put("updated_at", now);
                    send(ex, 200, "application/json", "{\"case_ref\": \"" + c.get("case_ref") + "\", \"updated\": true}");
                    return;
                }
            }
            String ref = String.format("CASE-%05d", SEQ.incrementAndGet());
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("case_ref", ref);
            c.put("alert_id", aid);
            c.put("payload", payload);
            c.put("updates", 0);
            c.put("verdict", null);
            c.put("received_at", now);
            c.put("updated_at", null);
            CASES.put(ref, c);
            send(ex, 200, "application/json", "{\"case_ref\": \"" + ref + "\"}");
        }
    }

    static void close(HttpExchange ex, String ref, String verdict) throws IOException {
        Map<String, Object> c = CASES.get(ref);
        if (c == null) {
            send(ex, 404, "application/json", "{\"detail\": \"no case\"}");
            return;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("alert_id", c.get("alert_id"));
        body.put("case_ref", ref);
        body.put("verdict", verdict);
        body.put("note", "사고처리 시스템 종결");
        int status;
        try {
            HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create(HOOK)).timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json").header("Authorization", "Bearer " + TOKEN)
                    .POST(HttpRequest.BodyPublishers.ofString(Mini.write(body), StandardCharsets.UTF_8)).build(),
                    HttpResponse.BodyHandlers.ofString());
            status = r.statusCode();
        } catch (IOException | InterruptedException e) {
            status = 0;
        }
        c.put("verdict", verdict + " (회신 " + status + ")");
        ex.getResponseHeaders().add("Location", "/");
        send(ex, 303, "text/plain", "");
    }

    static final Map<String, String> SEV_COLOR = Map.of("critical", "#c62828", "high", "#ef6c00", "medium", "#f9a825", "low", "#757575");

    @SuppressWarnings("unchecked")
    static String index() {
        List<Map<String, Object>> list;
        synchronized (CASES) {
            list = new ArrayList<>(CASES.values());
        }
        Collections.reverse(list);
        StringBuilder rows = new StringBuilder();
        for (Map<String, Object> c : list) {
            Map<String, Object> p = (Map<String, Object>) c.get("payload");
            String sev = String.valueOf(p.getOrDefault("severity", ""));
            StringBuilder btns = new StringBuilder();
            for (String[] v : new String[][]{{"true_positive", "정탐"}, {"false_positive", "오탐"}, {"benign", "정상"}}) {
                btns.append("<form method=\"post\" action=\"/cases/").append(c.get("case_ref")).append("/close?verdict=")
                        .append(v[0]).append("\" style=\"display:inline\"><button>").append(v[1]).append("</button></form>");
            }
            List<String> steps = new ArrayList<>();
            for (Object o : (List<Object>) p.getOrDefault("path", List.of())) {
                Map<String, Object> s = (Map<String, Object>) o;
                steps.add(esc(s.get("node")) + (s.get("result") != null ? "(" + esc(s.get("result")) + ")" : ""));
            }
            rows.append("<tr><td>").append(c.get("case_ref")).append("</td><td>").append(c.get("received_at"))
                    .append("</td><td><b style='color:").append(SEV_COLOR.getOrDefault(sev, "#000")).append("'>").append(esc(sev))
                    .append("</b>").append(Boolean.TRUE.equals(p.get("upgraded")) ? " (상향)" : "").append("</td><td>")
                    .append(esc(p.get("title"))).append("<br><small>").append(esc(p.get("source_id"))).append(" · ")
                    .append(esc(p.get("org_id"))).append(" · ").append(String.join(" → ", steps)).append("</small></td><td><small>")
                    .append(esc(p.get("playbook"))).append("</small></td><td>").append(c.get("updates")).append("</td><td>")
                    .append(esc(c.get("verdict") == null ? "" : c.get("verdict"))).append("<br>")
                    .append(c.get("verdict") == null ? btns : "").append("</td></tr>");
        }
        return "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>사고처리 시스템 (모의)</title>"
                + "<meta http-equiv=\"refresh\" content=\"15\"><style>body{font-family:sans-serif;margin:24px}"
                + "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px;vertical-align:top;font-size:14px}"
                + "th{background:#f5f5f5}</style></head><body><h2>사고처리 시스템 (모의) — 접수 " + list.size() + "건</h2>"
                + "<p>탐지 서버가 보낸 경보입니다. 종결 판정을 누르면 탐지 서버(/api/v1/hooks/case-verdict)로 회신합니다. 15초마다 새로고침.</p>"
                + "<table><tr><th>사건번호</th><th>접수</th><th>등급</th><th>제목·경로</th><th>대응</th><th>갱신</th><th>종결</th></tr>"
                + (rows.isEmpty() ? "<tr><td colspan=7>아직 접수된 경보가 없습니다</td></tr>" : rows) + "</table></body></html>";
    }

    static String esc(Object o) {
        return String.valueOf(o == null ? "" : o).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }

    static Map<String, String> query(HttpExchange ex) {
        Map<String, String> m = new LinkedHashMap<>();
        String q = ex.getRequestURI().getRawQuery();
        if (q != null) {
            for (String kv : q.split("&")) {
                int i = kv.indexOf('=');
                if (i > 0) {
                    m.put(URLDecoder.decode(kv.substring(0, i), StandardCharsets.UTF_8),
                            URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
                }
            }
        }
        return m;
    }

    static void send(HttpExchange ex, int status, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
        if (b.length > 0) {
            try (OutputStream os = ex.getResponseBody()) {
                os.write(b);
            }
        }
        ex.close();
    }

    /** 아주 작은 JSON 읽기·쓰기 (의존성 없이). */
    static final class Mini {
        private final String s;
        private int i;

        private Mini(String s) {
            this.s = s;
        }

        static Object parse(String s) {
            Mini m = new Mini(s);
            Object v = m.value();
            m.ws();
            return v;
        }

        void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        Object value() {
            ws();
            char c = s.charAt(i);
            if (c == '{') {
                Map<String, Object> m = new LinkedHashMap<>();
                i++;
                ws();
                if (s.charAt(i) == '}') {
                    i++;
                    return m;
                }
                while (true) {
                    ws();
                    String k = string();
                    ws();
                    i++; // :
                    m.put(k, value());
                    ws();
                    if (s.charAt(i++) == '}') {
                        return m;
                    }
                }
            }
            if (c == '[') {
                List<Object> l = new ArrayList<>();
                i++;
                ws();
                if (s.charAt(i) == ']') {
                    i++;
                    return l;
                }
                while (true) {
                    l.add(value());
                    ws();
                    if (s.charAt(i++) == ']') {
                        return l;
                    }
                }
            }
            if (c == '"') {
                return string();
            }
            if (s.startsWith("true", i)) {
                i += 4;
                return true;
            }
            if (s.startsWith("false", i)) {
                i += 5;
                return false;
            }
            if (s.startsWith("null", i)) {
                i += 4;
                return null;
            }
            int st = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            String num = s.substring(st, i);
            return num.matches("-?\\d+") ? (Object) Long.parseLong(num) : (Object) Double.parseDouble(num);
        }

        String string() {
            StringBuilder b = new StringBuilder();
            i++; // "
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') {
                    return b.toString();
                }
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case 'n' -> b.append('\n');
                        case 't' -> b.append('\t');
                        case 'r' -> b.append('\r');
                        case 'b' -> b.append('\b');
                        case 'f' -> b.append('\f');
                        case 'u' -> {
                            b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                        }
                        default -> b.append(e);
                    }
                } else {
                    b.append(c);
                }
            }
        }

        @SuppressWarnings("unchecked")
        static String write(Object v) {
            if (v == null) {
                return "null";
            }
            if (v instanceof String str) {
                StringBuilder b = new StringBuilder("\"");
                for (char c : str.toCharArray()) {
                    switch (c) {
                        case '"' -> b.append("\\\"");
                        case '\\' -> b.append("\\\\");
                        case '\n' -> b.append("\\n");
                        case '\r' -> b.append("\\r");
                        case '\t' -> b.append("\\t");
                        default -> {
                            if (c < 0x20) {
                                b.append(String.format("\\u%04x", (int) c));
                            } else {
                                b.append(c);
                            }
                        }
                    }
                }
                return b.append('"').toString();
            }
            if (v instanceof Map<?, ?> m) {
                List<String> parts = new ArrayList<>();
                ((Map<String, Object>) m).forEach((k, x) -> parts.add(write(k) + ": " + write(x)));
                return "{" + String.join(", ", parts) + "}";
            }
            if (v instanceof List<?> l) {
                List<String> parts = new ArrayList<>();
                l.forEach(x -> parts.add(write(x)));
                return "[" + String.join(", ", parts) + "]";
            }
            return String.valueOf(v);
        }
    }
}
