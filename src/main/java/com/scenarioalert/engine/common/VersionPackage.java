package com.scenarioalert.engine.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static com.scenarioalert.engine.common.Db.p;

/**
 * ATT&amp;CK·D3FEND 버전 내보내기 패키지 (다른 서버로 옮기기). zip 하나에 manifest.json 과 테이블마다 JSONL 파일 하나.
 * <ul>
 *   <li>manifest: 형식 표시, 종류(attack/d3fend), 버전 행(원본 파일 이름·sha256·건수 포함), 테이블별 파일·행 수·sha256</li>
 *   <li>버전 행의 source_sha256 은 원본 파일의 해시 그대로다: 받는 쪽에서 같은 원본을 다시 넣어도 "이미 가져옴" 이 된다</li>
 *   <li>JSONL 행에는 키 열(domain, version)을 넣지 않는다. 가져올 때 manifest 의 키로 채운다</li>
 * </ul>
 * 테이블·열 이름은 코드의 상수 명세에서만 온다 (패키지 내용을 SQL 에 잇지 않는다). 값은 모두 파라미터.
 */
public final class VersionPackage {
    public static final String FORMAT = "scenario-alert/mitre-version-package";
    public static final int FORMAT_VERSION = 1;
    public static final String MANIFEST = "manifest.json";
    /** 압축 해제 한도: 파일 하나와 전체. enterprise ATT&amp;CK 도 수십 MB 라 넉넉하다 (zip 폭탄 방지). */
    static final long MAX_ENTRY = 512L << 20;
    static final long MAX_TOTAL = 1024L << 20;

    private VersionPackage() {
    }

    public enum Kind { STR, INT, BOOL, JSON, TIME }

    public record Col(String name, Kind kind) {
        public static Col str(String n) {
            return new Col(n, Kind.STR);
        }

        public static Col integer(String n) {
            return new Col(n, Kind.INT);
        }

        public static Col bool(String n) {
            return new Col(n, Kind.BOOL);
        }

        public static Col json(String n) {
            return new Col(n, Kind.JSON);
        }

        public static Col time(String n) {
            return new Col(n, Kind.TIME);
        }
    }

    /** 테이블 명세. keys: 버전을 가리키는 열 (행에는 넣지 않는다), orderBy: 내보내기 순서 (같은 입력이면 같은 파일). */
    public record Table(String name, List<String> keys, List<Col> cols, String orderBy) {
        String file() {
            return name + ".jsonl";
        }

        String where() {
            return keys.stream().map(k -> k + "=:" + k).collect(Collectors.joining(" AND "));
        }

        String select() {
            return "SELECT " + cols.stream().map(Col::name).collect(Collectors.joining(", ")) + " FROM " + name + " WHERE " + where()
                    + (orderBy == null ? "" : " ORDER BY " + orderBy);
        }

        String insert() {
            List<String> all = new ArrayList<>(keys);
            cols.forEach(c -> all.add(c.name()));
            return "INSERT INTO " + name + " (" + String.join(", ", all) + ") VALUES ("
                    + all.stream().map(n -> ":" + n).collect(Collectors.joining(", ")) + ")";
        }
    }

    /** 읽은 패키지: manifest 의 버전 행(가져오기용 값으로 바꾼 것)과 테이블별 행(키 열 포함, 바로 INSERT 파라미터로 쓴다). */
    public record Loaded(Map<String, Object> manifest, Map<String, Object> versionRow, Map<String, List<Map<String, Object>>> rows) {
    }

    // ---------------------------------------------------------------- 내보내기

    /**
     * 버전 하나를 zip 으로. keyParams: 키 열 값 (예: domain, version). versionTable 의 행은 manifest 에, tables 는 JSONL 로 들어간다.
     */
    public static byte[] export(Db db, String kind, Map<String, Object> keyParams, Table versionTable, List<Table> tables,
                                String actor, LocalDateTime now) {
        Map<String, Object> vrow = db.row(versionTable.select(), keyParams);
        if (vrow == null) {
            throw ApiException.notFound(kind + " " + keyParams.values());
        }
        Map<String, Object> version = new LinkedHashMap<>(keyParams);
        version.putAll(toJson(vrow, versionTable.cols()));
        Map<String, Object> files = new LinkedHashMap<>();
        Map<String, byte[]> data = new LinkedHashMap<>();
        for (Table t : tables) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream(1 << 16);
            List<Map<String, Object>> rs = db.rows(t.select(), keyParams);
            for (Map<String, Object> r : rs) {
                buf.writeBytes(Json.dump(toJson(r, t.cols())).getBytes(StandardCharsets.UTF_8));
                buf.write('\n');
            }
            byte[] b = buf.toByteArray();
            data.put(t.file(), b);
            files.put(t.name(), Json.obj("file", t.file(), "rows", rs.size(), "sha256", sha256(b)));
        }
        Map<String, Object> manifest = Json.obj("format", FORMAT, "format_version", FORMAT_VERSION, "kind", kind,
                "version", version, "tables", files, "exported_at", now, "exported_by", actor);
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 << 20);
        try (ZipOutputStream z = new ZipOutputStream(out, StandardCharsets.UTF_8)) {
            put(z, MANIFEST, prettyJson(manifest), now);
            for (Map.Entry<String, byte[]> e : data.entrySet()) {
                put(z, e.getKey(), e.getValue(), now);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toByteArray();
    }

    private static byte[] prettyJson(Object v) {
        try {
            return Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(v);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void put(ZipOutputStream z, String name, byte[] b, LocalDateTime now) throws IOException {
        ZipEntry e = new ZipEntry(name);
        e.setTimeLocal(now);
        z.putNextEntry(e);
        z.write(b);
        z.closeEntry();
    }

    private static Map<String, Object> toJson(Map<String, Object> r, List<Col> cols) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (Col c : cols) {
            Object v = r.get(c.name());
            m.put(c.name(), switch (c.kind()) {
                case JSON -> v == null ? null : Json.load(String.valueOf(v));
                case BOOL -> Db.bool(r, c.name());
                case TIME -> Db.time(r, c.name());
                default -> v;
            });
        }
        return m;
    }

    // ---------------------------------------------------------------- 읽기

    /** manifest 만 읽는다 (디렉터리 목록 표시용). 형식이 아니면 null. */
    public static Map<String, Object> peekManifest(InputStream in) {
        try (ZipInputStream z = new ZipInputStream(in, StandardCharsets.UTF_8)) {
            for (ZipEntry e; (e = z.getNextEntry()) != null; ) {
                if (MANIFEST.equals(e.getName())) {
                    Map<String, Object> m = Json.loadMap(new String(readLimited(z, 4L << 20), StandardCharsets.UTF_8));
                    return m != null && FORMAT.equals(m.get("format")) ? m : null;
                }
            }
            return null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * 패키지를 읽고 검사한다: 형식·종류·형식 버전, 테이블 파일의 sha256·행 수, 버전 행의 키 형식(keyPattern).
     * 이상하면 400. 반환한 행은 키 열이 채워진 INSERT 파라미터다.
     */
    public static Loaded read(InputStream in, String kind, Table versionTable, List<Table> tables, Map<String, Pattern> keyPattern) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        long total = 0;
        try (ZipInputStream z = new ZipInputStream(in, StandardCharsets.UTF_8)) {
            List<String> allowed = new ArrayList<>(List.of(MANIFEST));
            tables.forEach(t -> allowed.add(t.file()));
            for (ZipEntry e; (e = z.getNextEntry()) != null; ) {
                if (e.isDirectory()) {
                    continue;
                }
                if (!allowed.contains(e.getName())) {
                    throw ApiException.badRequest("패키지에 모르는 파일이 있습니다: " + e.getName());
                }
                if (entries.containsKey(e.getName())) {
                    throw ApiException.badRequest("패키지에 같은 파일이 두 번 있습니다: " + e.getName());
                }
                byte[] b = readLimited(z, MAX_ENTRY);
                total += b.length;
                if (total > MAX_TOTAL) {
                    throw ApiException.badRequest("패키지가 너무 큽니다");
                }
                entries.put(e.getName(), b);
            }
        } catch (IOException e) {
            throw ApiException.badRequest("패키지(zip)를 읽지 못했습니다: " + e.getMessage());
        }
        byte[] mb = entries.get(MANIFEST);
        if (mb == null) {
            throw ApiException.badRequest("내보내기 패키지가 아닙니다 (" + MANIFEST + " 없음)");
        }
        Map<String, Object> manifest;
        try {
            manifest = Json.loadMap(new String(mb, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw ApiException.badRequest(MANIFEST + " 를 읽지 못했습니다");
        }
        if (manifest == null || !FORMAT.equals(manifest.get("format"))) {
            throw ApiException.badRequest("내보내기 패키지가 아닙니다 (format)");
        }
        if (!(manifest.get("format_version") instanceof Number fv) || fv.intValue() != FORMAT_VERSION) {
            throw ApiException.badRequest("지원하지 않는 패키지 형식 버전입니다: " + manifest.get("format_version"));
        }
        if (!kind.equals(manifest.get("kind"))) {
            throw ApiException.badRequest(kind + " 패키지가 아닙니다 (" + manifest.get("kind") + " 패키지)");
        }
        Map<String, Object> ver = Json.asMap(manifest.get("version"));
        if (ver == null) {
            throw ApiException.badRequest("manifest 에 version 이 없습니다");
        }
        Map<String, Object> keys = new LinkedHashMap<>();
        for (Map.Entry<String, Pattern> k : keyPattern.entrySet()) {
            Object v = ver.get(k.getKey());
            if (!(v instanceof String s) || !k.getValue().matcher(s).matches()) {
                throw ApiException.badRequest("manifest 의 " + k.getKey() + " 형식이 아닙니다: " + Json.repr(v));
            }
            keys.put(k.getKey(), s);
        }
        Object sha = ver.get("source_sha256");
        if (!(sha instanceof String s) || !s.matches("^[0-9a-f]{64}$")) {
            throw ApiException.badRequest("manifest 의 source_sha256 형식이 아닙니다");
        }
        Map<String, Object> versionRow = new LinkedHashMap<>(keys);
        versionRow.putAll(fromJson(ver, versionTable.cols(), "manifest.version"));
        Map<String, Object> tinfo = Json.asMap(manifest.get("tables"));
        Map<String, List<Map<String, Object>>> rows = new LinkedHashMap<>();
        for (Table t : tables) {
            Map<String, Object> ti = tinfo == null ? null : Json.asMap(tinfo.get(t.name()));
            byte[] b = entries.get(t.file());
            if (ti == null || b == null) {
                throw ApiException.badRequest("패키지에 " + t.file() + " 가 없습니다");
            }
            if (!sha256(b).equals(ti.get("sha256"))) {
                throw ApiException.badRequest(t.file() + " 의 sha256 이 manifest 와 다릅니다 (파일이 바뀌었거나 손상되었습니다)");
            }
            List<Map<String, Object>> list = new ArrayList<>();
            String[] lines = new String(b, StandardCharsets.UTF_8).split("\n");
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].isBlank()) {
                    continue;
                }
                Map<String, Object> r;
                try {
                    r = Json.loadMap(lines[i]);
                } catch (RuntimeException e) {
                    r = null;
                }
                if (r == null) {
                    throw ApiException.badRequest(t.file() + " " + (i + 1) + "행이 JSON 객체가 아닙니다");
                }
                Map<String, Object> row = new LinkedHashMap<>(keys);
                row.putAll(fromJson(r, t.cols(), t.file() + " " + (i + 1) + "행"));
                list.add(row);
            }
            if (!(ti.get("rows") instanceof Number n) || n.intValue() != list.size()) {
                throw ApiException.badRequest(t.file() + " 의 행 수가 manifest 와 다릅니다");
            }
            rows.put(t.name(), list);
        }
        return new Loaded(manifest, versionRow, rows);
    }

    private static Map<String, Object> fromJson(Map<String, Object> r, List<Col> cols, String where) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (Col c : cols) {
            Object v = r.get(c.name());
            try {
                m.put(c.name(), v == null ? (c.kind() == Kind.BOOL ? Boolean.FALSE : null) : switch (c.kind()) {
                    case STR -> {
                        if (v instanceof Map || v instanceof List) {
                            throw new IllegalArgumentException("문자열이어야 합니다");
                        }
                        yield String.valueOf(v);
                    }
                    case INT -> {
                        if (!Json.isInt(v)) {
                            throw new IllegalArgumentException("정수여야 합니다");
                        }
                        yield ((Number) v).intValue();
                    }
                    case BOOL -> {
                        if (!(v instanceof Boolean)) {
                            throw new IllegalArgumentException("true/false 여야 합니다");
                        }
                        yield v;
                    }
                    case JSON -> Json.dump(v);
                    case TIME -> Kst.parse(String.valueOf(v));
                });
            } catch (IllegalArgumentException | ApiException e) {
                throw ApiException.badRequest(where + " " + c.name() + ": " + e.getMessage());
            }
        }
        return m;
    }

    /** 가져오기: 행을 500개씩 나눠 넣는다. */
    public static void insert(Db db, Table t, List<Map<String, Object>> rows) {
        String sql = t.insert();
        for (int i = 0; i < rows.size(); i += 500) {
            @SuppressWarnings("unchecked")
            Map<String, Object>[] chunk = rows.subList(i, Math.min(rows.size(), i + 500)).toArray(new Map[0]);
            db.jdbc().batchUpdate(sql, chunk);
        }
    }

    /** manifest 의 출처 표시 (감사 기록용). */
    public static Map<String, Object> origin(Map<String, Object> manifest, String fileName) {
        return p("package", fileName, "exported_at", manifest.get("exported_at"), "exported_by", manifest.get("exported_by"));
    }

    private static byte[] readLimited(InputStream in, long max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[1 << 16];
        long n = 0;
        for (int r; (r = in.read(buf)) > 0; ) {
            n += r;
            if (n > max) {
                throw ApiException.badRequest("패키지 안의 파일이 너무 큽니다");
            }
            out.write(buf, 0, r);
        }
        return out.toByteArray();
    }

    public static String sha256(byte[] b) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
