package com.scenarioalert.engine.d3fend;

import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.config.AppProperties;
import com.scenarioalert.engine.d3fend.D3fendBundle.Bundle;
import com.scenarioalert.engine.d3fend.D3fendBundle.Mapping;
import com.scenarioalert.engine.d3fend.D3fendBundle.MitigationLink;
import com.scenarioalert.engine.d3fend.D3fendBundle.Ontology;
import com.scenarioalert.engine.d3fend.D3fendBundle.Tactic;
import com.scenarioalert.engine.d3fend.D3fendBundle.Technique;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.BiConsumer;
import java.util.stream.Stream;

import static com.scenarioalert.engine.common.Db.p;

/**
 * MITRE D3FEND 내부 사본 관리 (폐쇄망) 와 대응방책 연계.
 * <ul>
 *   <li>버전: 공식 릴리스(d3fend.json + d3fend-full-mappings.csv)를 가져와 버전별로 보관, 활성 버전 하나</li>
 *   <li>지정 대응방책: 단일룰 정의와 순서도 경보 노드의 d3fend (D3-xxx 목록). 경보는 생성 때 이름·전술을 스냅샷으로 남긴다</li>
 *   <li>권고 대응방책: 경보의 ATT&amp;CK 기법 → D3FEND 매핑 + ATT&amp;CK 완화(M) ↔ D3FEND 관계 (활성 버전으로 계산)</li>
 * </ul>
 * 탐지 로직과 무관한 메타데이터다: 생성 Python 에 넣지 않는다.
 */
@Component
public class D3fendService {
    private static final Logger log = LoggerFactory.getLogger(D3fendService.class);
    public static final int MAX_IDS = 20;
    public static final String ONTOLOGY_FILE = "d3fend.json";
    public static final String MAPPINGS_FILE = "d3fend-full-mappings.csv";
    /** 대응 순서: 사고 대응(격리·퇴출·복구) → 재발 방지(탐지·강화) → 기만·모델링. */
    public static final List<String> RESPONSE_ORDER = List.of("Isolate", "Evict", "Restore", "Detect", "Harden", "Deceive", "Model");
    public static final Map<String, String> TACTIC_KO = Map.of("Model", "모델링", "Harden", "강화", "Detect", "탐지", "Isolate", "격리",
            "Deceive", "기만", "Evict", "퇴출", "Restore", "복구");
    static final String ACTIVE = "(SELECT version FROM d3fend_versions WHERE is_active)";

    private final Db db;
    private final Path dir;

    public D3fendService(Db db, AppProperties props, @Value("${app.d3fend-dir:}") String d3fendDir) {
        this.db = db;
        this.dir = d3fendDir == null || d3fendDir.isBlank()
                ? Path.of(props.rootDir()).resolve("data").resolve("d3fend").toAbsolutePath().normalize()
                : Path.of(d3fendDir).toAbsolutePath().normalize();
    }

    public Path dir() {
        return dir;
    }

    // ---------------------------------------------------------------- 형식 검사 (검증기에서 쓰는 순수 함수)

    /** 룰 정의·경보 노드의 d3fend 값 형식. 오류 메시지 또는 null. */
    public static String formatError(Object v) {
        if (v == null) {
            return null;
        }
        if (!(v instanceof List<?> l)) {
            return "d3fend 는 D3FEND 방어 기법 ID 목록입니다 (예: [D3-PT, D3-NI])";
        }
        if (l.size() > MAX_IDS) {
            return "d3fend 는 " + MAX_IDS + "개 이하입니다";
        }
        Set<Object> seen = new LinkedHashSet<>();
        for (Object o : l) {
            if (!(o instanceof String s) || !D3fendBundle.TECHNIQUE_ID.matcher(s).matches()) {
                return "D3FEND 기법 ID 형식이 아닙니다: " + Json.repr(o) + " (D3-PT 처럼 D3- 로 시작)";
            }
            if (!seen.add(s)) {
                return "같은 대응 기법이 두 번 있습니다: " + s;
            }
        }
        return null;
    }

    public static List<String> ids(Object v) {
        if (!(v instanceof List<?> l)) {
            return List.of();
        }
        return l.stream().filter(o -> o instanceof String s && D3fendBundle.TECHNIQUE_ID.matcher(s).matches())
                .map(String::valueOf).distinct().toList();
    }

    // ---------------------------------------------------------------- 가져오기

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** 온톨로지와 매핑 CSV 한 쌍을 가져온다. source: 파일 이름 표시용 (디렉터리 가져오기는 하위 디렉터리 이름). */
    public Map<String, Object> importStreams(InputStream ontology, String ontologyName, InputStream mappings, String mappingsName,
                                             String source, String actor, String versionOverride) {
        MessageDigest md1 = sha256();
        MessageDigest md2 = sha256();
        Bundle b;
        long size1;
        long size2;
        try (DigestInputStream o = new DigestInputStream(new BufferedInputStream(ontology, 1 << 16), md1);
             DigestInputStream m = new DigestInputStream(new BufferedInputStream(mappings, 1 << 16), md2)) {
            Ontology ont = D3fendBundle.parseOntology(o, versionOverride);
            o.transferTo(OutputStream.nullOutputStream());
            b = D3fendBundle.parseMappings(ont, m);
            m.transferTo(OutputStream.nullOutputStream());
        } catch (IOException e) {
            throw ApiException.badRequest("D3FEND 파일을 읽지 못했습니다: " + e.getMessage());
        }
        String sha1 = HexFormat.of().formatHex(md1.digest());
        String sha2 = HexFormat.of().formatHex(md2.digest());
        String sha = HexFormat.of().formatHex(sha256().digest((sha1 + sha2).getBytes(StandardCharsets.US_ASCII)));
        List<Map<String, Object>> files = List.of(Json.obj("file", ontologyName, "sha256", sha1),
                Json.obj("file", mappingsName, "sha256", sha2));
        if (b.mappings().isEmpty()) {
            throw ApiException.badRequest("매핑 CSV 에서 ATT&CK ↔ D3FEND 매핑을 하나도 찾지 못했습니다 (온톨로지와 같은 버전인지 확인하세요)");
        }
        return store(b, source, files, sha, actor);
    }

    private Map<String, Object> store(Bundle b, String source, List<Map<String, Object>> files, String sha, String actor) {
        String ver = b.version();
        return db.tx(() -> {
            Map<String, Object> ex = db.row("SELECT source_sha256, is_active FROM d3fend_versions WHERE version=:v FOR UPDATE", p("v", ver));
            if (ex != null) {
                if (sha.equals(Db.str(ex, "source_sha256"))) {
                    return Json.obj("version", ver, "status", "already_imported", "is_active", Db.bool(ex, "is_active"));
                }
                throw ApiException.conflict("D3FEND " + ver + " 은 다른 파일로 이미 가져왔습니다 (sha256 다름). 같은 버전을 다시 넣으려면 먼저 삭제하세요");
            }
            Ontology o = b.ontology();
            db.execute("INSERT INTO d3fend_versions (version, released_at, source_files, source_sha256, counts, imported_by) "
                            + "VALUES (:v, :r, :f, :sha, :c, :by)",
                    p("v", ver, "r", o.releasedAt(), "f", Json.dump(Json.obj("source", source, "files", files)), "sha", sha,
                            "c", Json.dump(b.counts()), "by", actor));
            List<Map<String, Object>> rows = new ArrayList<>();
            for (Tactic t : o.tactics()) {
                rows.add(p("v", ver, "t", t.name(), "o", t.ord(), "d", t.definition()));
            }
            batch("INSERT INTO d3fend_tactics (version, tactic, ord, definition) VALUES (:v, :t, :o, :d)", rows);
            rows = new ArrayList<>();
            for (Technique t : o.techniques()) {
                rows.add(p("v", ver, "id", t.id(), "iri", t.iri(), "n", t.name(), "t", t.tactic(), "pa", t.parentId(), "dp", t.depth(),
                        "de", t.definition(), "kb", t.kbArticle(), "sy", t.synonyms().isEmpty() ? null : Json.dump(t.synonyms())));
            }
            batch("INSERT INTO d3fend_techniques (version, d3f_id, iri, name, tactic, parent_id, depth, definition, kb_article, synonyms) "
                    + "VALUES (:v, :id, :iri, :n, :t, :pa, :dp, :de, :kb, :sy)", rows);
            rows = new ArrayList<>();
            for (Mapping m : b.mappings()) {
                rows.add(p("v", ver, "a", m.attackId(), "d", m.d3fId(), "dom", m.attackDomain(), "an", m.attackName(),
                        "via", Json.dump(m.via())));
            }
            batch("INSERT INTO d3fend_attack_map (version, attack_id, d3f_id, attack_domain, attack_name, via) "
                    + "VALUES (:v, :a, :d, :dom, :an, :via)", rows);
            rows = new ArrayList<>();
            for (MitigationLink m : o.mitigations()) {
                rows.add(p("v", ver, "m", m.mitigationId(), "n", m.mitigationName(), "d", m.d3fId()));
            }
            batch("INSERT INTO d3fend_mitigation_map (version, mitigation_id, mitigation_name, d3f_id) VALUES (:v, :m, :n, :d)", rows);
            boolean activate = db.row("SELECT 1 AS x FROM d3fend_versions WHERE is_active", Map.of()) == null;
            if (activate) {
                db.execute("UPDATE d3fend_versions SET is_active=TRUE, activated_at=CURRENT_TIMESTAMP(3) WHERE version=:v", p("v", ver));
            }
            db.audit(actor, "d3fend.import", ver, Json.obj("source", source, "files", files, "counts", b.counts(),
                    "skipped_rows", b.skippedMappingRows(), "activated", activate));
            log.info("D3FEND imported: {} ({}){}", ver, b.counts(), activate ? " - activated" : "");
            return Json.obj("version", ver, "status", "imported", "is_active", activate, "counts", b.counts(), "sha256", sha);
        });
    }

    private void batch(String sql, List<Map<String, Object>> rows) {
        for (int i = 0; i < rows.size(); i += 500) {
            @SuppressWarnings("unchecked")
            Map<String, Object>[] chunk = rows.subList(i, Math.min(rows.size(), i + 500)).toArray(new Map[0]);
            db.jdbc().batchUpdate(sql, chunk);
        }
    }

    /**
     * 서버의 D3FEND 디렉터리(D3FEND_DIR)에 놓인 릴리스. 버전마다 하위 디렉터리 하나에 d3fend.json 과 d3fend-full-mappings.csv 를 둔다
     * (예: data/d3fend/1.6.0/). 폐쇄망에서는 이 디렉터리에 복사해 가져온다.
     */
    public List<Map<String, Object>> files() {
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        Map<String, Map<String, Object>> imported = new HashMap<>();
        db.rows("SELECT version, source_files FROM d3fend_versions").forEach(r -> {
            Object src = Json.loadMap(Db.str(r, "source_files")).get("source");
            if (src != null) {
                imported.put(String.valueOf(src), r);
            }
        });
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(Files::isDirectory).sorted().map(d -> {
                String n = d.getFileName().toString();
                Path o = d.resolve(ONTOLOGY_FILE);
                Path m = d.resolve(MAPPINGS_FILE);
                Map<String, Object> im = imported.get(n);
                try {
                    return Json.obj("name", n, "ontology", Files.isRegularFile(o) ? Files.size(o) : null,
                            "mappings", Files.isRegularFile(m) ? Files.size(m) : null, "complete", Files.isRegularFile(o) && Files.isRegularFile(m),
                            "imported", im != null, "version", im == null ? null : im.get("version"));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public Map<String, Object> importDirEntry(String name, String actor, String versionOverride) {
        if (name == null || !name.matches("^[A-Za-z0-9._\\-]{1,64}$") || name.startsWith(".")) {
            throw ApiException.badRequest("디렉터리 이름 형식이 아닙니다");
        }
        Path d = dir.resolve(name).normalize();
        if (!d.startsWith(dir) || !Files.isDirectory(d)) {
            throw ApiException.notFound("D3FEND 디렉터리 " + name);
        }
        Path o = d.resolve(ONTOLOGY_FILE);
        Path m = d.resolve(MAPPINGS_FILE);
        if (!Files.isRegularFile(o) || !Files.isRegularFile(m)) {
            throw ApiException.badRequest(name + " 에 " + ONTOLOGY_FILE + " 와 " + MAPPINGS_FILE + " 가 모두 있어야 합니다");
        }
        try (InputStream oi = Files.newInputStream(o); InputStream mi = Files.newInputStream(m)) {
            return importStreams(oi, ONTOLOGY_FILE, mi, MAPPINGS_FILE, name, actor, versionOverride);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** init: 디렉터리에서 아직 가져오지 않은 릴리스를 모두 가져온다. 이번에 처음 활성화가 생겼으면 가장 높은 버전으로 맞춘다. */
    public List<Map<String, Object>> importDir(String actor) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> f : files()) {
            if (!Boolean.TRUE.equals(f.get("imported")) && Boolean.TRUE.equals(f.get("complete"))) {
                try {
                    out.add(importDirEntry((String) f.get("name"), actor, null));
                } catch (ApiException e) {
                    log.warn("D3FEND {} skipped: {}", f.get("name"), e.getMessage());
                    out.add(Json.obj("name", f.get("name"), "status", "error", "error", e.getMessage()));
                }
            }
        }
        if (out.stream().anyMatch(o -> Boolean.TRUE.equals(o.get("is_active")) && "imported".equals(o.get("status")))) {
            db.rows("SELECT version FROM d3fend_versions").stream().map(r -> Db.str(r, "version"))
                    .max(VERSION_ORDER).ifPresent(v -> activate(v, actor));
        }
        return out;
    }

    /** 버전 순서: 점으로 나눈 각 마디의 앞 숫자로 비교한다 (0.13.0-BETA-1 같은 옛 표기도 받는다). */
    public static final Comparator<String> VERSION_ORDER = (a, b) -> {
        String[] x = a.split("\\.");
        String[] y = b.split("\\.");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int c = Integer.compare(i < x.length ? lead(x[i]) : 0, i < y.length ? lead(y[i]) : 0);
            if (c != 0) {
                return c;
            }
        }
        return a.compareTo(b);
    };

    private static int lead(String s) {
        int n = 0;
        for (int i = 0; i < s.length() && Character.isDigit(s.charAt(i)) && i < 9; i++) {
            n = n * 10 + (s.charAt(i) - '0');
        }
        return n;
    }

    // ---------------------------------------------------------------- 버전

    public List<Map<String, Object>> versions() {
        List<Map<String, Object>> rs = db.rows("SELECT version, released_at, source_files, source_sha256, counts, is_active, imported_by, "
                + "imported_at, activated_at FROM d3fend_versions");
        rs.forEach(r -> {
            r.put("counts", Json.load(Db.str(r, "counts")));
            r.put("source_files", Json.load(Db.str(r, "source_files")));
            r.put("is_active", Db.bool(r, "is_active"));
            for (String k : List.of("released_at", "imported_at", "activated_at")) {
                r.put(k, Db.time(r, k) == null ? null : Kst.iso(Db.time(r, k)));
            }
        });
        rs.sort(Comparator.comparing((Map<String, Object> r) -> Db.str(r, "version"), VERSION_ORDER.reversed()));
        return rs;
    }

    private void requireVersion(String version) {
        if (db.row("SELECT 1 AS x FROM d3fend_versions WHERE version=:v", p("v", version)) == null) {
            throw ApiException.notFound("D3FEND " + version);
        }
    }

    public void activate(String version, String actor) {
        db.txRun(() -> {
            requireVersion(version);
            db.execute("UPDATE d3fend_versions SET is_active=FALSE WHERE version<>:v AND is_active", p("v", version));
            db.execute("UPDATE d3fend_versions SET is_active=TRUE, activated_at=CURRENT_TIMESTAMP(3) WHERE version=:v AND NOT is_active",
                    p("v", version));
            db.audit(actor, "d3fend.activate", version, Map.of());
        });
    }

    public void delete(String version, String actor) {
        db.txRun(() -> {
            Map<String, Object> r = db.row("SELECT is_active FROM d3fend_versions WHERE version=:v FOR UPDATE", p("v", version));
            if (r == null) {
                throw ApiException.notFound("D3FEND " + version);
            }
            if (Db.bool(r, "is_active")) {
                throw ApiException.conflict("활성 버전은 지울 수 없습니다. 다른 버전을 먼저 활성화하세요");
            }
            db.execute("DELETE FROM d3fend_versions WHERE version=:v", p("v", version));
            db.audit(actor, "d3fend.delete", version, Map.of());
        });
    }

    /** 활성 버전 또는 null. */
    public String active() {
        Map<String, Object> r = db.row("SELECT version FROM d3fend_versions WHERE is_active", Map.of());
        return r == null ? null : Db.str(r, "version");
    }

    /** version 이 비어 있으면 활성 버전. */
    public String pick(String version) {
        if (version != null && !version.isBlank()) {
            requireVersion(version);
            return version;
        }
        String a = active();
        if (a == null) {
            throw ApiException.notFound("활성 D3FEND 버전 (먼저 D3FEND 릴리스를 가져오세요)");
        }
        return a;
    }

    // ---------------------------------------------------------------- 기법 조회

    /** 활성 버전의 기법 정보 (경보 스냅샷·검사·화면 칩). */
    public Map<String, Map<String, Object>> lookup(Collection<String> ids) {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        if (ids.isEmpty()) {
            return out;
        }
        db.rows("SELECT d3f_id, name, tactic, parent_id, version FROM d3fend_techniques WHERE version=" + ACTIVE + " AND d3f_id IN (:ids)",
                p("ids", List.copyOf(ids))).forEach(r -> out.put(Db.str(r, "d3f_id"), Json.obj("id", Db.str(r, "d3f_id"),
                "name", Db.str(r, "name"), "tactic", r.get("tactic"), "parent_id", r.get("parent_id"), "version", Db.str(r, "version"))));
        return out;
    }

    /** 경보에 저장할 지정 대응방책 스냅샷과 버전 표기. 활성 버전에 없는 ID 도 ID 만으로 남긴다. */
    public record Snapshot(List<Map<String, Object>> items, String versionLabel) {
    }

    public Snapshot snapshot(Collection<String> idsIn) {
        List<String> ids = idsIn.stream().distinct().sorted().toList();
        if (ids.isEmpty()) {
            return new Snapshot(List.of(), null);
        }
        Map<String, Map<String, Object>> info = lookup(ids);
        List<Map<String, Object>> items = new ArrayList<>();
        String ver = null;
        for (String id : ids) {
            Map<String, Object> t = info.get(id);
            if (t == null) {
                items.add(Json.obj("id", id, "name", null, "tactic", null));
            } else {
                ver = String.valueOf(t.get("version"));
                items.add(Json.obj("id", id, "name", t.get("name"), "tactic", t.get("tactic")));
            }
        }
        return new Snapshot(items, ver == null ? null : "D3FEND " + ver);
    }

    /** 룰·경보 노드의 대응 기법 참조 검사 (저장 시). 활성 버전에 없으면 오류. 활성 버전이 없으면 경고 하나. */
    public void checkRefs(Object value, BiConsumer<Boolean, String> sink) {
        List<String> ids = ids(value);
        if (ids.isEmpty()) {
            return;
        }
        if (active() == null) {
            sink.accept(false, "D3FEND 데이터가 없어 대응 기법이 있는지 확인하지 못했습니다 (D3FEND > 버전 관리에서 가져오세요)");
            return;
        }
        Map<String, Map<String, Object>> info = lookup(ids);
        for (String id : ids) {
            if (!info.containsKey(id)) {
                sink.accept(true, "활성 D3FEND 버전에 없는 대응 기법입니다: " + id);
            }
        }
    }

    public List<Map<String, Object>> search(String q, String version, String tactic, int limit) {
        String v = pick(version);
        String s = q == null ? "" : q.trim();
        Map<String, Object> params = p("v", v, "n", Math.min(Math.max(limit, 1), 300));
        StringBuilder where = new StringBuilder();
        if (!s.isEmpty()) {
            where.append(" AND (t.d3f_id LIKE :pre OR t.name LIKE :like OR t.synonyms LIKE :like)");
            params.put("pre", s.toUpperCase(Locale.ROOT).replace("%", "") + "%");
            params.put("like", "%" + s.replace("%", "").replace("_", "\\_") + "%");
        }
        if (tactic != null && !tactic.isBlank()) {
            where.append(" AND t.tactic = :ta");
            params.put("ta", tactic);
        }
        List<Map<String, Object>> rs = db.rows("SELECT t.d3f_id AS id, t.name, t.tactic, t.parent_id, p.name AS parent_name, t.depth, "
                + "(SELECT COUNT(*) FROM d3fend_attack_map m WHERE m.version=t.version AND m.d3f_id=t.d3f_id) AS attack_count "
                + "FROM d3fend_techniques t LEFT JOIN d3fend_techniques p ON p.version=t.version AND p.d3f_id=t.parent_id "
                + "WHERE t.version=:v" + where + " ORDER BY t.d3f_id LIMIT :n", params);
        rs.forEach(r -> r.put("attack_count", Db.integer(r, "attack_count")));
        return rs;
    }

    /** 전술별 기법 트리(이름순, 깊이 포함)와 지정 수. 화면의 D3FEND 매트릭스. */
    public Map<String, Object> matrix(String version) {
        String v = pick(version);
        Map<String, List<Ref>> refs = directRefs();
        Map<String, Integer> attackCount = new HashMap<>();
        db.rows("SELECT d3f_id, COUNT(*) AS n FROM d3fend_attack_map WHERE version=:v GROUP BY d3f_id", p("v", v))
                .forEach(r -> attackCount.put(Db.str(r, "d3f_id"), Db.integer(r, "n")));
        List<Map<String, Object>> techs = db.rows("SELECT d3f_id AS id, name, tactic, parent_id, depth FROM d3fend_techniques "
                + "WHERE version=:v ORDER BY name", p("v", v));
        Map<String, List<Map<String, Object>>> children = new HashMap<>();
        for (Map<String, Object> t : techs) {
            t.put("attack_count", attackCount.getOrDefault(Db.str(t, "id"), 0));
            t.put("designated", refs.getOrDefault(Db.str(t, "id"), List.of()).size());
            children.computeIfAbsent(Objects.toString(t.get("parent_id"), ""), k -> new ArrayList<>()).add(t);
        }
        List<Map<String, Object>> tactics = db.rows("SELECT tactic AS name, ord, definition FROM d3fend_tactics WHERE version=:v ORDER BY ord",
                p("v", v));
        for (Map<String, Object> ta : tactics) {
            List<Map<String, Object>> flat = new ArrayList<>();
            for (Map<String, Object> top : children.getOrDefault("", List.of())) {
                if (Objects.equals(top.get("tactic"), ta.get("name"))) {
                    flatten(top, children, flat);
                }
            }
            ta.put("label_ko", TACTIC_KO.getOrDefault(Db.str(ta, "name"), Db.str(ta, "name")));
            ta.put("techniques", flat);
        }
        return Json.obj("version", v, "tactics", tactics, "summary", Json.obj("techniques", techs.size(),
                "designated", techs.stream().filter(t -> ((Number) t.get("designated")).intValue() > 0).count()));
    }

    private static void flatten(Map<String, Object> t, Map<String, List<Map<String, Object>>> children, List<Map<String, Object>> out) {
        out.add(t);
        for (Map<String, Object> c : children.getOrDefault(Db.str(t, "id"), List.of())) {
            flatten(c, children, out);
        }
    }

    public Map<String, Object> technique(String id, String version) {
        String v = pick(version);
        Map<String, Object> o = db.row("SELECT d3f_id AS id, iri, name, tactic, parent_id, depth, definition, kb_article, synonyms "
                + "FROM d3fend_techniques WHERE version=:v AND d3f_id=:id", p("v", v, "id", id));
        if (o == null) {
            throw ApiException.notFound("D3FEND 기법 " + id + " (" + v + ")");
        }
        o.put("version", v);
        o.put("synonyms", o.get("synonyms") == null ? List.of() : Json.load(Db.str(o, "synonyms")));
        o.put("tactic_ko", TACTIC_KO.get(Db.str(o, "tactic")));
        List<Map<String, Object>> ancestors = new ArrayList<>();
        for (Object pid = o.get("parent_id"); pid != null && ancestors.size() < 10; ) {
            Map<String, Object> pr = db.row("SELECT d3f_id AS id, name, parent_id FROM d3fend_techniques WHERE version=:v AND d3f_id=:id",
                    p("v", v, "id", pid));
            if (pr == null) {
                break;
            }
            pid = pr.remove("parent_id");
            ancestors.add(0, pr);
        }
        o.put("ancestors", ancestors);
        o.put("children", db.rows("SELECT d3f_id AS id, name FROM d3fend_techniques WHERE version=:v AND parent_id=:id ORDER BY name",
                p("v", v, "id", id)));
        List<Map<String, Object>> attack = db.rows("SELECT attack_id AS id, attack_name AS name, attack_domain AS domain, via "
                + "FROM d3fend_attack_map WHERE version=:v AND d3f_id=:id ORDER BY attack_id", p("v", v, "id", id));
        attack.forEach(r -> r.put("via", Json.load(Db.str(r, "via"))));
        o.put("attack", attack);
        o.put("mitigations", db.rows("SELECT mitigation_id AS id, mitigation_name AS name FROM d3fend_mitigation_map "
                + "WHERE version=:v AND d3f_id=:id ORDER BY mitigation_id", p("v", v, "id", id)));
        o.put("designated_by", directRefs().getOrDefault(id, List.of()).stream().map(Ref::json).toList());
        return o;
    }

    // ---------------------------------------------------------------- 대응방책 (경보·ATT&CK 기법 → 권고)

    /**
     * ATT&CK 기법들에 대한 대응방책. 지정(designated: 룰·경보 노드에 사람이 정한 것)과 권고(D3FEND 매핑)를 전술별로 묶는다.
     * 권고 순서: 지정 → ATT&CK 완화(M) 와 이어진 기법 → 더 많은 기법을 막는 것. 하위 기법(T1059.004)에 매핑이 없으면 상위(T1059)를 쓴다.
     */
    public Map<String, Object> countermeasures(List<String> attackIds, List<String> designated, String version) {
        String v = pick(version);
        List<String> atk = attackIds.stream().filter(s -> com.scenarioalert.engine.attack.AttackBundle.TECHNIQUE_ID.matcher(s).matches())
                .distinct().sorted().toList();
        Map<String, Map<String, Object>> tech = new LinkedHashMap<>();
        Map<String, String> used = new LinkedHashMap<>();  // 경보 기법 → 매핑에 쓴 기법 (상위로 대체했으면 상위)
        for (String a : atk) {
            String key = a;
            if (!hasMapping(v, a) && a.contains(".")) {
                key = a.substring(0, a.indexOf('.'));
            }
            used.put(a, key);
        }
        Map<String, Set<String>> d3fToAttack = new TreeMap<>();
        Map<String, List<Object>> via = new HashMap<>();
        if (!used.isEmpty()) {
            List<String> keys = List.copyOf(new TreeSet<>(used.values()));
            for (Map<String, Object> r : db.rows("SELECT attack_id, d3f_id, via FROM d3fend_attack_map WHERE version=:v AND attack_id IN (:a)",
                    p("v", v, "a", keys))) {
                String d = Db.str(r, "d3f_id");
                for (Map.Entry<String, String> e : used.entrySet()) {
                    if (e.getValue().equals(Db.str(r, "attack_id"))) {
                        d3fToAttack.computeIfAbsent(d, k -> new TreeSet<>()).add(e.getKey());
                    }
                }
                List<Object> vl = via.computeIfAbsent(d, k -> new ArrayList<>());
                for (Object x : Json.asList(Json.load(Db.str(r, "via")))) {
                    if (vl.size() < 2 && !vl.contains(x)) {
                        vl.add(x);
                    }
                }
            }
        }
        // ATT&CK 완화(M): 활성 ATT&CK 버전에서 이 기법들을 완화하는 M → D3FEND 관계
        List<Map<String, Object>> mitigations = new ArrayList<>();
        Map<String, List<Map<String, Object>>> d3fToMit = new HashMap<>();
        if (!atk.isEmpty()) {
            Map<String, Map<String, Object>> mit = new TreeMap<>();
            for (Map<String, Object> r : db.rows("SELECT r.src_id, o.name, r.dst_id FROM attack_relations r JOIN attack_versions av "
                    + "ON av.domain=r.domain AND av.version=r.version AND av.is_active JOIN attack_objects o ON o.domain=r.domain "
                    + "AND o.version=r.version AND o.obj_type='mitigation' AND o.attack_id=r.src_id "
                    + "WHERE r.rel_type='mitigates' AND r.src_type='mitigation' AND r.dst_id IN (:a) AND NOT o.revoked AND NOT o.deprecated",
                    p("a", List.copyOf(new TreeSet<>(atk))))) {
                @SuppressWarnings("unchecked")
                Set<String> techs = (Set<String>) mit.computeIfAbsent(Db.str(r, "src_id"), k -> Json.obj("id", k, "name", Db.str(r, "name"),
                        "attack", new TreeSet<String>(), "d3fend", new ArrayList<String>())).get("attack");
                techs.add(Db.str(r, "dst_id"));
            }
            if (!mit.isEmpty()) {
                for (Map<String, Object> r : db.rows("SELECT mitigation_id, d3f_id FROM d3fend_mitigation_map WHERE version=:v "
                        + "AND mitigation_id IN (:m) ORDER BY d3f_id", p("v", v, "m", List.copyOf(mit.keySet())))) {
                    Map<String, Object> m = mit.get(Db.str(r, "mitigation_id"));
                    @SuppressWarnings("unchecked")
                    List<String> dl = (List<String>) m.get("d3fend");
                    dl.add(Db.str(r, "d3f_id"));
                    d3fToMit.computeIfAbsent(Db.str(r, "d3f_id"), k -> new ArrayList<>()).add(Json.obj("id", m.get("id"), "name", m.get("name")));
                }
            }
            mit.values().forEach(m -> {
                m.put("attack", List.copyOf((Set<?>) m.get("attack")));
                mitigations.add(m);
            });
        }
        Set<String> all = new LinkedHashSet<>(designated);
        all.addAll(d3fToAttack.keySet());
        all.addAll(d3fToMit.keySet());
        if (!all.isEmpty()) {
            db.rows("SELECT d3f_id, name, tactic, parent_id, depth, definition FROM d3fend_techniques WHERE version=:v AND d3f_id IN (:ids)",
                    p("v", v, "ids", List.copyOf(all))).forEach(r -> tech.put(Db.str(r, "d3f_id"), r));
        }
        Map<String, List<Map<String, Object>>> byTactic = new LinkedHashMap<>();
        RESPONSE_ORDER.forEach(t -> byTactic.put(t, new ArrayList<>()));
        List<Map<String, Object>> missing = new ArrayList<>();
        for (String id : all) {
            Map<String, Object> t = tech.get(id);
            if (t == null) {
                missing.add(Json.obj("id", id));
                continue;
            }
            List<String> a = List.copyOf(d3fToAttack.getOrDefault(id, Set.of()));
            List<Map<String, Object>> ms = d3fToMit.getOrDefault(id, List.of());
            Map<String, Object> item = Json.obj("id", id, "name", t.get("name"), "parent_id", t.get("parent_id"), "depth", Db.integer(t, "depth"),
                    "definition", t.get("definition"), "attack", a, "via", via.getOrDefault(id, List.of()), "mitigations", ms,
                    "designated", designated.contains(id), "recommended", !ms.isEmpty());
            byTactic.computeIfAbsent(Objects.toString(t.get("tactic"), "Other"), k -> new ArrayList<>()).add(item);
        }
        Comparator<Map<String, Object>> order = Comparator
                .comparing((Map<String, Object> x) -> !Boolean.TRUE.equals(x.get("designated")))
                .thenComparing(x -> !Boolean.TRUE.equals(x.get("recommended")))
                .thenComparing(x -> -((List<?>) x.get("attack")).size())
                .thenComparing(x -> String.valueOf(x.get("name")));
        List<Map<String, Object>> groups = new ArrayList<>();
        byTactic.forEach((ta, items) -> {
            if (!items.isEmpty()) {
                items.sort(order);
                groups.add(Json.obj("tactic", ta, "label_ko", TACTIC_KO.getOrDefault(ta, ta),
                        "response", List.of("Isolate", "Evict", "Restore").contains(ta), "techniques", items));
            }
        });
        List<String> unmapped = atk.stream().filter(a -> d3fToAttack.values().stream().noneMatch(s -> s.contains(a))).toList();
        List<Map<String, Object>> parentUsed = used.entrySet().stream().filter(e -> !e.getKey().equals(e.getValue()))
                .map(e -> Json.obj("attack", e.getKey(), "used", e.getValue())).toList();
        return Json.obj("version", v, "attack", atk, "designated", designated, "tactics", groups, "attack_mitigations", mitigations,
                "unmapped_attack", unmapped, "parent_fallback", parentUsed, "missing_designated", missing,
                "summary", Json.obj("techniques", all.size() - missing.size(), "designated", designated.size(),
                        "recommended", d3fToMit.size(), "mapped", d3fToAttack.size()));
    }

    private boolean hasMapping(String v, String attackId) {
        return db.row("SELECT 1 AS x FROM d3fend_attack_map WHERE version=:v AND attack_id=:a LIMIT 1", p("v", v, "a", attackId)) != null;
    }

    // ---------------------------------------------------------------- 지정 참조·연계 현황

    /** 대응 기법을 지정한 곳 (단일룰 정의의 d3fend, 순서도 경보 노드의 d3fend). */
    public record Ref(String kind, String id, String name, String status, String detail) {
        Map<String, Object> json() {
            return Json.obj("kind", kind, "id", id, "name", name, "status", status, "detail", detail);
        }
    }

    public Map<String, List<Ref>> directRefs() {
        Map<String, List<Ref>> out = new TreeMap<>();
        for (Map<String, Object> l : links()) {
            for (String id : Json.strings(l.get("d3fend"))) {
                out.computeIfAbsent(id, k -> new ArrayList<>()).add(new Ref(Db.str(l, "kind"), Db.str(l, "id"), Db.str(l, "name"),
                        Db.str(l, "status"), l.get("node") == null ? null : "경보 노드 " + l.get("node")));
            }
        }
        return out;
    }

    /** 현재 버전의 단일룰과 순서도 경보 노드마다 ATT&CK 기법과 지정 대응방책. */
    public List<Map<String, Object>> links() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> r : db.rows("SELECT r.rule_id, r.name, r.status, v.definition FROM single_rules r JOIN single_rule_versions v "
                + "ON v.rule_id=r.rule_id AND v.version=r.current_version ORDER BY r.rule_id")) {
            Map<String, Object> d = Json.loadMap(Db.str(r, "definition"));
            out.add(Json.obj("kind", "rule", "id", Db.str(r, "rule_id"), "name", Db.str(r, "name"), "status", Db.str(r, "status"),
                    "node", null, "severity", d.get("severity"), "attack", AttackService.ids(d.get("attack")), "d3fend", ids(d.get("d3fend"))));
        }
        for (Map<String, Object> s : db.rows("SELECT s.scenario_id, s.name, s.status, v.graph FROM scenarios s JOIN scenario_versions v "
                + "ON v.scenario_id=s.scenario_id AND v.version=s.current_version ORDER BY s.scenario_id")) {
            for (Object n : Json.asList(Json.loadMap(Db.str(s, "graph")).get("nodes"))) {
                Map<String, Object> node = Json.asMap(n);
                if ("alert".equals(node.get("type"))) {
                    out.add(Json.obj("kind", "scenario", "id", Db.str(s, "scenario_id"), "name", Db.str(s, "name"),
                            "status", Db.str(s, "status"), "node", node.get("id"), "severity", node.get("severity"),
                            "title", node.get("title"), "attack", AttackService.ids(node.get("attack")), "d3fend", ids(node.get("d3fend"))));
                }
            }
        }
        return out;
    }

    /** 연계 현황 화면: 링크마다 지정 대응방책의 이름·전술, 권고 수, 사고 대응(격리·퇴출·복구) 지정 여부. */
    public Map<String, Object> linkReport() {
        String v = active();
        List<Map<String, Object>> ls = links();
        Set<String> allD3 = new TreeSet<>();
        Set<String> allAtk = new TreeSet<>();
        ls.forEach(l -> {
            allD3.addAll(Json.strings(l.get("d3fend")));
            allAtk.addAll(Json.strings(l.get("attack")));
        });
        Map<String, Map<String, Object>> info = v == null ? Map.of() : lookup(allD3);
        Map<String, Integer> recCount = new HashMap<>();
        if (v != null && !allAtk.isEmpty()) {
            db.rows("SELECT attack_id, COUNT(*) AS n FROM d3fend_attack_map WHERE version=:v AND attack_id IN (:a) GROUP BY attack_id",
                    p("v", v, "a", List.copyOf(allAtk))).forEach(r -> recCount.put(Db.str(r, "attack_id"), Db.integer(r, "n")));
        }
        int withAttack = 0;
        int withD3 = 0;
        int withResponse = 0;
        for (Map<String, Object> l : ls) {
            List<Map<String, Object>> d = new ArrayList<>();
            boolean response = false;
            for (String id : Json.strings(l.get("d3fend"))) {
                Map<String, Object> t = info.get(id);
                d.add(Json.obj("id", id, "name", t == null ? null : t.get("name"), "tactic", t == null ? null : t.get("tactic")));
                response |= t != null && List.of("Isolate", "Evict", "Restore").contains(String.valueOf(t.get("tactic")));
            }
            l.put("d3fend", d);
            l.put("mapped", Json.strings(l.get("attack")).stream().mapToInt(a -> recCount.getOrDefault(a, 0)).sum());
            l.put("response", response);
            withAttack += Json.strings(l.get("attack")).isEmpty() ? 0 : 1;
            withD3 += d.isEmpty() ? 0 : 1;
            withResponse += response ? 1 : 0;
        }
        return Json.obj("version", v, "items", ls, "summary", Json.obj("total", ls.size(), "with_attack", withAttack,
                "with_d3fend", withD3, "with_response", withResponse));
    }

    // ---------------------------------------------------------------- 버전 비교

    private Map<String, Map<String, Object>> techniques(String v) {
        Map<String, Map<String, Object>> m = new TreeMap<>();
        db.rows("SELECT d3f_id, name, tactic, parent_id, definition FROM d3fend_techniques WHERE version=:v", p("v", v))
                .forEach(r -> m.put(Db.str(r, "d3f_id"), r));
        return m;
    }

    private Set<String> mappingPairs(String v) {
        Set<String> s = new TreeSet<>();
        db.rows("SELECT attack_id, d3f_id FROM d3fend_attack_map WHERE version=:v", p("v", v))
                .forEach(r -> s.add(Db.str(r, "attack_id") + "|" + Db.str(r, "d3f_id")));
        return s;
    }

    /** from(기본: 활성) → to: 기법 추가·삭제·이름·전술·상위 변경, 정의 갱신, 매핑 변화, 지정 대응방책 영향(없어지는 기법). */
    public Map<String, Object> diff(String to, String from) {
        requireVersion(to);
        String f = from == null || from.isBlank() ? active() : from;
        Map<String, Map<String, Object>> toT = techniques(to);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("from", f);
        out.put("to", to);
        if (f != null) {
            requireVersion(f);
            Map<String, Map<String, Object>> fromT = techniques(f);
            List<Map<String, Object>> added = new ArrayList<>();
            List<Map<String, Object>> removed = new ArrayList<>();
            List<Map<String, Object>> renamed = new ArrayList<>();
            List<Map<String, Object>> moved = new ArrayList<>();
            List<String> updated = new ArrayList<>();
            toT.forEach((id, t) -> {
                if (!fromT.containsKey(id)) {
                    added.add(Json.obj("id", id, "name", t.get("name"), "tactic", t.get("tactic")));
                }
            });
            fromT.forEach((id, o) -> {
                Map<String, Object> t = toT.get(id);
                if (t == null) {
                    removed.add(Json.obj("id", id, "name", o.get("name"), "tactic", o.get("tactic")));
                    return;
                }
                if (!Objects.equals(o.get("name"), t.get("name"))) {
                    renamed.add(Json.obj("id", id, "from", o.get("name"), "to", t.get("name")));
                }
                if (!Objects.equals(o.get("tactic"), t.get("tactic")) || !Objects.equals(o.get("parent_id"), t.get("parent_id"))) {
                    moved.add(Json.obj("id", id, "name", t.get("name"), "from", o.get("tactic") + " / " + Objects.toString(o.get("parent_id"), "-"),
                            "to", t.get("tactic") + " / " + Objects.toString(t.get("parent_id"), "-")));
                }
                if (!Objects.equals(o.get("definition"), t.get("definition"))) {
                    updated.add(id);
                }
            });
            Set<String> pf = mappingPairs(f);
            Set<String> pt = mappingPairs(to);
            long mAdded = pt.stream().filter(x -> !pf.contains(x)).count();
            long mRemoved = pf.stream().filter(x -> !pt.contains(x)).count();
            out.put("added", added);
            out.put("removed", removed);
            out.put("renamed", renamed);
            out.put("moved", moved);
            out.put("updated", updated);
            out.put("summary", Json.obj("added", added.size(), "removed", removed.size(), "renamed", renamed.size(), "moved", moved.size(),
                    "updated", updated.size(), "mappings_added", mAdded, "mappings_removed", mRemoved));
        }
        List<Map<String, Object>> impact = new ArrayList<>();
        directRefs().forEach((id, refs) -> {
            if (!toT.containsKey(id)) {
                impact.add(Json.obj("technique", id, "status", "missing", "refs", refs.stream().map(Ref::json).toList()));
            }
        });
        out.put("impact", impact);
        return out;
    }
}
