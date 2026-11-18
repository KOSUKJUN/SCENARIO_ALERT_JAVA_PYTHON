package com.scenarioalert.engine.attack;

import com.scenarioalert.engine.attack.AttackBundle.Bundle;
import com.scenarioalert.engine.attack.AttackBundle.Obj;
import com.scenarioalert.engine.attack.AttackBundle.Rel;
import com.scenarioalert.engine.attack.AttackDiff.Ref;
import com.scenarioalert.engine.attack.AttackDiff.Tech;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.common.AppClock;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.common.VersionPackage;
import com.scenarioalert.engine.common.VersionPackage.Col;
import com.scenarioalert.engine.common.VersionPackage.Loaded;
import com.scenarioalert.engine.common.VersionPackage.Table;
import com.scenarioalert.engine.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
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
import java.util.function.BiConsumer;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static com.scenarioalert.engine.common.Db.p;

/**
 * MITRE ATT&CK 내부 사본 관리 (폐쇄망). 번들 가져오기·버전 활성화·조회, 룰·순서도의 기법 참조 검사, 경보용 기법 정보, 커버리지.
 * 서버는 메모리 상태를 갖지 않는다: 활성 버전은 매번 DB 에서 읽는다 (서버·worker 가 여러 대여도 바로 같은 버전을 본다).
 */
@Component
public class AttackService {
    private static final Logger log = LoggerFactory.getLogger(AttackService.class);
    public static final int MAX_IDS = 20;
    static final String ACTIVE_JOIN = " JOIN attack_versions v ON v.domain = o.domain AND v.version = o.version AND v.is_active ";

    private final Db db;
    private final Path dir;
    private final AppClock clock = AppClock.SYSTEM;

    public AttackService(Db db, AppProperties props, @Value("${app.attack-dir:}") String attackDir) {
        this.db = db;
        this.dir = attackDir == null || attackDir.isBlank()
                ? Path.of(props.rootDir()).resolve("data").resolve("attack").toAbsolutePath().normalize()
                : Path.of(attackDir).toAbsolutePath().normalize();
    }

    public Path dir() {
        return dir;
    }

    // ---------------------------------------------------------------- 형식 검사 (검증기에서 쓰는 순수 함수)

    /** 룰 정의·경보 노드의 attack 값 형식. 오류 메시지 또는 null. */
    public static String formatError(Object v) {
        if (v == null) {
            return null;
        }
        if (!(v instanceof List<?> l)) {
            return "attack 은 기법 ID 목록입니다 (예: [T1190, T1059.004])";
        }
        if (l.size() > MAX_IDS) {
            return "attack 은 " + MAX_IDS + "개 이하입니다";
        }
        Set<Object> seen = new LinkedHashSet<>();
        for (Object o : l) {
            if (!(o instanceof String s) || !AttackBundle.TECHNIQUE_ID.matcher(s).matches()) {
                return "기법 ID 형식이 아닙니다: " + Json.repr(o) + " (T1234 또는 T1234.001)";
            }
            if (!seen.add(s)) {
                return "같은 기법이 두 번 있습니다: " + s;
            }
        }
        return null;
    }

    public static List<String> ids(Object v) {
        if (!(v instanceof List<?> l)) {
            return List.of();
        }
        return l.stream().filter(o -> o instanceof String s && AttackBundle.TECHNIQUE_ID.matcher(s).matches())
                .map(String::valueOf).distinct().toList();
    }

    // ---------------------------------------------------------------- 가져오기

    public Map<String, Object> importStream(InputStream in, String fileName, String actor, String versionOverride) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        Bundle b;
        try (DigestInputStream din = new DigestInputStream(new BufferedInputStream(in, 1 << 16), md)) {
            b = AttackBundle.parse(din, versionOverride);
            din.transferTo(java.io.OutputStream.nullOutputStream());  // 해시는 파일 전체로 낸다
        } catch (IOException e) {
            throw ApiException.badRequest("번들을 읽지 못했습니다: " + e.getMessage());
        }
        String sha = HexFormat.of().formatHex(md.digest());
        return store(b, fileName, sha, actor);
    }

    private Map<String, Object> store(Bundle b, String fileName, String sha, String actor) {
        return db.tx(() -> {
            Map<String, Object> done = existing(b.domain(), b.version(), sha);
            if (done != null) {
                return done;
            }
            db.execute("INSERT INTO attack_versions (domain, version, name, released_at, spec_version, source_file, source_sha256, "
                            + "counts, imported_by) VALUES (:d, :v, :n, :r, :s, :f, :sha, :c, :by)",
                    p("d", b.domain(), "v", b.version(), "n", b.name(), "r", b.releasedAt(), "s", b.specVersion(),
                            "f", fileName == null ? "" : fileName, "sha", sha, "c", Json.dump(b.counts()), "by", actor));
            List<Map<String, Object>> objs = new ArrayList<>();
            for (Obj o : b.objects()) {
                objs.add(p("d", b.domain(), "v", b.version(), "t", o.type(), "id", o.attackId(), "sx", o.stixId(), "n", o.name(),
                        "pa", o.parentId(), "sn", o.shortname(), "ord", o.ord(), "de", o.description(), "u", o.url(),
                        "ta", o.tactics() == null ? null : Json.dump(o.tactics()), "ex", o.extra() == null ? null : Json.dump(o.extra()),
                        "dep", o.deprecated(), "rev", o.revoked(), "rb", o.revokedBy(), "m", o.modified()));
            }
            batch("INSERT INTO attack_objects (domain, version, obj_type, attack_id, stix_id, name, parent_id, shortname, ord, "
                    + "description, url, tactics, extra, deprecated, revoked, revoked_by, stix_modified) VALUES (:d, :v, :t, :id, :sx, "
                    + ":n, :pa, :sn, :ord, :de, :u, :ta, :ex, :dep, :rev, :rb, :m)", objs);
            List<Map<String, Object>> rels = new ArrayList<>();
            for (Rel r : b.relations()) {
                rels.add(p("d", b.domain(), "v", b.version(), "rt", r.relType(), "st", r.srcType(), "s", r.srcId(), "t", r.dstId(),
                        "de", r.description()));
            }
            batch("INSERT INTO attack_relations (domain, version, rel_type, src_type, src_id, dst_id, description) "
                    + "VALUES (:d, :v, :rt, :st, :s, :t, :de)", rels);
            boolean activate = activateIfNone(b.domain(), b.version());
            db.audit(actor, "attack.import", b.domain() + " " + b.version(),
                    Json.obj("file", fileName, "sha256", sha, "counts", b.counts(), "activated", activate));
            log.info("ATT&CK imported: {} {} ({}){}", b.domain(), b.version(), b.counts(), activate ? " - activated" : "");
            return Json.obj("domain", b.domain(), "version", b.version(), "name", b.name(), "status", "imported",
                    "is_active", activate, "counts", b.counts(), "sha256", sha);
        });
    }

    private void batch(String sql, List<Map<String, Object>> rows) {
        for (int i = 0; i < rows.size(); i += 500) {
            @SuppressWarnings("unchecked")
            Map<String, Object>[] chunk = rows.subList(i, Math.min(rows.size(), i + 500)).toArray(new Map[0]);
            db.jdbc().batchUpdate(sql, chunk);
        }
    }

    // ---------------------------------------------------------------- 내보내기 패키지 (다른 서버로 옮기기)

    static final List<String> PKG_KEYS = List.of("domain", "version");
    static final Table PKG_VERSION = new Table("attack_versions", PKG_KEYS, List.of(Col.str("name"), Col.time("released_at"),
            Col.str("spec_version"), Col.str("source_file"), Col.str("source_sha256"), Col.json("counts")), null);
    static final List<Table> PKG_TABLES = List.of(
            new Table("attack_objects", PKG_KEYS, List.of(Col.str("obj_type"), Col.str("attack_id"), Col.str("stix_id"), Col.str("name"),
                    Col.str("parent_id"), Col.str("shortname"), Col.integer("ord"), Col.str("description"), Col.str("url"),
                    Col.json("tactics"), Col.json("extra"), Col.bool("deprecated"), Col.bool("revoked"), Col.str("revoked_by"),
                    Col.time("stix_modified")), "obj_type, attack_id"),
            new Table("attack_relations", PKG_KEYS, List.of(Col.str("rel_type"), Col.str("src_type"), Col.str("src_id"), Col.str("dst_id"),
                    Col.str("description")), "rel_type, src_type, src_id, dst_id"));
    static final Map<String, Pattern> PKG_KEY_FORMAT = Map.of("domain", Pattern.compile("^[a-z][a-z0-9-]{0,31}$"),
            "version", Pattern.compile("^\\d{1,4}(\\.\\d{1,4}){0,3}$"));
    public static final String PKG_SUFFIX = ".zip";

    /** 버전 하나를 패키지(zip)로. 원본 번들이 없어도 DB 의 내용으로 같은 버전을 다른 서버에 만든다. */
    public byte[] exportPackage(String domain, String version, String actor) {
        requireVersion(domain, version);
        byte[] b = VersionPackage.export(db, "attack", p("domain", domain, "version", version), PKG_VERSION, PKG_TABLES, actor, clock.now());
        db.audit(actor, "attack.export", domain + " " + version, Json.obj("bytes", b.length));
        return b;
    }

    public static String packageName(String domain, String version) {
        return "attack_" + domain + "_" + version + PKG_SUFFIX;
    }

    /**
     * 다른 서버에서 내보낸 패키지를 가져온다. 버전 행(원본 파일 이름·sha256·발표일·건수)은 원본 그대로 두고 가져온 사람만 이 서버의 사용자로 한다.
     * 같은 버전이 같은 원본(sha256)으로 이미 있으면 already_imported, 다른 원본이면 409 (번들 가져오기와 같다).
     */
    public Map<String, Object> importPackage(InputStream in, String fileName, String actor) {
        Loaded l = VersionPackage.read(in, "attack", PKG_VERSION, PKG_TABLES, PKG_KEY_FORMAT);
        Map<String, Object> v = l.versionRow();
        String domain = (String) v.get("domain");
        String version = (String) v.get("version");
        String sha = (String) v.get("source_sha256");
        try {
            return db.tx(() -> {
                Map<String, Object> done = existing(domain, version, sha);
                if (done != null) {
                    return done;
                }
                Map<String, Object> row = new LinkedHashMap<>(v);
                row.put("imported_by", actor);
                db.execute("INSERT INTO attack_versions (domain, version, name, released_at, spec_version, source_file, source_sha256, "
                        + "counts, imported_by) VALUES (:domain, :version, :name, :released_at, :spec_version, :source_file, "
                        + ":source_sha256, :counts, :imported_by)", row);
                for (Table t : PKG_TABLES) {
                    VersionPackage.insert(db, t, l.rows().get(t.name()));
                }
                boolean activate = activateIfNone(domain, version);
                Object counts = Json.load((String) v.get("counts"));
                Map<String, Object> detail = VersionPackage.origin(l.manifest(), fileName);
                detail.put("sha256", sha);
                detail.put("activated", activate);
                db.audit(actor, "attack.import", domain + " " + version, detail);
                log.info("ATT&CK imported from package: {} {}{}", domain, version, activate ? " - activated" : "");
                return Json.obj("domain", domain, "version", version, "name", v.get("name"), "status", "imported",
                        "is_active", activate, "counts", counts, "sha256", sha);
            });
        } catch (DataAccessException e) {
            throw ApiException.badRequest("패키지 데이터를 넣지 못했습니다: " + e.getMostSpecificCause().getMessage());
        }
    }

    /** 같은 원본으로 이미 있으면 그 결과, 다른 원본이면 409, 없으면 null. 트랜잭션 안에서 부른다. */
    private Map<String, Object> existing(String domain, String version, String sha) {
        Map<String, Object> ex = db.row("SELECT source_sha256, is_active FROM attack_versions WHERE domain=:d AND version=:v FOR UPDATE",
                p("d", domain, "v", version));
        if (ex == null) {
            return null;
        }
        if (sha.equals(Db.str(ex, "source_sha256"))) {
            return Json.obj("domain", domain, "version", version, "status", "already_imported", "is_active", Db.bool(ex, "is_active"));
        }
        throw ApiException.conflict(domain + " " + version + " 은 다른 파일로 이미 가져왔습니다 (sha256 다름). "
                + "같은 버전을 다시 넣으려면 먼저 삭제하세요");
    }

    /** 도메인에 활성 버전이 없으면 이 버전을 활성화한다. */
    private boolean activateIfNone(String domain, String version) {
        boolean activate = db.row("SELECT 1 AS x FROM attack_versions WHERE domain=:d AND is_active", p("d", domain)) == null;
        if (activate) {
            db.execute("UPDATE attack_versions SET is_active=TRUE, activated_at=CURRENT_TIMESTAMP(3) WHERE domain=:d AND version=:v",
                    p("d", domain, "v", version));
        }
        return activate;
    }

    /**
     * 서버의 ATT&CK 디렉터리(ATTACK_DIR)에 놓인 번들 파일(*.json)과 내보내기 패키지(*.zip).
     * 폐쇄망에서는 파일을 이 디렉터리에 복사해 가져온다.
     */
    public List<Map<String, Object>> files() {
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        Map<String, Map<String, Object>> imported = new HashMap<>();
        Map<String, String> shaByVersion = new HashMap<>();
        db.rows("SELECT source_file, source_sha256, domain, version FROM attack_versions").forEach(r -> {
            imported.put(Db.str(r, "source_file"), r);
            shaByVersion.put(Db.str(r, "domain") + " " + Db.str(r, "version"), Db.str(r, "source_sha256"));
        });
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(f -> Files.isRegularFile(f) && (f.getFileName().toString().endsWith(".json")
                    || f.getFileName().toString().endsWith(PKG_SUFFIX))).sorted().map(f -> {
                String n = f.getFileName().toString();
                try {
                    if (n.endsWith(PKG_SUFFIX)) {
                        Map<String, Object> m;
                        try (InputStream in = Files.newInputStream(f)) {
                            m = VersionPackage.peekManifest(in);
                        }
                        Map<String, Object> ver = m == null || !"attack".equals(m.get("kind")) ? null : Json.asMap(m.get("version"));
                        String key = ver == null ? null : ver.get("domain") + " " + ver.get("version");
                        boolean done = ver != null && Objects.equals(shaByVersion.get(key), ver.get("source_sha256"));
                        return Json.obj("file", n, "size", Files.size(f), "package", true, "valid", ver != null, "imported", done,
                                "domain", ver == null ? null : ver.get("domain"), "version", ver == null ? null : ver.get("version"));
                    }
                    Map<String, Object> im = imported.get(n);
                    return Json.obj("file", n, "size", Files.size(f), "package", false, "valid", true, "imported", im != null,
                            "domain", im == null ? null : im.get("domain"), "version", im == null ? null : im.get("version"));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public Map<String, Object> importFile(String fileName, String actor, String versionOverride) {
        if (fileName == null || !fileName.matches("^[A-Za-z0-9._\\-]{1,200}\\.(json|zip)$")) {
            throw ApiException.badRequest("파일 이름 형식이 아닙니다");
        }
        Path f = dir.resolve(fileName).normalize();
        if (!f.startsWith(dir) || !Files.isRegularFile(f)) {
            throw ApiException.notFound("ATT&CK 파일 " + fileName);
        }
        try (InputStream in = Files.newInputStream(f)) {
            return fileName.endsWith(PKG_SUFFIX) ? importPackage(in, fileName, actor) : importStream(in, fileName, actor, versionOverride);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** init: 디렉터리의 번들 중 아직 가져오지 않은 파일을 모두 가져온다. 도메인에 활성 버전이 없으면 가장 높은 버전을 활성화한다. */
    public List<Map<String, Object>> importDir(String actor) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> f : files()) {
            if (!Boolean.TRUE.equals(f.get("imported")) && Boolean.TRUE.equals(f.get("valid"))) {
                try {
                    out.add(importFile((String) f.get("file"), actor, null));
                } catch (ApiException e) {
                    log.warn("ATT&CK file {} skipped: {}", f.get("file"), e.getMessage());
                    out.add(Json.obj("file", f.get("file"), "status", "error", "error", e.getMessage()));
                }
            }
        }
        // 처음 가져온 파일이 낮은 버전이면 그것이 활성화되었을 수 있다. 도메인마다 활성 버전이 첫 가져오기 결과면 최신으로 맞춘다.
        if (!out.isEmpty()) {
            for (Map<String, Object> d : db.rows("SELECT DISTINCT domain FROM attack_versions")) {
                String dom = Db.str(d, "domain");
                boolean importedNow = out.stream().anyMatch(o -> dom.equals(o.get("domain")) && Boolean.TRUE.equals(o.get("is_active")));
                if (importedNow) {
                    String latest = db.rows("SELECT version FROM attack_versions WHERE domain=:d", p("d", dom)).stream()
                            .map(r -> Db.str(r, "version")).max(VERSION_ORDER).orElseThrow();
                    activate(dom, latest, actor);
                }
            }
        }
        return out;
    }

    public static final Comparator<String> VERSION_ORDER = (a, b) -> {
        String[] x = a.split("\\.");
        String[] y = b.split("\\.");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int c = Integer.compare(i < x.length ? Integer.parseInt(x[i]) : 0, i < y.length ? Integer.parseInt(y[i]) : 0);
            if (c != 0) {
                return c;
            }
        }
        return 0;
    };

    // ---------------------------------------------------------------- 버전

    public List<Map<String, Object>> versions() {
        List<Map<String, Object>> rs = db.rows("SELECT domain, version, name, released_at, spec_version, source_file, source_sha256, "
                + "counts, is_active, imported_by, imported_at, activated_at FROM attack_versions");
        rs.forEach(r -> {
            r.put("counts", Json.load(Db.str(r, "counts")));
            r.put("is_active", Db.bool(r, "is_active"));
            for (String k : List.of("released_at", "imported_at", "activated_at")) {
                r.put(k, Db.time(r, k) == null ? null : Kst.iso(Db.time(r, k)));
            }
        });
        rs.sort(Comparator.comparing((Map<String, Object> r) -> Db.str(r, "domain"))
                .thenComparing((Map<String, Object> r) -> Db.str(r, "version"), VERSION_ORDER.reversed()));
        return rs;
    }

    private void requireVersion(String domain, String version) {
        if (db.row("SELECT 1 AS x FROM attack_versions WHERE domain=:d AND version=:v", p("d", domain, "v", version)) == null) {
            throw ApiException.notFound("ATT&CK " + domain + " " + version);
        }
    }

    public void activate(String domain, String version, String actor) {
        db.txRun(() -> {
            requireVersion(domain, version);
            db.execute("UPDATE attack_versions SET is_active=FALSE WHERE domain=:d AND version<>:v", p("d", domain, "v", version));
            db.execute("UPDATE attack_versions SET is_active=TRUE, activated_at=CURRENT_TIMESTAMP(3) WHERE domain=:d AND version=:v "
                    + "AND NOT is_active", p("d", domain, "v", version));
            db.audit(actor, "attack.activate", domain + " " + version, Map.of());
        });
    }

    public void delete(String domain, String version, String actor) {
        db.txRun(() -> {
            Map<String, Object> r = db.row("SELECT is_active FROM attack_versions WHERE domain=:d AND version=:v FOR UPDATE",
                    p("d", domain, "v", version));
            if (r == null) {
                throw ApiException.notFound("ATT&CK " + domain + " " + version);
            }
            if (Db.bool(r, "is_active")) {
                throw ApiException.conflict("활성 버전은 지울 수 없습니다. 다른 버전을 먼저 활성화하세요");
            }
            db.execute("DELETE FROM attack_versions WHERE domain=:d AND version=:v", p("d", domain, "v", version));
            db.audit(actor, "attack.delete", domain + " " + version, Map.of());
        });
    }

    /** 도메인 → 활성 버전. */
    public Map<String, String> active() {
        Map<String, String> m = new TreeMap<>();
        db.rows("SELECT domain, version FROM attack_versions WHERE is_active").forEach(r -> m.put(Db.str(r, "domain"), Db.str(r, "version")));
        return m;
    }

    /** domain/version 이 비어 있으면 활성 버전 (enterprise 우선). */
    public String[] pick(String domain, String version) {
        if (domain != null && !domain.isBlank() && version != null && !version.isBlank()) {
            requireVersion(domain, version);
            return new String[]{domain, version};
        }
        Map<String, String> act = active();
        if (act.isEmpty()) {
            throw ApiException.notFound("활성 ATT&CK 버전 (먼저 번들을 가져오세요)");
        }
        String d = domain != null && !domain.isBlank() ? domain : act.containsKey("enterprise-attack") ? "enterprise-attack"
                : act.keySet().iterator().next();
        String v = act.get(d);
        if (v == null) {
            throw ApiException.notFound("활성 ATT&CK 버전 (" + d + ")");
        }
        return new String[]{d, v};
    }

    // ---------------------------------------------------------------- 기법 조회

    /** 활성 버전의 기법 정보 (경보·검사용). 같은 ID 가 여러 도메인에 있으면 enterprise 를 쓴다. */
    public Map<String, Map<String, Object>> lookup(Collection<String> ids) {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        if (ids.isEmpty()) {
            return out;
        }
        Map<String, Map<String, String>> tactics = new HashMap<>();  // domain -> shortname -> "TA0001|Initial Access"
        db.rows("SELECT o.domain, o.shortname, o.attack_id, o.name FROM attack_objects o" + ACTIVE_JOIN + "WHERE o.obj_type='tactic'")
                .forEach(r -> tactics.computeIfAbsent(Db.str(r, "domain"), k -> new HashMap<>())
                        .put(Db.str(r, "shortname"), Db.str(r, "attack_id") + "|" + Db.str(r, "name")));
        List<Map<String, Object>> rs = db.rows("SELECT o.domain, o.version, o.attack_id, o.name, o.tactics, o.deprecated, o.revoked, "
                + "o.revoked_by FROM attack_objects o" + ACTIVE_JOIN + "WHERE o.obj_type='technique' AND o.attack_id IN (:ids) "
                + "ORDER BY o.domain <> 'enterprise-attack'", p("ids", List.copyOf(ids)));
        for (Map<String, Object> r : rs) {
            String id = Db.str(r, "attack_id");
            if (out.containsKey(id)) {
                continue;
            }
            List<Map<String, Object>> tl = new ArrayList<>();
            Map<String, String> td = tactics.getOrDefault(Db.str(r, "domain"), Map.of());
            for (String sn : Json.strings(Json.load(Db.str(r, "tactics")))) {
                String[] t = td.getOrDefault(sn, sn + "|" + sn).split("\\|", 2);
                tl.add(Json.obj("id", t[0], "name", t[1], "shortname", sn));
            }
            out.put(id, Json.obj("id", id, "name", Db.str(r, "name"), "tactics", tl, "deprecated", Db.bool(r, "deprecated"),
                    "revoked", Db.bool(r, "revoked"), "revoked_by", r.get("revoked_by"),
                    "domain", Db.str(r, "domain"), "version", Db.str(r, "version")));
        }
        return out;
    }

    /** 경보에 저장할 기법 스냅샷과 버전 표기. 활성 버전에 없는 ID 도 ID 만으로 남긴다. */
    public record Snapshot(List<Map<String, Object>> items, String versionLabel) {
    }

    public Snapshot snapshot(Collection<String> idsIn) {
        List<String> ids = idsIn.stream().distinct().sorted().toList();
        if (ids.isEmpty()) {
            return new Snapshot(List.of(), null);
        }
        Map<String, Map<String, Object>> info = lookup(ids);
        List<Map<String, Object>> items = new ArrayList<>();
        Set<String> versions = new LinkedHashSet<>();
        for (String id : ids) {
            Map<String, Object> t = info.get(id);
            if (t == null) {
                items.add(Json.obj("id", id, "name", null, "tactics", List.of()));
                continue;
            }
            versions.add(t.get("domain") + " " + t.get("version"));
            Map<String, Object> it = Json.obj("id", id, "name", t.get("name"), "tactics", t.get("tactics"));
            if (Boolean.TRUE.equals(t.get("revoked"))) {
                it.put("revoked_by", t.get("revoked_by"));
            }
            items.add(it);
        }
        return new Snapshot(items, versions.isEmpty() ? null : String.join(", ", versions));
    }

    /**
     * 룰·경보 노드의 기법 참조 검사 (저장 시). 활성 버전에 없으면 오류, 폐기(revoked)면 대체 기법과 함께 오류, 사용 중단(deprecated)이면 경고.
     * 활성 버전이 없으면 형식만 보고 경고 하나를 낸다. sink: (오류 여부, 메시지).
     */
    public void checkRefs(Object attackValue, BiConsumer<Boolean, String> sink) {
        List<String> ids = ids(attackValue);
        if (ids.isEmpty()) {
            return;
        }
        if (active().isEmpty()) {
            sink.accept(false, "ATT&CK 데이터가 없어 기법이 있는지 확인하지 못했습니다 (설정 > ATT&CK 에서 번들을 가져오세요)");
            return;
        }
        Map<String, Map<String, Object>> info = lookup(ids);
        for (String id : ids) {
            Map<String, Object> t = info.get(id);
            if (t == null) {
                sink.accept(true, "활성 ATT&CK 버전에 없는 기법입니다: " + id);
            } else if (Boolean.TRUE.equals(t.get("revoked"))) {
                sink.accept(true, id + " 는 폐기되었습니다" + (t.get("revoked_by") == null ? "" : " → " + t.get("revoked_by") + " 를 쓰세요"));
            } else if (Boolean.TRUE.equals(t.get("deprecated"))) {
                sink.accept(false, id + " (" + t.get("name") + ") 는 사용 중단된 기법입니다");
            }
        }
    }

    public List<Map<String, Object>> search(String q, String domain, String version, int limit) {
        String[] dv = pick(domain, version);
        String s = q == null ? "" : q.trim();
        Map<String, Object> params = p("d", dv[0], "v", dv[1], "n", Math.min(Math.max(limit, 1), 100));
        String where = "";
        if (!s.isEmpty()) {
            where = " AND (o.attack_id LIKE :pre OR o.name LIKE :like)";
            params.put("pre", s.toUpperCase(Locale.ROOT).replace("%", "") + "%");
            params.put("like", "%" + s.replace("%", "").replace("_", "\\_") + "%");
        }
        List<Map<String, Object>> rs = db.rows("SELECT o.attack_id AS id, o.name, o.parent_id, o.tactics FROM attack_objects o "
                + "WHERE o.domain=:d AND o.version=:v AND o.obj_type='technique' AND NOT o.revoked AND NOT o.deprecated" + where
                + " ORDER BY o.attack_id LIMIT :n", params);
        Map<String, String> parents = new HashMap<>();
        Set<String> pids = new LinkedHashSet<>();
        rs.forEach(r -> {
            if (r.get("parent_id") != null) {
                pids.add(Db.str(r, "parent_id"));
            }
        });
        if (!pids.isEmpty()) {
            db.rows("SELECT attack_id, name FROM attack_objects WHERE domain=:d AND version=:v AND obj_type='technique' AND attack_id IN (:p)",
                    p("d", dv[0], "v", dv[1], "p", List.copyOf(pids))).forEach(r -> parents.put(Db.str(r, "attack_id"), Db.str(r, "name")));
        }
        rs.forEach(r -> {
            r.put("tactics", Json.load(Db.str(r, "tactics")));
            r.put("parent_name", r.get("parent_id") == null ? null : parents.get(Db.str(r, "parent_id")));
        });
        return rs;
    }

    public Map<String, Object> technique(String id, String domain, String version) {
        String[] dv = pick(domain, version);
        Map<String, Object> o = db.row("SELECT attack_id AS id, name, parent_id, description, url, tactics, extra, deprecated, revoked, "
                        + "revoked_by, stix_modified FROM attack_objects WHERE domain=:d AND version=:v AND obj_type='technique' AND attack_id=:id",
                p("d", dv[0], "v", dv[1], "id", id));
        if (o == null) {
            throw ApiException.notFound("기법 " + id + " (" + dv[0] + " " + dv[1] + ")");
        }
        o.put("domain", dv[0]);
        o.put("version", dv[1]);
        o.put("deprecated", Db.bool(o, "deprecated"));
        o.put("revoked", Db.bool(o, "revoked"));
        o.put("extra", o.get("extra") == null ? Map.of() : Json.load(Db.str(o, "extra")));
        o.put("stix_modified", Db.time(o, "stix_modified") == null ? null : Kst.iso(Db.time(o, "stix_modified")));
        Map<String, Map<String, Object>> tinfo = lookupIn(dv, List.of(id));
        o.put("tactics", tinfo.containsKey(id) ? tinfo.get(id).get("tactics") : List.of());
        if (o.get("parent_id") != null) {
            Map<String, Object> pr = db.row("SELECT name FROM attack_objects WHERE domain=:d AND version=:v AND obj_type='technique' "
                    + "AND attack_id=:id", p("d", dv[0], "v", dv[1], "id", o.get("parent_id")));
            o.put("parent_name", pr == null ? null : pr.get("name"));
        }
        o.put("subtechniques", db.rows("SELECT attack_id AS id, name FROM attack_objects WHERE domain=:d AND version=:v "
                + "AND obj_type='technique' AND parent_id=:id AND NOT revoked AND NOT deprecated ORDER BY attack_id", p("d", dv[0], "v", dv[1], "id", id)));
        for (String[] rel : List.of(new String[]{"mitigates", "mitigation", "mitigations"}, new String[]{"detects", "detection", "detections"},
                new String[]{"uses", "group", "groups"}, new String[]{"uses", "software", "software"})) {
            o.put(rel[2], db.rows("SELECT r.src_id AS id, s.name, r.description FROM attack_relations r JOIN attack_objects s "
                    + "ON s.domain=r.domain AND s.version=r.version AND s.obj_type=r.src_type AND s.attack_id=r.src_id "
                    + "WHERE r.domain=:d AND r.version=:v AND r.rel_type=:rt AND r.src_type=:st AND r.dst_id=:id AND NOT s.revoked "
                    + "AND NOT s.deprecated ORDER BY r.src_id", p("d", dv[0], "v", dv[1], "rt", rel[0], "st", rel[1], "id", id)));
        }
        Map<String, Map<String, Object>> cov = coverage();
        o.put("coverage", cov.getOrDefault(id, emptyCoverage()));
        return o;
    }

    private Map<String, Map<String, Object>> lookupIn(String[] dv, List<String> ids) {
        Map<String, String> td = new HashMap<>();
        db.rows("SELECT shortname, attack_id, name FROM attack_objects WHERE domain=:d AND version=:v AND obj_type='tactic'",
                p("d", dv[0], "v", dv[1])).forEach(r -> td.put(Db.str(r, "shortname"), Db.str(r, "attack_id") + "|" + Db.str(r, "name")));
        Map<String, Map<String, Object>> out = new HashMap<>();
        db.rows("SELECT attack_id, tactics FROM attack_objects WHERE domain=:d AND version=:v AND obj_type='technique' AND attack_id IN (:ids)",
                p("d", dv[0], "v", dv[1], "ids", ids)).forEach(r -> {
            List<Map<String, Object>> tl = new ArrayList<>();
            for (String sn : Json.strings(Json.load(Db.str(r, "tactics")))) {
                String[] t = td.getOrDefault(sn, sn + "|" + sn).split("\\|", 2);
                tl.add(Json.obj("id", t[0], "name", t[1], "shortname", sn));
            }
            out.put(Db.str(r, "attack_id"), Json.obj("tactics", tl));
        });
        return out;
    }

    // ---------------------------------------------------------------- 참조·커버리지

    /** 현재 버전의 단일룰·순서도가 직접 참조하는 기법 (룰 정의의 attack, 순서도 경보 노드의 attack). */
    public Map<String, List<Ref>> directRefs() {
        Map<String, List<Ref>> out = new TreeMap<>();
        for (Map<String, Object> r : db.rows("SELECT r.rule_id, r.name, r.status, v.definition FROM single_rules r JOIN single_rule_versions v "
                + "ON v.rule_id=r.rule_id AND v.version=r.current_version")) {
            for (String id : ids(Json.loadMap(Db.str(r, "definition")).get("attack"))) {
                out.computeIfAbsent(id, k -> new ArrayList<>()).add(new Ref("rule", Db.str(r, "rule_id"), Db.str(r, "name"),
                        Db.str(r, "status"), null));
            }
        }
        for (Map<String, Object> s : db.rows("SELECT s.scenario_id, s.name, s.status, v.graph FROM scenarios s JOIN scenario_versions v "
                + "ON v.scenario_id=s.scenario_id AND v.version=s.current_version")) {
            for (Object n : Json.asList(Json.loadMap(Db.str(s, "graph")).get("nodes"))) {
                Map<String, Object> node = Json.asMap(n);
                if ("alert".equals(node.get("type"))) {
                    for (String id : ids(node.get("attack"))) {
                        out.computeIfAbsent(id, k -> new ArrayList<>()).add(new Ref("scenario", Db.str(s, "scenario_id"),
                                Db.str(s, "name"), Db.str(s, "status"), "경보 노드 " + node.get("id")));
                    }
                }
            }
        }
        return out;
    }

    private static Map<String, Object> emptyCoverage() {
        return Json.obj("rules", List.of(), "scenarios", List.of(), "alerts_30d", 0);
    }

    /**
     * 기법별 탐지 커버리지: 그 기법을 단 단일룰, 그 기법에 이르는 순서도(경보 노드의 attack 또는 참조 룰의 attack), 최근 30일 경보 수.
     * 사용 안 함(disabled) 룰·순서도도 상태와 함께 보여 준다.
     */
    public Map<String, Map<String, Object>> coverage() {
        Map<String, Map<String, Object>> out = new TreeMap<>();
        Map<String, List<String>> ruleAttack = new HashMap<>();
        for (Map<String, Object> r : db.rows("SELECT r.rule_id, r.name, r.status, v.definition FROM single_rules r JOIN single_rule_versions v "
                + "ON v.rule_id=r.rule_id AND v.version=r.current_version")) {
            List<String> ids = ids(Json.loadMap(Db.str(r, "definition")).get("attack"));
            ruleAttack.put(Db.str(r, "rule_id"), ids);
            for (String id : ids) {
                listOf(out, id, "rules").add(Json.obj("id", Db.str(r, "rule_id"), "name", Db.str(r, "name"), "status", Db.str(r, "status")));
            }
        }
        for (Map<String, Object> s : db.rows("SELECT s.scenario_id, s.name, s.status, v.graph FROM scenarios s JOIN scenario_versions v "
                + "ON v.scenario_id=s.scenario_id AND v.version=s.current_version")) {
            Map<String, String> via = new TreeMap<>();
            for (Object n : Json.asList(Json.loadMap(Db.str(s, "graph")).get("nodes"))) {
                Map<String, Object> node = Json.asMap(n);
                switch (String.valueOf(node.get("type"))) {
                    case "alert" -> ids(node.get("attack")).forEach(id -> via.put(id, "경보 노드"));
                    case "rule" -> ruleAttack.getOrDefault(String.valueOf(node.get("rule_id")), List.of())
                            .forEach(id -> via.putIfAbsent(id, "룰 " + node.get("rule_id")));
                    case "check" -> Json.strings(node.get("rule_ids")).forEach(rid -> ruleAttack.getOrDefault(rid, List.of())
                            .forEach(id -> via.putIfAbsent(id, "룰 " + rid)));
                    default -> {
                    }
                }
            }
            via.forEach((id, how) -> listOf(out, id, "scenarios").add(Json.obj("id", Db.str(s, "scenario_id"), "name", Db.str(s, "name"),
                    "status", Db.str(s, "status"), "via", how)));
        }
        for (Map<String, Object> a : db.rows("SELECT attack FROM alerts WHERE attack IS NOT NULL AND first_seen >= :since",
                p("since", Kst.now().minusDays(30)))) {
            for (Object it : Json.asList(Json.load(Db.str(a, "attack")))) {
                Object id = Json.asMap(it).get("id");
                if (id != null) {
                    Map<String, Object> c = out.computeIfAbsent(String.valueOf(id), k -> emptyCoverageMutable());
                    c.put("alerts_30d", ((Number) c.get("alerts_30d")).intValue() + 1);
                }
            }
        }
        return out;
    }

    private static Map<String, Object> emptyCoverageMutable() {
        return Json.obj("rules", new ArrayList<>(), "scenarios", new ArrayList<>(), "alerts_30d", 0);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> listOf(Map<String, Map<String, Object>> out, String id, String k) {
        return (List<Map<String, Object>>) out.computeIfAbsent(id, x -> emptyCoverageMutable()).get(k);
    }

    /** 매트릭스: 전술(순서대로) × 기법(하위 기법 포함) + 커버리지. 하위 기법의 커버리지는 상위 기법 칸에도 합산한다. */
    public Map<String, Object> matrix(String domain, String version) {
        String[] dv = pick(domain, version);
        List<Map<String, Object>> tactics = db.rows("SELECT attack_id AS id, name, shortname FROM attack_objects WHERE domain=:d AND "
                + "version=:v AND obj_type='tactic' AND NOT revoked AND NOT deprecated ORDER BY ord IS NULL, ord, attack_id", p("d", dv[0], "v", dv[1]));
        List<Map<String, Object>> techs = db.rows("SELECT attack_id AS id, name, parent_id, tactics FROM attack_objects WHERE domain=:d AND "
                + "version=:v AND obj_type='technique' AND NOT revoked AND NOT deprecated ORDER BY name", p("d", dv[0], "v", dv[1]));
        Map<String, Map<String, Object>> cov = coverage();
        Map<String, List<Map<String, Object>>> subs = new HashMap<>();
        for (Map<String, Object> t : techs) {
            if (t.get("parent_id") != null) {
                subs.computeIfAbsent(Db.str(t, "parent_id"), k -> new ArrayList<>()).add(cell(t, cov));
            }
        }
        Set<String> coveredTechs = new LinkedHashSet<>();
        int total = 0;
        for (Map<String, Object> tac : tactics) {
            List<Map<String, Object>> cells = new ArrayList<>();
            for (Map<String, Object> t : techs) {
                if (t.get("parent_id") != null || !Json.strings(Json.load(Db.str(t, "tactics"))).contains(Db.str(tac, "shortname"))) {
                    continue;
                }
                Map<String, Object> c = cell(t, cov);
                List<Map<String, Object>> sl = subs.getOrDefault(Db.str(t, "id"), List.of());
                c.put("subtechniques", sl);
                boolean subCovered = sl.stream().anyMatch(x -> Boolean.TRUE.equals(x.get("covered")));
                c.put("covered", Boolean.TRUE.equals(c.get("covered")) || subCovered);
                // 상위 칸의 룰·순서도 수 = 상위 기법과 하위 기법을 단 곳의 합집합 (같은 룰을 두 번 세지 않는다)
                List<String> family = new ArrayList<>(List.of(Db.str(t, "id")));
                sl.forEach(x -> family.add(String.valueOf(x.get("id"))));
                c.put("rules", distinctRefs(cov, family, "rules"));
                c.put("scenarios", distinctRefs(cov, family, "scenarios"));
                c.put("alerts_30d", ((Number) c.get("alerts_30d")).intValue()
                        + sl.stream().mapToInt(x -> ((Number) x.get("alerts_30d")).intValue()).sum());
                cells.add(c);
                total++;
                if (Boolean.TRUE.equals(c.get("covered"))) {
                    coveredTechs.add(Db.str(t, "id"));
                }
            }
            tac.put("techniques", cells);
        }
        return Json.obj("domain", dv[0], "version", dv[1], "tactics", tactics,
                "summary", Json.obj("techniques", techs.stream().filter(t -> t.get("parent_id") == null).count(),
                        "covered", coveredTechs.size(), "cells", total));
    }

    @SuppressWarnings("unchecked")
    private static int distinctRefs(Map<String, Map<String, Object>> cov, List<String> ids, String kind) {
        Set<Object> s = new LinkedHashSet<>();
        for (String id : ids) {
            Map<String, Object> c = cov.get(id);
            if (c != null) {
                ((List<Map<String, Object>>) c.get(kind)).forEach(r -> s.add(r.get("id")));
            }
        }
        return s.size();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cell(Map<String, Object> t, Map<String, Map<String, Object>> cov) {
        Map<String, Object> c = cov.get(Db.str(t, "id"));
        int rules = c == null ? 0 : ((List<Object>) c.get("rules")).size();
        int scs = c == null ? 0 : ((List<Object>) c.get("scenarios")).size();
        int alerts = c == null ? 0 : ((Number) c.get("alerts_30d")).intValue();
        return Json.obj("id", t.get("id"), "name", t.get("name"), "rules", rules, "scenarios", scs, "alerts_30d", alerts,
                "covered", rules + scs > 0);
    }

    // ---------------------------------------------------------------- 버전 비교

    public Map<String, Tech> techniques(String domain, String version) {
        Map<String, Tech> m = new HashMap<>();
        db.rows("SELECT attack_id, name, tactics, deprecated, revoked, revoked_by, stix_modified FROM attack_objects WHERE domain=:d "
                + "AND version=:v AND obj_type='technique'", p("d", domain, "v", version)).forEach(r -> m.put(Db.str(r, "attack_id"),
                new Tech(Db.str(r, "attack_id"), Db.str(r, "name"), Json.strings(Json.load(Db.str(r, "tactics"))), Db.bool(r, "deprecated"),
                        Db.bool(r, "revoked"), (String) r.get("revoked_by"), Db.time(r, "stix_modified"))));
        return m;
    }

    /** from(기본: 활성 버전) → to 의 기법 변화와, 현재 룰·순서도가 참조하는 기법에 미치는 영향. */
    public Map<String, Object> diff(String domain, String to, String from) {
        requireVersion(domain, to);
        String f = from;
        if (f == null || f.isBlank()) {
            f = active().get(domain);
        }
        Map<String, Tech> toT = techniques(domain, to);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("domain", domain);
        out.put("from", f);
        out.put("to", to);
        if (f != null) {
            requireVersion(domain, f);
            out.putAll(AttackDiff.diff(techniques(domain, f), toT));
        }
        out.put("impact", AttackDiff.impact(directRefs(), toT));
        return out;
    }
}
