package com.scenarioalert.engine.alerting;

import com.scenarioalert.engine.attack.AttackService;
import com.scenarioalert.engine.d3fend.D3fendService;
import com.scenarioalert.engine.common.AppClock;
import com.scenarioalert.engine.common.Db;
import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.config.AppProperties;
import com.scenarioalert.engine.meta.Fields;
import com.scenarioalert.engine.repo.Repo;
import com.scenarioalert.engine.scenario.ScenarioCodeGenerator;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import static com.scenarioalert.engine.common.Db.p;

/**
 * 경보 생성, 등급 상향, 중복 억제, 사고처리 시스템 전달과 재시도 (설계안 7장).
 *
 * <p>억제 키는 (원천, org_id, entity). 억제 시간 안에 같은 등급 이하면 건수와 최종 시각만 갱신,
 * 더 높은 등급이면 기존 경보를 상향하고 다시 전달한다. 여러 서버가 같은 키를 동시에 처리하지 않도록 MariaDB GET_LOCK 을 쓴다.</p>
 */
@Component
public class AlertService {
    public static final int MAX_DELIVERY_ATTEMPTS = 10;
    static final int DELIVERY_LEASE_SEC = 120;
    /** 전달 중에 경보가 상향되면(recordAlert 가 pending 으로 되돌림) 결과를 덮어쓰지 않는다. */
    private static final String SAME_VERSION = "alert_id=:id AND severity=:sev AND upgraded_at <=> :upg AND attack <=> :atk AND d3fend <=> :d3f";

    public enum Decision { CREATE, UPGRADE, TOUCH }

    public record ExistingAlert(String alertId, String severity, LocalDateTime lastSeen) {
    }

    public record AlertCandidate(String sourceType, String sourceId, int sourceVersion, String orgId, String entityType,
                                 String entity, String severity, String title, String alertNode, String playbook,
                                 List<Map<String, Object>> path, LocalDateTime firstSeen, LocalDateTime lastSeen,
                                 boolean silent, int suppressSec, List<String> attack, List<String> d3fend) {
        public AlertCandidate(String sourceType, String sourceId, int sourceVersion, String orgId, String entityType,
                              String entity, String severity, String title, String alertNode, String playbook,
                              List<Map<String, Object>> path, LocalDateTime firstSeen, LocalDateTime lastSeen,
                              boolean silent, int suppressSec, List<String> attack) {
            this(sourceType, sourceId, sourceVersion, orgId, entityType, entity, severity, title, alertNode, playbook, path, firstSeen,
                    lastSeen, silent, suppressSec, attack, List.of());
        }
    }

    public record Recorded(Decision decision, String alertId) {
    }

    private final Db db;
    private final DataSource ds;
    private final Repo repo;
    private final CaseWebhook webhook;
    private final AppProperties props;
    private final MeterRegistry meters;
    private final AttackService attack;
    private final D3fendService d3fend;

    public AlertService(Db db, DataSource ds, Repo repo, CaseWebhook webhook, AppProperties props, MeterRegistry meters,
                        AttackService attack, D3fendService d3fend) {
        this.attack = attack;
        this.d3fend = d3fend;
        this.db = db;
        this.ds = ds;
        this.repo = repo;
        this.webhook = webhook;
        this.props = props;
        this.meters = meters;
    }

    /** 순수 함수: 억제 정책 (실시간과 백테스트가 함께 쓴다). */
    public static Decision decide(ExistingAlert existing, String severity, LocalDateTime now, int suppressSec) {
        if (existing == null || existing.lastSeen().isBefore(now.minusSeconds(suppressSec))) {
            return Decision.CREATE;
        }
        if (Fields.severityRank(severity) > Fields.severityRank(existing.severity())) {
            return Decision.UPGRADE;
        }
        return Decision.TOUCH;
    }

    /**
     * 억제 키 단위로 직렬화해 경보를 만들거나 갱신한다.
     * GET_LOCK 은 세션 단위 잠금이라 별도 연결에서 쥐고, 경보 트랜잭션을 커밋한 다음에 푼다.
     */
    public Recorded recordAlert(AlertCandidate c, LocalDateTime now) {
        String key = c.sourceType() + ":" + c.sourceId() + ":" + c.orgId() + ":" + c.entity();
        String lock = "alert:" + ScenarioCodeGenerator.sha256(key).substring(0, 40);
        try (Connection lconn = ds.getConnection()) {
            try (PreparedStatement ps = lconn.prepareStatement("SELECT GET_LOCK(?, 10)")) {
                ps.setString(1, lock);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next() || rs.getInt(1) != 1) {
                        throw new IllegalStateException("경보 잠금을 얻지 못했습니다");
                    }
                }
            }
            try {
                return db.tx(() -> recordLocked(c, now));
            } finally {
                try (PreparedStatement ps = lconn.prepareStatement("SELECT RELEASE_LOCK(?)")) {
                    ps.setString(1, lock);
                    ps.executeQuery().close();
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("경보 잠금 실패: " + e.getMessage(), e);
        }
    }

    private Recorded recordLocked(AlertCandidate c, LocalDateTime now) {
        LocalDateTime since = now.minusSeconds(c.suppressSec());
        Map<String, Object> ex = db.row("SELECT alert_id, severity, last_seen, attack, d3fend, silent FROM alerts WHERE source_type=:st AND "
                        + "source_id=:sid AND org_id=:o AND entity=:e AND last_seen >= :since ORDER BY last_seen DESC LIMIT 1",
                p("st", c.sourceType(), "sid", c.sourceId(), "o", c.orgId(), "e", c.entity(), "since", since));
        ExistingAlert existing = ex == null ? null
                : new ExistingAlert(Db.str(ex, "alert_id"), Db.str(ex, "severity"), Db.time(ex, "last_seen"));
        Decision d = decide(existing, c.severity(), now, c.suppressSec());
        String delivery = c.silent() ? "skipped" : "pending";
        // ATT&CK 기법 스냅샷: 경보가 만들어질 때(등급 상향 때)의 활성 버전 이름·전술. 버전이 바뀌어도 경보 내용은 그대로다.
        // 억제 시간 안에 같은 대상에서 다음 단계(예: 실행 뒤 도구 반입)가 보이면 기법을 누적한다 (등급·억제 판단은 그대로).
        Set<String> before = existing == null ? Set.of() : attackIds(ex.get("attack"));
        Set<String> merged = new TreeSet<>(before);
        merged.addAll(c.attack() == null ? List.of() : c.attack());
        // 지정 대응방책(D3FEND)도 같은 방식으로 스냅샷·누적한다: 다음 단계가 보이면 그 단계의 대응방책이 더해진다.
        Set<String> d3Before = existing == null ? Set.of() : attackIds(ex.get("d3fend"));
        Set<String> d3Merged = new TreeSet<>(d3Before);
        d3Merged.addAll(c.d3fend() == null ? List.of() : c.d3fend());
        boolean attackGrew = existing != null && (!merged.equals(before) || !d3Merged.equals(d3Before));
        AttackService.Snapshot snap = d == Decision.TOUCH && !attackGrew ? null : attack.snapshot(merged);
        String attackJson = snap == null || snap.items().isEmpty() ? null : Json.dump(snap.items());
        String attackVer = snap == null ? null : snap.versionLabel();
        D3fendService.Snapshot d3snap = d == Decision.TOUCH && !attackGrew ? null : d3fend.snapshot(d3Merged);
        String d3Json = d3snap == null || d3snap.items().isEmpty() ? null : Json.dump(d3snap.items());
        String d3Ver = d3snap == null ? null : d3snap.versionLabel();
        if (d == Decision.CREATE) {
            String aid = UUID.randomUUID().toString();
            db.execute("INSERT INTO alerts (alert_id, source_type, source_id, source_version, org_id, entity_type, entity, "
                            + "severity, title, alert_node, playbook, path, first_seen, last_seen, hit_count, silent, delivery_status, attack, "
                            + "attack_version, d3fend, d3fend_version) VALUES (:id, :st, :sid, :sv, :o, :et, :e, :sev, :t, :n, :pb, :p, :fs, "
                            + ":ls, 1, :sil, :ds, :atk, :atv, :d3f, :d3v)",
                    p("id", aid, "st", c.sourceType(), "sid", c.sourceId(), "sv", c.sourceVersion(), "o", c.orgId(),
                            "et", c.entityType(), "e", c.entity(), "sev", c.severity(), "t", c.title(), "n", c.alertNode(),
                            "pb", c.playbook(), "p", Json.dump(c.path()), "fs", c.firstSeen(), "ls", c.lastSeen(),
                            "sil", c.silent(), "ds", delivery, "atk", attackJson, "atv", attackVer, "d3f", d3Json, "d3v", d3Ver));
            meters.counter("alerts_total", "source", c.sourceId(), "decision", "create").increment();
            return new Recorded(d, aid);
        }
        if (d == Decision.UPGRADE) {
            db.execute("UPDATE alerts SET severity=:sev, title=:t, alert_node=:n, playbook=:pb, path=:p, source_version=:sv, "
                            + "last_seen=GREATEST(last_seen, :ls), hit_count=hit_count+1, upgraded_at=:now, silent=:sil, attack=:atk, attack_version=:atv, "
                            + "d3fend=:d3f, d3fend_version=:d3v, delivery_status=:ds, delivery_attempts=0, next_delivery_at=NULL, delivery_error=NULL "
                            + "WHERE alert_id=:id",
                    p("id", existing.alertId(), "sev", c.severity(), "t", c.title(), "n", c.alertNode(), "pb", c.playbook(),
                            "p", Json.dump(c.path()), "sv", c.sourceVersion(), "ls", c.lastSeen(), "now", now,
                            "sil", c.silent(), "ds", delivery, "atk", attackJson, "atv", attackVer, "d3f", d3Json, "d3v", d3Ver));
            meters.counter("alerts_total", "source", c.sourceId(), "decision", "upgrade").increment();
        } else if (attackGrew) {
            // ATT&CK 단계가 늘었다: 기법을 갱신하고 사고처리 시스템에 다시 보낸다 (alert_id 로 같은 사건을 갱신)
            boolean silentNow = Db.bool(ex, "silent");
            db.execute("UPDATE alerts SET last_seen=GREATEST(last_seen, :ls), hit_count=hit_count+1, attack=:atk, attack_version=:atv, d3fend=:d3f, d3fend_version=:d3v"
                            + (silentNow ? "" : ", delivery_status='pending', delivery_attempts=0, next_delivery_at=NULL, delivery_error=NULL")
                            + " WHERE alert_id=:id",
                    p("id", existing.alertId(), "ls", c.lastSeen(), "atk", attackJson, "atv", attackVer, "d3f", d3Json, "d3v", d3Ver));
            meters.counter("alerts_total", "source", c.sourceId(), "decision", "attack_stage").increment();
        } else {
            db.execute("UPDATE alerts SET last_seen=GREATEST(last_seen, :ls), hit_count=hit_count+1 WHERE alert_id=:id",
                    p("id", existing.alertId(), "ls", c.lastSeen()));
        }
        return new Recorded(d, existing.alertId());
    }

    static Set<String> attackIds(Object json) {
        Set<String> ids = new TreeSet<>();
        if (json != null) {
            for (Object o : Json.asList(Json.load(String.valueOf(json)))) {
                Object id = Json.asMap(o).get("id");
                if (id != null) {
                    ids.add(String.valueOf(id));
                }
            }
        }
        return ids;
    }

    // ---------------------------------------------------------------- 전달
    public Map<String, Object> buildPayload(Map<String, Object> a) {
        Map<String, Object> asset = repo.assetInfo(Db.str(a, "org_id"), Db.str(a, "entity"));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("alert_id", Db.str(a, "alert_id"));
        m.put("source_type", a.get("source_type"));
        m.put("source_id", a.get("source_id"));
        m.put("source_version", a.get("source_version"));
        m.put("org_id", a.get("org_id"));
        m.put("severity", a.get("severity"));
        m.put("title", a.get("title"));
        m.put("entity", Json.obj("type", a.get("entity_type"), "value", a.get("entity")));
        m.put("asset", Json.obj("tags", asset == null ? List.of() : asset.get("tags"),
                "purpose", asset == null ? null : asset.get("purpose"), "os", asset == null ? null : asset.get("os")));
        m.put("path", Json.load(Db.str(a, "path")));
        m.put("first_seen", Kst.iso(Db.time(a, "first_seen")));
        m.put("last_seen", Kst.iso(Db.time(a, "last_seen")));
        m.put("playbook", a.get("playbook") == null ? "" : a.get("playbook"));
        // MITRE ATT&CK 기법 (경보 생성 때 스냅샷): [{id, name, tactics:[{id, name, shortname}]}]
        m.put("attack", a.get("attack") == null ? List.of() : Json.load(Db.str(a, "attack")));
        m.put("attack_version", a.get("attack_version"));
        // 지정 대응방책 (MITRE D3FEND 방어 기법, 경보 생성 때 스냅샷): [{id, name, tactic}]
        m.put("d3fend", a.get("d3fend") == null ? List.of() : Json.load(Db.str(a, "d3fend")));
        m.put("d3fend_version", a.get("d3fend_version"));
        m.put("upgraded", a.get("upgraded_at") != null);
        m.put("evidence_url", props.publicBaseUrl().replaceAll("/+$", "") + "/alerts/" + Db.str(a, "alert_id"));
        return m;
    }

    /**
     * 전달 대기 경보를 보낸다. 실패하면 지수 간격(30초 × 2^n, 최대 1시간)으로 최대 10회 재시도.
     * HTTP 호출은 트랜잭션 밖에서 한다. 짧은 트랜잭션으로 next_delivery_at 을 임대 시각으로 미뤄 두고 커밋한 뒤 보낸다.
     */
    public int deliverPending(AppClock clock, int limit) {
        LocalDateTime now = clock.now();
        List<Map<String, Object>> pend = new ArrayList<>();
        List<Map<String, Object>> payloads = new ArrayList<>();
        db.txRun(() -> {
            pend.addAll(db.rows("SELECT * FROM alerts WHERE delivery_status='pending' AND silent=0 AND "
                    + "(next_delivery_at IS NULL OR next_delivery_at <= :now) ORDER BY created_at LIMIT :n FOR UPDATE SKIP LOCKED",
                    p("now", now, "n", limit)));
            if (!pend.isEmpty()) {
                db.execute("UPDATE alerts SET next_delivery_at=:lease WHERE alert_id IN (:ids)",
                        p("lease", now.plusSeconds(DELIVERY_LEASE_SEC), "ids", pend.stream().map(a -> Db.str(a, "alert_id")).toList()));
            }
            pend.forEach(a -> payloads.add(buildPayload(a)));
        });
        int sent = 0;
        for (int i = 0; i < pend.size(); i++) {
            Map<String, Object> a = pend.get(i);
            CaseWebhook.DeliveryResult r = webhook.deliver(payloads.get(i));
            Map<String, Object> pr = p("id", Db.str(a, "alert_id"), "sev", a.get("severity"), "upg", a.get("upgraded_at"), "atk", a.get("attack"),
                    "d3f", a.get("d3fend"), "e", r.error());
            if (r.ok()) {
                pr.put("ref", r.caseRef());
                db.txRun(() -> db.execute("UPDATE alerts SET delivery_status='sent', delivery_attempts=delivery_attempts+1, "
                        + "case_ref=COALESCE(:ref, case_ref), delivery_error=NULL, next_delivery_at=NULL WHERE " + SAME_VERSION, pr));
                sent++;
                continue;
            }
            int attempts = Db.integer(a, "delivery_attempts") + 1;
            meters.counter("delivery_failures_total").increment();
            pr.put("n", attempts);
            if (attempts >= MAX_DELIVERY_ATTEMPTS) {
                db.txRun(() -> db.execute("UPDATE alerts SET delivery_status='failed', delivery_attempts=:n, delivery_error=:e, "
                        + "next_delivery_at=NULL WHERE " + SAME_VERSION, pr));
            } else {
                long delay = Math.min(30L * (1L << (attempts - 1)), 3600L);
                pr.put("nx", now.plusSeconds(delay));
                db.txRun(() -> db.execute("UPDATE alerts SET delivery_attempts=:n, delivery_error=:e, next_delivery_at=:nx "
                        + "WHERE " + SAME_VERSION, pr));
            }
        }
        return sent;
    }
}
