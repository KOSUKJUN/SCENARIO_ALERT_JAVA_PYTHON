package com.scenarioalert.engine.attack;

import com.scenarioalert.engine.common.Json;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;

/** ATT&CK 두 버전의 기법 비교와, 룰·순서도가 참조하는 기법에 미치는 영향. 순수 함수. */
public final class AttackDiff {
    private AttackDiff() {
    }

    /** 비교에 쓰는 기법 정보. */
    public record Tech(String id, String name, List<String> tactics, boolean deprecated, boolean revoked, String revokedBy,
                       LocalDateTime modified) {
        boolean live() {
            return !deprecated && !revoked;
        }
    }

    /** 기법을 참조하는 곳 (단일룰 또는 순서도 경보 노드). */
    public record Ref(String kind, String id, String name, String status, String detail) {
    }

    public static Map<String, Object> diff(Map<String, Tech> from, Map<String, Tech> to) {
        List<Map<String, Object>> added = new ArrayList<>();
        List<Map<String, Object>> removed = new ArrayList<>();
        List<Map<String, Object>> revoked = new ArrayList<>();
        List<Map<String, Object>> deprecated = new ArrayList<>();
        List<Map<String, Object>> renamed = new ArrayList<>();
        List<Map<String, Object>> tactics = new ArrayList<>();
        List<String> updated = new ArrayList<>();
        for (Tech t : new TreeMap<>(to).values()) {
            Tech f = from.get(t.id());
            if (t.live() && (f == null || !f.live())) {
                added.add(Json.obj("id", t.id(), "name", t.name(), "tactics", t.tactics()));
            }
        }
        for (Tech f : new TreeMap<>(from).values()) {
            if (!f.live()) {
                continue;
            }
            Tech t = to.get(f.id());
            if (t == null) {
                removed.add(Json.obj("id", f.id(), "name", f.name()));
            } else if (t.revoked()) {
                Tech by = t.revokedBy() == null ? null : to.get(t.revokedBy());
                revoked.add(Json.obj("id", f.id(), "name", f.name(), "revoked_by", t.revokedBy(),
                        "revoked_by_name", by == null ? null : by.name()));
            } else if (t.deprecated()) {
                deprecated.add(Json.obj("id", f.id(), "name", f.name()));
            } else {
                if (!f.name().equals(t.name())) {
                    renamed.add(Json.obj("id", f.id(), "from", f.name(), "to", t.name()));
                }
                if (!new TreeSet<>(nz(f.tactics())).equals(new TreeSet<>(nz(t.tactics())))) {
                    tactics.add(Json.obj("id", f.id(), "name", t.name(), "from", nz(f.tactics()), "to", nz(t.tactics())));
                }
                if (!Objects.equals(f.modified(), t.modified())) {
                    updated.add(f.id());
                }
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("added", added);
        out.put("removed", removed);
        out.put("revoked", revoked);
        out.put("deprecated", deprecated);
        out.put("renamed", renamed);
        out.put("tactics_changed", tactics);
        out.put("updated", updated);
        out.put("summary", Json.obj("added", added.size(), "removed", removed.size(), "revoked", revoked.size(),
                "deprecated", deprecated.size(), "renamed", renamed.size(), "tactics_changed", tactics.size(),
                "updated", updated.size()));
        return out;
    }

    /**
     * 참조 기법 ID 마다 대상 버전에서의 상태: ok | missing | revoked | deprecated.
     * refs: 기법 ID → 그 기법을 참조하는 곳 목록.
     */
    public static List<Map<String, Object>> impact(Map<String, List<Ref>> refs, Map<String, Tech> to) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map.Entry<String, List<Ref>> e : new TreeMap<>(refs).entrySet()) {
            Tech t = to.get(e.getKey());
            String status;
            String hint = null;
            if (t == null) {
                status = "missing";
            } else if (t.revoked()) {
                status = "revoked";
                Tech by = t.revokedBy() == null ? null : to.get(t.revokedBy());
                hint = t.revokedBy() == null ? null : t.revokedBy() + (by == null ? "" : " " + by.name());
            } else if (t.deprecated()) {
                status = "deprecated";
            } else {
                continue;
            }
            out.add(Json.obj("technique", e.getKey(), "status", status, "replacement", hint,
                    "refs", e.getValue().stream().map(r -> Json.obj("kind", r.kind(), "id", r.id(), "name", r.name(),
                            "status", r.status(), "detail", r.detail())).toList()));
        }
        return out;
    }

    private static List<String> nz(List<String> l) {
        return l == null ? List.of() : l;
    }
}
