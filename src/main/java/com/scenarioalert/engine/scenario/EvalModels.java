package com.scenarioalert.engine.scenario;

import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.common.Kst;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Java ↔ Python 시나리오 평가 입출력 모델. */
public final class EvalModels {
    private EvalModels() {
    }

    /** (rule_id, org_id, entity, hit_bucket) — 히트 하나를 가리키는 키. */
    public record HitKey(String ruleId, String orgId, String entity, LocalDateTime hitBucket) {
        List<Object> toJson() {
            return List.of(ruleId, orgId, entity, Kst.naiveIso(hitBucket));
        }
    }

    /** 단일룰 히트 (rule_hits 한 행). */
    public record Hit(String ruleId, int ruleVersion, String orgId, String entity, LocalDateTime hitBucket,
                      LocalDateTime firstSeen, LocalDateTime lastSeen, double value, double threshold,
                      List<String> sampleEventIds, LocalDateTime winTo, int windowSec) {
        public HitKey key() {
            return new HitKey(ruleId, orgId, entity, hitBucket);
        }

        public Hit withWindow(int sec) {
            return new Hit(ruleId, ruleVersion, orgId, entity, hitBucket, firstSeen, lastSeen, value, threshold,
                    sampleEventIds, winTo, sec);
        }

        Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("rule_id", ruleId);
            m.put("rule_version", ruleVersion);
            m.put("org_id", orgId);
            m.put("entity", entity);
            m.put("hit_bucket", Kst.naiveIso(hitBucket));
            m.put("first_seen", Kst.naiveIso(firstSeen));
            m.put("last_seen", Kst.naiveIso(lastSeen));
            m.put("value", value);
            m.put("threshold", threshold);
            m.put("sample_event_ids", sampleEventIds);
            m.put("win_to", Kst.naiveIso(winTo));
            m.put("window_sec", windowSec);
            return m;
        }
    }

    /** 평가 한 건: 한 (기관, 대상)의 히트와 자산 태그. newHitKeys 가 있으면 그 히트를 쓴 경로만 경보 후보. */
    public record EvalCase(String orgId, String entity, List<Hit> hits, Set<String> assetTags, Set<HitKey> newHitKeys) {
        Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("org_id", orgId);
            m.put("entity", entity);
            m.put("hits", hits.stream().map(Hit::toJson).toList());
            m.put("asset_tags", List.copyOf(assetTags));
            m.put("new_hit_keys", newHitKeys == null ? null : newHitKeys.stream().map(HitKey::toJson).toList());
            return m;
        }
    }

    /** 고른 경보 (가장 높은 등급 하나). */
    public record Chosen(String node, String severity, String title, String playbook, List<Map<String, Object>> path,
                         LocalDateTime time, LocalDateTime firstSeen, LocalDateTime lastSeen) {
    }

    /** 평가 결과 한 건. */
    public record EvalOutcome(Map<String, Object> nodeStatus, List<String> reachedAlerts, Chosen chosen) {
        @SuppressWarnings("unchecked")
        static EvalOutcome fromJson(Map<String, Object> m) {
            Chosen c = null;
            Map<String, Object> cm = Json.asMap(m.get("chosen"));
            if (cm != null) {
                List<Map<String, Object>> path = new ArrayList<>();
                for (Object s : Json.asList(cm.get("path"))) {
                    path.add((Map<String, Object>) s);
                }
                c = new Chosen((String) cm.get("node"), (String) cm.get("severity"), (String) cm.get("title"),
                        (String) cm.get("playbook"), path, Kst.parse((String) cm.get("time")),
                        Kst.parse((String) cm.get("first_seen")), Kst.parse((String) cm.get("last_seen")));
            }
            Map<String, Object> ns = Json.asMap(m.get("node_status"));
            return new EvalOutcome(ns == null ? Map.of() : ns, Json.strings(m.get("reached_alerts")), c);
        }
    }

    /** 평가할 시나리오 코드 (버전별 생성 코드). draft 는 저장 전 초안 (화면 시뮬레이션). */
    public record ScenarioProgram(String scenarioId, int version, String code, String sha256, boolean draft) {
    }
}
