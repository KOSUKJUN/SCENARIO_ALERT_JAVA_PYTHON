package com.scenarioalert.engine.singlerule;

import java.util.List;
import java.util.Map;

/** 검증을 통과한 단일룰 정의를 컴파일러가 쓰기 좋게 정리한 것. */
public record ParsedRule(
        String id,
        String name,
        String type,
        String entityType,
        String entityField,
        List<String> dataTp,
        Map<String, Object> filter,
        String aggFunc,
        String aggField,
        int windowSec,
        double threshold,
        List<String> excludeLists,
        int scheduleSec,
        boolean alertOnHit,
        String severity,
        int suppressSec,
        boolean usesNewPeer,
        Map<String, Object> raw) {
}
