package com.scenarioalert.engine.repo;

import com.scenarioalert.engine.common.Kst;
import com.scenarioalert.engine.scenario.EvalModels.ScenarioProgram;

import java.time.LocalDateTime;
import java.util.Map;

/** 저장소 레코드. */
public final class Records {
    private Records() {
    }

    public record RuleRecord(String ruleId, String name, int version, String status, String type, String entityType,
                             int scheduleSec, Map<String, Object> definition, LocalDateTime lastEvaluatedTo,
                             LocalDateTime nextRunAt, int consecutiveFailures, LocalDateTime updatedAt) {
    }

    public record ScenarioRecord(String scenarioId, String name, int version, String status, String entityType,
                                 Map<String, Object> graph, int maxSpanSec, String pythonCode, String codeSha256,
                                 String generatorVersion, LocalDateTime updatedAt) {
        public int suppressSec() {
            return Kst.parseDuration(graph.getOrDefault("suppress_for", "6h"));
        }

        public ScenarioProgram program() {
            return new ScenarioProgram(scenarioId, version, pythonCode, codeSha256, false);
        }
    }
}
