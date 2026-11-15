package com.scenarioalert.engine.common;

import java.util.List;
import java.util.Map;

/**
 * API 오류. 응답 본문은 {"detail": ..., "errors": [...], "warnings": [...]} 로 관리 화면(api.ts)이 읽는 형식이다.
 */
public class ApiException extends RuntimeException {
    private final int status;
    private final List<Map<String, String>> errors;
    private final List<Map<String, String>> warnings;

    public ApiException(int status, String detail) {
        this(status, detail, List.of(), List.of());
    }

    public ApiException(int status, String detail, List<Map<String, String>> errors, List<Map<String, String>> warnings) {
        super(detail);
        this.status = status;
        this.errors = errors;
        this.warnings = warnings;
    }

    public int status() {
        return status;
    }

    public List<Map<String, String>> errors() {
        return errors;
    }

    public List<Map<String, String>> warnings() {
        return warnings;
    }

    public static ApiException notFound(String what) {
        return new ApiException(404, "찾을 수 없습니다: " + what);
    }

    public static ApiException conflict(String msg) {
        return new ApiException(409, msg);
    }

    public static ApiException badRequest(String msg) {
        return new ApiException(400, msg);
    }
}
