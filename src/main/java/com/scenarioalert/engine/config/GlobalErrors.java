package com.scenarioalert.engine.config;

import com.scenarioalert.engine.ch.ClickHouse.ClickHouseException;
import com.scenarioalert.engine.common.ApiException;
import com.scenarioalert.engine.scenario.GraphValidation.GraphValidationException;
import com.scenarioalert.engine.scenario.PythonScenarioEngine.ScenarioEngineException;
import com.scenarioalert.engine.singlerule.RuleValidator.RuleValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 오류 응답: {"detail": ..., "errors": [...], "warnings": [...]} (관리 화면 api.ts 형식). */
@RestControllerAdvice
public class GlobalErrors {
    private static final Logger log = LoggerFactory.getLogger(GlobalErrors.class);

    private static ResponseEntity<Map<String, Object>> body(int status, String detail, List<?> errors, List<?> warnings) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("detail", detail);
        if (errors != null) {
            m.put("errors", errors);
        }
        if (warnings != null) {
            m.put("warnings", warnings);
        }
        return ResponseEntity.status(status).body(m);
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> api(ApiException e) {
        return body(e.status(), e.getMessage(), e.errors().isEmpty() ? null : e.errors(),
                e.warnings().isEmpty() ? null : e.warnings());
    }

    @ExceptionHandler(RuleValidationException.class)
    public ResponseEntity<Map<String, Object>> rule(RuleValidationException e) {
        return body(422, "이벤트 탐지모듈 정의가 올바르지 않습니다", e.result.errorMaps(), e.result.warningMaps());
    }

    @ExceptionHandler(GraphValidationException.class)
    public ResponseEntity<Map<String, Object>> graph(GraphValidationException e) {
        return body(422, "순서도가 올바르지 않습니다", e.result.errorMaps(), e.result.warningMaps());
    }

    @ExceptionHandler(ClickHouseException.class)
    public ResponseEntity<Map<String, Object>> ch(ClickHouseException e) {
        log.warn("clickhouse error: {}", e.getMessage());
        return body(502, "ClickHouse 오류: " + e.getMessage(), null, null);
    }

    @ExceptionHandler(ScenarioEngineException.class)
    public ResponseEntity<Map<String, Object>> py(ScenarioEngineException e) {
        log.warn("scenario engine error: {}", e.getMessage());
        return body(503, "시나리오 평가(Python) 오류: " + e.getMessage(), null, null);
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MissingServletRequestParameterException.class,
            MethodArgumentTypeMismatchException.class, MissingServletRequestPartException.class})
    public ResponseEntity<Map<String, Object>> badRequest(Exception e) {
        return body(422, "요청 형식이 올바르지 않습니다",
                List.of(Map.of("path", "", "message", String.valueOf(e.getMessage()))), null);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> method(HttpRequestMethodNotSupportedException e) {
        return body(405, e.getMessage(), null, null);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> notFound(NoResourceFoundException e) {
        return body(404, "Not Found", null, null);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> other(Exception e) {
        log.error("unhandled", e);
        return body(500, "서버 오류: " + e.getMessage(), null, null);
    }
}
