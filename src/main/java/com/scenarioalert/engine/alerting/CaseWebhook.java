package com.scenarioalert.engine.alerting;

import com.scenarioalert.engine.common.Json;
import com.scenarioalert.engine.config.AppProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * 사고처리 시스템 연동 (REST webhook). 규격이 확정되면 이 클래스만 바꾼다.
 *
 * <p>가정: POST {CASE_WEBHOOK_URL} 에 경보 본문(설계안 9장)을 JSON 으로 보낸다.
 * Authorization: Bearer {CASE_SERVICE_TOKEN}. 응답 JSON 의 case_ref(있으면)를 저장한다.</p>
 */
@Component
public class CaseWebhook {
    private final AppProperties.Case cfg;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    public CaseWebhook(AppProperties props) {
        this.cfg = props.caseSystem();
    }

    public record DeliveryResult(boolean ok, String caseRef, String error) {
    }

    public DeliveryResult deliver(Map<String, Object> payload) {
        if (cfg.webhookUrl() == null || cfg.webhookUrl().isBlank()) {
            return new DeliveryResult(false, null, "CASE_WEBHOOK_URL 미설정");
        }
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(cfg.webhookUrl()))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + (cfg.serviceToken() == null ? "" : cfg.serviceToken()))
                    .POST(HttpRequest.BodyPublishers.ofString(Json.dump(payload), StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (r.statusCode() >= 300) {
                String b = r.body() == null ? "" : r.body();
                return new DeliveryResult(false, null, "HTTP " + r.statusCode() + ": " + (b.length() > 300 ? b.substring(0, 300) : b));
            }
            String ref = null;
            try {
                Map<String, Object> body = Json.loadMap(r.body());
                if (body != null && body.get("case_ref") != null) {
                    ref = String.valueOf(body.get("case_ref"));
                    ref = ref.length() > 64 ? ref.substring(0, 64) : ref;
                }
            } catch (IllegalArgumentException ignored) {
                // 본문이 JSON 이 아니어도 접수는 성공
            }
            return new DeliveryResult(true, ref, null);
        } catch (IOException | IllegalArgumentException e) {
            String m = String.valueOf(e.getMessage());
            return new DeliveryResult(false, null, m.length() > 300 ? m.substring(0, 300) : m);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new DeliveryResult(false, null, "중단됨");
        }
    }
}
