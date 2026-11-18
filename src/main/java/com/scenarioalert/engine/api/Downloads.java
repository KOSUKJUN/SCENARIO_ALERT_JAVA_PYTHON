package com.scenarioalert.engine.api;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/** 파일 내려받기 응답. */
final class Downloads {
    private Downloads() {
    }

    static ResponseEntity<byte[]> zip(byte[] body, String fileName) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.parseMediaType("application/zip"));
        h.setContentDisposition(ContentDisposition.attachment().filename(fileName.replaceAll("[^A-Za-z0-9._\\-]", "_")).build());
        h.setContentLength(body.length);
        return ResponseEntity.ok().headers(h).body(body);
    }
}
