package com.scenarioalert.engine.common;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 시각과 기간. 모든 시각은 한국 시간(Asia/Seoul) 기준 LocalDateTime(naive)으로 다룬다.
 * ClickHouse 의 Asia/Seoul, MariaDB 세션 time_zone='+09:00' 과 맞춘다.
 */
public final class Kst {
    public static final ZoneId ZONE = ZoneId.of("Asia/Seoul");
    public static final ZoneOffset OFFSET = ZoneOffset.ofHours(9);
    private static final DateTimeFormatter PARAM = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
    private static final DateTimeFormatter NAIVE_ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");
    private static final Pattern DUR = Pattern.compile("^(\\d+)\\s*([smhd])$");

    private Kst() {
    }

    public static LocalDateTime now() {
        return LocalDateTime.now(ZONE).truncatedTo(ChronoUnit.MILLIS);
    }

    /** ClickHouse·MariaDB 파라미터용 문자열 (밀리초). */
    public static String fmt(LocalDateTime t) {
        return t.format(PARAM);
    }

    /** 화면·전달용: +09:00 ISO 문자열. */
    public static String iso(LocalDateTime t) {
        return t == null ? null : t.atOffset(OFFSET).format(ISO);
    }

    /** Python 시나리오 런타임과 주고받는 형식 (시간대 없는 ISO, 밀리초). */
    public static String naiveIso(LocalDateTime t) {
        return t == null ? null : t.format(NAIVE_ISO);
    }

    /**
     * 문자열 시각 해석. "2026-11-13T10:00:00+09:00", "...Z", "2026-11-13 10:00:00.000", "2026-11-13T10:00" 모두 받는다.
     * 시간대가 있으면 KST 로 바꾼다.
     */
    public static LocalDateTime parse(String v) {
        if (v == null || v.isBlank()) {
            return null;
        }
        String s = v.trim().replace(' ', 'T');
        try {
            if (s.matches("\\d{4}-\\d\\d-\\d\\d")) {
                return java.time.LocalDate.parse(s).atStartOfDay();
            }
            if (s.endsWith("Z") || s.matches(".*[+-]\\d\\d:?\\d\\d$")) {
                return OffsetDateTime.parse(s).atZoneSameInstant(ZONE).toLocalDateTime();
            }
            return LocalDateTime.parse(s);
        } catch (DateTimeParseException e) {
            throw new ApiException(400, "시각 형식이 아닙니다: " + v);
        }
    }

    /** '10m' → 600. 정수는 초로 본다. */
    public static int parseDuration(Object v) {
        if (v instanceof Integer || v instanceof Long) {
            long n = ((Number) v).longValue();
            if (n <= 0) {
                throw new IllegalArgumentException("duration must be positive");
            }
            return (int) n;
        }
        if (!(v instanceof String str)) {
            throw new IllegalArgumentException("잘못된 시간 형식: " + Json.repr(v) + " (예: 30s, 10m, 1h, 1d)");
        }
        Matcher m = DUR.matcher(str.trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("잘못된 시간 형식: " + Json.repr(v) + " (예: 30s, 10m, 1h, 1d)");
        }
        long n = Long.parseLong(m.group(1)) * switch (m.group(2)) {
            case "s" -> 1;
            case "m" -> 60;
            case "h" -> 3600;
            default -> 86400;
        };
        if (n <= 0 || n > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("duration must be positive");
        }
        return (int) n;
    }

    public static int parseDurationOr(Object v, int fallback) {
        try {
            return parseDuration(v);
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }

    public static String formatDuration(int sec) {
        if (sec % 86400 == 0) {
            return sec / 86400 + "d";
        }
        if (sec % 3600 == 0) {
            return sec / 3600 + "h";
        }
        if (sec % 60 == 0) {
            return sec / 60 + "m";
        }
        return sec + "s";
    }

    /** KST 자정 기준으로 step 단위 내림 (step 은 86400 의 약수). */
    public static LocalDateTime floor(LocalDateTime t, int stepSec) {
        LocalDateTime midnight = t.truncatedTo(ChronoUnit.DAYS);
        long s = Duration.between(midnight, t).getSeconds();
        return midnight.plusSeconds(s - s % stepSec);
    }
}
