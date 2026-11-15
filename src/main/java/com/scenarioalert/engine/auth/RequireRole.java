package com.scenarioalert.engine.auth;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 최소 역할 (viewer &lt; analyst &lt; author &lt; admin). 컨트롤러 메서드에 붙인다.
 * "none" 이면 인증 없이 호출할 수 있다 (로그인, 상태 점검). "service" 는 사고처리 시스템 서비스 토큰.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRole {
    String value();
}
