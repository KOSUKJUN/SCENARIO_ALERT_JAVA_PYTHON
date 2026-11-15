package com.scenarioalert.engine.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scenarioalert.engine.auth.AuthInterceptor;
import com.scenarioalert.engine.common.Json;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final AuthInterceptor auth;

    public WebConfig(AuthInterceptor auth) {
        this.auth = auth;
    }

    /** 응답 직렬화 규칙(시각은 +09:00 ISO)을 API 전체에 쓴다. */
    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        return Json.MAPPER;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(auth).addPathPatterns("/api/**");
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(auth);
    }
}
