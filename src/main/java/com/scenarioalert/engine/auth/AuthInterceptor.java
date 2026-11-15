package com.scenarioalert.engine.auth;

import com.scenarioalert.engine.common.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * /api/v1 요청의 인증·권한 검사. 모든 API 메서드는 {@link RequireRole} 을 가져야 한다 (없으면 거부: 실수로 열어 두지 않도록).
 * 인증된 사용자는 컨트롤러 인자 {@link AuthService.User} 로 받는다.
 */
@Component
public class AuthInterceptor implements HandlerInterceptor, HandlerMethodArgumentResolver {
    static final String ATTR = "auth.user";
    private final AuthService auth;

    public AuthInterceptor(AuthService auth) {
        this.auth = auth;
    }

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) {
        if (!(handler instanceof HandlerMethod hm)) {
            return true;
        }
        if (!hm.getBeanType().getPackageName().startsWith("com.scenarioalert.engine")) {
            return true;  // springdoc 등
        }
        RequireRole rr = hm.getMethodAnnotation(RequireRole.class);
        if (rr == null) {
            throw new ApiException(403, "권한 설정이 없는 API 입니다");
        }
        String need = rr.value();
        if ("none".equals(need)) {
            return true;
        }
        String authz = req.getHeader("Authorization");
        if ("service".equals(need)) {
            auth.checkServiceToken(authz);
            return true;
        }
        AuthService.User u = auth.authenticate(authz);
        if (!"any".equals(need) && !u.has(need)) {
            throw new ApiException(403, need + " 이상 권한이 필요합니다");
        }
        req.setAttribute(ATTR, u);
        return true;
    }

    @Override
    public boolean supportsParameter(MethodParameter p) {
        return p.getParameterType().equals(AuthService.User.class);
    }

    @Override
    public Object resolveArgument(MethodParameter p, ModelAndViewContainer mav, NativeWebRequest req,
                                  WebDataBinderFactory bf) {
        Object u = req.getAttribute(ATTR, NativeWebRequest.SCOPE_REQUEST);
        if (u == null) {
            throw new ApiException(401, "로그인이 필요합니다");
        }
        return u;
    }
}
