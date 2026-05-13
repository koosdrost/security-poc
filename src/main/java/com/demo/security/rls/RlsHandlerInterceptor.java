package com.demo.security.rls;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Leest de {@code X-Eigenaar-Id} header en zet deze in de {@link RlsContext}.
 * Ruimt de context op na afloop van de request (altijd, ook bij exceptions).
 */
public class RlsHandlerInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String eigenaarId = request.getHeader("X-Eigenaar-Id");
        if (eigenaarId != null && !eigenaarId.isBlank()) {
            RlsContext.set(eigenaarId);
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        RlsContext.clear();
    }
}
