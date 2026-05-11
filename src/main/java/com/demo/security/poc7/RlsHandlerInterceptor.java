package com.demo.security.poc7;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Zet de RLS-context vóór elke request, ruimt op na afloop.
 *
 * Productie-equivalent (PostgreSQL + Spring):
 *   String userId = jwtToken.getSubject();   // uit SecurityContextHolder
 *   jdbcTemplate.update("SET LOCAL app.current_user_id = ?", userId);
 *
 * Hier simuleren we dat met een ThreadLocal zodat H2 geen echte sessievariabelen nodig heeft.
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
