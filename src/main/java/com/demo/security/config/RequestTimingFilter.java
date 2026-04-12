package com.demo.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Logt de duur van elke HTTP-aanroep op /v1/**.
 *
 * Formaat: METHOD URI[?query] → status duurMs ms
 * Voorbeeld: GET /v1/poc-6/_perf?operatie=lijst → 200 (143 ms)
 */
@Component
@Order(1)
public class RequestTimingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger("REQUEST_TIMING");

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/v1/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        long start = System.nanoTime();
        try {
            filterChain.doFilter(request, response);
        } finally {
            long duurMs = (System.nanoTime() - start) / 1_000_000;
            String query = request.getQueryString();
            String uri   = query != null
                ? request.getRequestURI() + "?" + query
                : request.getRequestURI();

            log.info("{} {} → {} ({} ms)",
                request.getMethod(),
                uri,
                response.getStatus(),
                duurMs);
        }
    }
}
