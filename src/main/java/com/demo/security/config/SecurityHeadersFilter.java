package com.demo.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Voegt verplichte security headers toe conform de NL GOV API Design Rules.
 *
 * Referentie: ADR v2.1.0 sectie 3.8 (Transport Security) en
 *             NL GOV API Design Rules — Transport Security module.
 *
 * Verplichte headers:
 *  - Cache-Control: no-store         — voorkom caching van gevoelige data
 *  - Content-Security-Policy         — clickjacking bescherming
 *  - Strict-Transport-Security       — vereis HTTPS (in productie)
 *  - X-Content-Type-Options: nosniff — voorkom MIME sniffing
 *  - X-Frame-Options: DENY           — clickjacking bescherming
 *  - API-Version                     — volledige versie in response header (ADR)
 */
@Component
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private static final String API_VERSION = "1.0.0";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

        // H2 console heeft sameOrigin nodig voor iframe — andere paden krijgen DENY
        String uri = request.getRequestURI();
        if (!uri.startsWith("/h2-console")) {
            response.setHeader("X-Frame-Options", "DENY");
            response.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
        }

        // ADR: API-Version header in alle /v1/ responses
        if (uri.startsWith("/v1/")) {
            response.setHeader("API-Version", API_VERSION);
        }

        filterChain.doFilter(request, response);
    }
}
