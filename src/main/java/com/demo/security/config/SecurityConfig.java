package com.demo.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource Server configuratie conform het NL GOV OAuth 2.0 profiel.
 *
 * <p>Tokens worden verwacht als {@code Authorization: Bearer <jwt>} header (RFC 9068).
 * Transport via query parameters is verboden per NL GOV OAuth profiel.
 *
 * <p><strong>POC-afwijking:</strong> {@code anyRequest().permitAll()} — endpoints zijn
 * in deze demo-omgeving bereikbaar zonder geldig token zodat curl/Postman-tests eenvoudig
 * zijn. In productie vervangen door {@code .authenticated()} of scope-checks per endpoint.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {
        http
            // REST API is stateless (Bearer tokens) — CSRF niet van toepassing.
            // H2-console krijgt sameOrigin frame-toegang.
            .csrf(csrf -> csrf.disable())
            .headers(headers -> headers
                .frameOptions(fo -> fo.sameOrigin()))
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll());
        return http.build();
    }
}
