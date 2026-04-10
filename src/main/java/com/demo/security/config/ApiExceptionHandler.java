package com.demo.security.config;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;

/**
 * Globale foutafhandeling conform RFC 9457 (application/problem+json).
 *
 * Referentie: NL GOV API Design Rules v2.1.0 — Foutafhandeling
 *  - Gebruik application/problem+json voor alle foutresponses
 *  - Geen technische details (stack traces) in foutmeldingen
 *  - type URI verwijst naar beschrijving van de fout
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    private final AuditService audit;

    public ApiExceptionHandler(AuditService audit) {
        this.audit = audit;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(IllegalArgumentException ex) {
        audit.failure(Event.FAILURE, "api", ex.getClass().getSimpleName(), ex.getMessage());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setType(URI.create("https://example.com/fouten/ongeldig-verzoek"));
        problem.setTitle("Ongeldig verzoek");
        return problem;
    }

    @ExceptionHandler(IllegalStateException.class)
    public ProblemDetail handleIllegalState(IllegalStateException ex) {
        audit.failure(Event.FAILURE, "api", ex.getClass().getSimpleName(), ex.getMessage());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.CONFLICT, ex.getMessage());
        problem.setType(URI.create("https://example.com/fouten/conflictstatus"));
        problem.setTitle("Conflictstatus");
        return problem;
    }
}
