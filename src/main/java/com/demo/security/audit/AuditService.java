package com.demo.security.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * Centrale auditlogging voor data-toegang en sleutelbeheer.
 *
 * Alle gevoelige operaties worden vastgelegd conform GDPR/AVG traceerbaarheid
 * en NEN 7513 logging-eisen. De AUDIT-logger schrijft naar een apart logbestand
 * (zie logback-spring.xml) zodat auditlogs gescheiden kunnen worden bewaard.
 *
 * Wat wordt NOOIT gelogd: plaintext data, sleutelmateriaal, wachtwoorden.
 * Wat wordt WEL gelogd: wie, wat, wanneer, met welk resultaat.
 */
@Service
public class AuditService {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

    public enum Event {
        DATA_WRITE,
        DATA_READ,
        DATA_SEARCH,
        FAILURE
    }

    /** Log een succesvolle operatie. */
    public void success(Event event, String resource, String details) {
        AUDIT.info("event={} principal={} resource={} outcome=SUCCESS details={}",
            event, currentPrincipal(), resource, details);
    }

    /** Log een mislukte operatie (geen stack trace, alleen fouttype + melding). */
    public void failure(Event event, String resource, String errorType, String message) {
        AUDIT.warn("event={} principal={} resource={} outcome=FAILURE error={} message={}",
            event, currentPrincipal(), resource, errorType, message);
    }

    /** Lees de geauthenticeerde gebruiker uit de Security Context. */
    public static String currentPrincipal() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return "anonymous";
        }
        return auth.getName();
    }
}
