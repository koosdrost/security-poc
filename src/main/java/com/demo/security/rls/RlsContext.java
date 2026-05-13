package com.demo.security.rls;

/**
 * ThreadLocal-wrapper voor de eigenaar-id van de huidige request.
 *
 * <p>Simuleert de PostgreSQL sessievariabele {@code app.current_user_id}:
 * <pre>{@code SET LOCAL app.current_user_id = 'gebruiker-1';}</pre>
 *
 * <p>De waarde wordt gezet door {@link RlsHandlerInterceptor} vanuit de
 * {@code X-Eigenaar-Id} HTTP-header en geruimd na afloop van de request.
 * In productie vervangt de JWT {@code sub}-claim de header.
 */
public class RlsContext {

    private static final ThreadLocal<String> EIGENAAR = new ThreadLocal<>();

    public static void set(String eigenaarId) { EIGENAAR.set(eigenaarId); }
    public static String get()               { return EIGENAAR.get(); }
    public static void clear()               { EIGENAAR.remove(); }
}
