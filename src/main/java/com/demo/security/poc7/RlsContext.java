package com.demo.security.poc7;

/**
 * Simuleert de PostgreSQL sessievariabele app.current_user_id.
 *
 * PostgreSQL: SET LOCAL app.current_user_id = ?
 * Hier:       RlsContext.set(userId)
 *
 * In productie: gelezen uit JWT sub-claim via SecurityContextHolder.
 */
public class RlsContext {

    private static final ThreadLocal<String> EIGENAAR = new ThreadLocal<>();

    public static void set(String eigenaarId) { EIGENAAR.set(eigenaarId); }
    public static String get()               { return EIGENAAR.get(); }
    public static void clear()               { EIGENAAR.remove(); }
}
