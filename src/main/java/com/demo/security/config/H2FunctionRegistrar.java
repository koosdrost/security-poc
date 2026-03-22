package com.demo.security.config;

import com.demo.security.crypto.CryptoUtil;
import com.demo.security.poc4.H2EncryptFunctions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Registreert H2 custom SQL functies (ENCRYPT_STRING / DECRYPT_STRING) bij opstarten.
 * Loopt na context refresh maar vóór HTTP verkeer — timing is gegarandeerd veilig.
 *
 * Referentie: CLAUDE.md 4.2
 */
@Component
public class H2FunctionRegistrar implements CommandLineRunner {

    private final JdbcTemplate jdbcTemplate;

    @Value("${encryption.kek}")
    private String kekPassphrase;

    public H2FunctionRegistrar(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(String... args) {
        // Stel de sleutel in op de static utility class zodat H2-functies er gebruik van kunnen maken
        H2EncryptFunctions.kek = CryptoUtil.deriveKey(kekPassphrase);

        // Registreer de H2 aliases (idempotent via IF NOT EXISTS)
        jdbcTemplate.execute(
            "CREATE ALIAS IF NOT EXISTS ENCRYPT_STRING FOR " +
            "\"com.demo.security.poc4.H2EncryptFunctions.encryptString\"");

        jdbcTemplate.execute(
            "CREATE ALIAS IF NOT EXISTS DECRYPT_STRING FOR " +
            "\"com.demo.security.poc4.H2EncryptFunctions.decryptString\"");
    }
}
