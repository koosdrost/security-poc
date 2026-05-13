package com.demo.security.config;

import com.demo.security.crypto.H2EncryptFunctions;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Registreert H2 custom SQL-functies ENCRYPT_STRING / DECRYPT_STRING.
 *
 * H2 laadt {@link com.demo.security.crypto.H2EncryptFunctions} via zijn eigen classloader,
 * waardoor Spring-injectie niet werkt. De KEK-passphrase wordt daarom via een system property
 * doorgegeven zodat hij over classloader-grenzen beschikbaar is.
 *
 * Gebruikt @PostConstruct zodat de functies beschikbaar zijn vóórdat Hibernate zijn eerste
 * statement voorbereidt én vóórdat CommandLineRunner-seeders draaien.
 *
 * Productie-equivalent: PostgreSQL pgcrypto functies encrypt_string / decrypt_string.
 */
@Component
public class H2FunctionRegistrar {

    private final JdbcTemplate jdbcTemplate;

    @Value("${encryption.kek}")
    private String kekPassphrase;

    public H2FunctionRegistrar(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostConstruct
    public void initialiseer() {
        // Passphrase via sysprop beschikbaar stellen voor H2's classloader-instantie van H2EncryptFunctions
        System.setProperty(H2EncryptFunctions.SYSPROP, kekPassphrase);

        // Registreer de H2 aliases (idempotent via IF NOT EXISTS)
        jdbcTemplate.execute(
            "CREATE ALIAS IF NOT EXISTS ENCRYPT_STRING FOR " +
            "\"com.demo.security.crypto.H2EncryptFunctions.encryptString\"");

        jdbcTemplate.execute(
            "CREATE ALIAS IF NOT EXISTS DECRYPT_STRING FOR " +
            "\"com.demo.security.crypto.H2EncryptFunctions.decryptString\"");
    }
}
