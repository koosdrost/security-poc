package com.demo.security.config;

import com.demo.security.poc4.H2EncryptFunctions;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Registreert H2 custom SQL functies (ENCRYPT_STRING / DECRYPT_STRING) en initialiseert de KEK.
 *
 * Gebruikt @PostConstruct zodat zowel de kek als de SQL-aliassen beschikbaar zijn
 * vóórdat Hibernate zijn eerste statement voorbereidt en vóórdat CommandLineRunner-beans draaien.
 *
 * Referentie: CLAUDE.md 4.2
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
            "\"com.demo.security.poc4.H2EncryptFunctions.encryptString\"");

        jdbcTemplate.execute(
            "CREATE ALIAS IF NOT EXISTS DECRYPT_STRING FOR " +
            "\"com.demo.security.poc4.H2EncryptFunctions.decryptString\"");
    }
}
