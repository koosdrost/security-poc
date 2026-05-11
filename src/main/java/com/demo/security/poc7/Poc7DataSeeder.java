package com.demo.security.poc7;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Seed-data voor 3 gebruikers zodat RLS-isolatie direct zichtbaar is:
 *   gebruiker-1 → 3 records
 *   gebruiker-2 → 2 records
 *   gebruiker-3 → 1 record
 *
 * GET /v1/poc-7 met X-Eigenaar-Id: gebruiker-1 → 3 resultaten
 * GET /v1/poc-7 zonder header       → 0 resultaten
 * GET /v1/poc-7/_admin              → 6 resultaten (alle, geen filter)
 */
@Component
@Order(5)
public class Poc7DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(Poc7DataSeeder.class);

    private final Poc7Repository repo;

    public Poc7DataSeeder(Poc7Repository repo) {
        this.repo = repo;
    }

    @Override
    public void run(String... args) {
        if (repo.count() > 0) return;

        String[][] records = {
            {"gebruiker-1", "Vertrouwelijk dossier A", "openbaar-1a"},
            {"gebruiker-1", "Vertrouwelijk dossier B", "openbaar-1b"},
            {"gebruiker-1", "Vertrouwelijk dossier C", "openbaar-1c"},
            {"gebruiker-2", "Geheim rapport X",        "openbaar-2a"},
            {"gebruiker-2", "Geheim rapport Y",        "openbaar-2b"},
            {"gebruiker-3", "Privé notitie Alpha",     "openbaar-3a"},
        };

        for (String[] row : records) {
            Poc7Entity e = new Poc7Entity();
            e.setEigenaarId(row[0]);
            e.setInhoud(row[1]);
            e.setOpenbaar(row[2]);
            repo.save(e);
        }

        log.info("POC 7 seeder: {} records aangemaakt voor 3 gebruikers.", records.length);
    }
}
