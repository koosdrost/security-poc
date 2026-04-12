package com.demo.security.poc6;

import com.demo.security.crypto.CryptoUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Vult de poc6-tabel met 10.000 records voor performance testing.
 * Draait alleen als de tabel leeg is (idempotent).
 *
 * Namen en notities worden gevarieerd zodat zoekresultaten realistisch zijn:
 *   - 100 unieke namen × 100 unieke notities = 10.000 combinaties
 *   - Elke naam komt dus ~100 keer voor → zoeken geeft een realistische resultaatset
 *
 * Inserts gebeuren in batches van 500 via saveAll() om Hibernate batch inserts te benutten.
 */
@Component
@Order(2)  // na H2FunctionRegistrar (Order 1 impliciet via CommandLineRunner volgorde)
public class Poc6DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(Poc6DataSeeder.class);

    private static final int TOTAAL         = 10_000;
    private static final int BATCH_GROOTTE  = 500;
    private static final int UNIEKE_NAMEN   = 100;
    private static final int UNIEKE_NOTITIES = 100;

    private final Poc6Repository repo;
    private final byte[] hmacKey;

    private static final String[] VOORNAMEN = {
        "Emma", "Noah", "Olivia", "Liam", "Ava", "Elijah", "Sophia", "James",
        "Isabella", "Oliver", "Mia", "Benjamin", "Charlotte", "Lucas", "Amelia",
        "Mason", "Harper", "Ethan", "Evelyn", "Alexander"
    };

    private static final String[] ACHTERNAMEN = {
        "de Vries", "van den Berg", "Jansen", "Bakker", "Visser",
        "Smit", "Meijer", "de Boer", "Mulder", "van der Linden",
        "de Groot", "Bos", "Vos", "Peters", "Hendriks",
        "van Leeuwen", "Dekker", "Brouwer", "de Wit", "Dijkstra"
    };

    private static final String[] NOTITIE_TEMPLATES = {
        "Vertrouwelijk dossier nummer %d",
        "Medische notitie %d",
        "Financieel rapport Q%d",
        "Interne memo %d",
        "Beveiligingsincident %d",
        "Klachtdossier %d",
        "Contractnummer %d",
        "Projectcode %d",
        "Casusnummer %d",
        "Referentiedocument %d"
    };

    public Poc6DataSeeder(Poc6Repository repo,
                          @Value("${encryption.hmac-secret}") String hmacSecret) {
        this.repo   = repo;
        this.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    @Override
    public void run(String... args) {
        if (repo.count() > 0) {
            log.info("POC 6 seeder: tabel bevat al {} records, seeding overgeslagen.", repo.count());
            return;
        }

        log.info("POC 6 seeder: aanmaken van {} records...", TOTAAL);
        long start = System.currentTimeMillis();

        Random rng = new Random(42);  // vaste seed → reproduceerbaar
        List<Poc6Entity> batch = new ArrayList<>(BATCH_GROOTTE);

        for (int i = 0; i < TOTAAL; i++) {
            String naam    = naamVoor(i % UNIEKE_NAMEN);
            String notitie = notitieVoor(i % UNIEKE_NOTITIES, rng);

            Poc6Entity e = new Poc6Entity();
            e.setNaam(naam);
            e.setNaamHmac(CryptoUtil.hmacBase64(naam, hmacKey));
            e.setNotitie(notitie);
            e.setNotitieHmac(CryptoUtil.hmacBase64(notitie, hmacKey));
            e.setOpenbaar("record-" + i);
            batch.add(e);

            if (batch.size() == BATCH_GROOTTE) {
                repo.saveAll(batch);
                batch.clear();
            }
        }
        if (!batch.isEmpty()) {
            repo.saveAll(batch);
        }

        long duur = System.currentTimeMillis() - start;
        log.info("POC 6 seeder: {} records aangemaakt in {} ms ({} ms/record gemiddeld).",
            TOTAAL, duur, duur / TOTAAL);
    }

    private String naamVoor(int index) {
        return VOORNAMEN[index % VOORNAMEN.length] + " " + ACHTERNAMEN[index % ACHTERNAMEN.length];
    }

    private String notitieVoor(int index, Random rng) {
        String template = NOTITIE_TEMPLATES[index % NOTITIE_TEMPLATES.length];
        return String.format(template, index + 1);
    }
}
