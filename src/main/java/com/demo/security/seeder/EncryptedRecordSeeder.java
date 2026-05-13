package com.demo.security.seeder;

import com.demo.security.crypto.CryptoUtil;
import com.demo.security.domain.EncryptedRecord;
import com.demo.security.repository.EncryptedRecordRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Vult de poc6-tabel met 10.000 records voor performance testing.
 * Idempotent: wordt overgeslagen als de tabel al gevuld is.
 *
 * <p>Records worden verdeeld over 3 eigenaren zodat RLS-isolatie direct zichtbaar is:
 * <ul>
 *   <li>{@code gebruiker-1} — records 0, 3, 6, ... (~3.334 records)</li>
 *   <li>{@code gebruiker-2} — records 1, 4, 7, ... (~3.333 records)</li>
 *   <li>{@code gebruiker-3} — records 2, 5, 8, ... (~3.333 records)</li>
 * </ul>
 *
 * <p>100 unieke namen × 100 unieke notities = 10.000 combinaties.
 * Zoeken op een naam geeft ~100 totale resultaten, waarvan ~33 per eigenaar.
 */
@Component
@Order(10)  // na H2FunctionRegistrar (@PostConstruct) zodat ENCRYPT_STRING beschikbaar is
public class EncryptedRecordSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(EncryptedRecordSeeder.class);

    private static final int TOTAAL          = 10_000;
    private static final int BATCH_GROOTTE   = 500;
    private static final int UNIEKE_NAMEN    = 100;
    private static final int UNIEKE_NOTITIES = 100;

    private static final String[] EIGENAREN = {"gebruiker-1", "gebruiker-2", "gebruiker-3"};

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
        "Vertrouwelijk dossier nummer %d", "Medische notitie %d",
        "Financieel rapport Q%d",          "Interne memo %d",
        "Beveiligingsincident %d",         "Klachtdossier %d",
        "Contractnummer %d",               "Projectcode %d",
        "Casusnummer %d",                  "Referentiedocument %d"
    };

    private final EncryptedRecordRepository repo;
    private final byte[] hmacKey;

    public EncryptedRecordSeeder(EncryptedRecordRepository repo,
                                 @Value("${encryption.hmac-secret}") String hmacSecret) {
        this.repo    = repo;
        this.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    @Override
    public void run(String... args) {
        if (repo.count() > 0) {
            log.info("EncryptedRecord seeder: tabel al gevuld ({} records), overgeslagen.", repo.count());
            return;
        }

        log.info("EncryptedRecord seeder: aanmaken van {} records voor {} eigenaren...",
            TOTAAL, EIGENAREN.length);
        long start = System.currentTimeMillis();
        List<EncryptedRecord> batch = new ArrayList<>(BATCH_GROOTTE);

        for (int i = 0; i < TOTAAL; i++) {
            String naam      = naamVoor(i % UNIEKE_NAMEN);
            String notitie   = notitieVoor(i % UNIEKE_NOTITIES);
            String eigenaarId = EIGENAREN[i % EIGENAREN.length];

            EncryptedRecord r = new EncryptedRecord();
            r.setEigenaarId(eigenaarId);
            r.setNaam(naam);
            r.setNaamHmac(CryptoUtil.hmacBase64(naam, hmacKey));
            r.setNotitie(notitie);
            r.setNotitieHmac(CryptoUtil.hmacBase64(notitie, hmacKey));
            r.setOpenbaar("record-" + i);
            batch.add(r);

            if (batch.size() == BATCH_GROOTTE) {
                repo.saveAll(batch);
                batch.clear();
            }
        }
        if (!batch.isEmpty()) repo.saveAll(batch);

        long duur = System.currentTimeMillis() - start;
        log.info("EncryptedRecord seeder: {} records aangemaakt in {} ms.", TOTAAL, duur);
    }

    private String naamVoor(int index) {
        return VOORNAMEN[index % VOORNAMEN.length] + " " + ACHTERNAMEN[index % ACHTERNAMEN.length];
    }

    private String notitieVoor(int index) {
        return String.format(NOTITIE_TEMPLATES[index % NOTITIE_TEMPLATES.length], index + 1);
    }
}
