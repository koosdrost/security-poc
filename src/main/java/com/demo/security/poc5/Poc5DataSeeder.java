package com.demo.security.poc5;

import com.demo.security.crypto.CryptoUtil;
import com.demo.security.seeder.SeedHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** Vult poc5 met 10.000 records voor performance vergelijking. */
@Component
@Order(15)
public class Poc5DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(Poc5DataSeeder.class);

    private final Poc5Repository repo;
    private final byte[] hmacKey;

    public Poc5DataSeeder(Poc5Repository repo,
                          @Value("${encryption.hmac-secret}") String hmacSecret) {
        this.repo    = repo;
        this.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    @Override
    public void run(String... args) {
        if (repo.count() > 0) return;

        log.info("POC 5 seeder: aanmaken van {} records...", SeedHelper.TOTAAL);
        long start = System.currentTimeMillis();

        List<Poc5Entity> batch = new ArrayList<>(SeedHelper.BATCH);
        for (int i = 0; i < SeedHelper.TOTAAL; i++) {
            String naam    = SeedHelper.naam(i);
            String notitie = SeedHelper.notitie(i);
            Poc5Entity e = new Poc5Entity();
            e.setNaam(naam);
            e.setNotitie(notitie);
            e.setNotitieHmac(CryptoUtil.hmacBase64(notitie, hmacKey));
            e.setReferentie("ref-" + i);
            e.setOpenbaar("record-" + i);
            batch.add(e);
            if (batch.size() == SeedHelper.BATCH) {
                repo.saveAll(batch);
                batch.clear();
            }
        }
        if (!batch.isEmpty()) repo.saveAll(batch);

        log.info("POC 5 seeder: klaar in {} ms.", System.currentTimeMillis() - start);
    }
}
