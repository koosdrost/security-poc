package com.demo.security.poc3;

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

/** Vult poc3 met 10.000 records voor performance vergelijking. */
@Component
@Order(13)
public class Poc3DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(Poc3DataSeeder.class);

    private final Poc3Repository repo;
    private final byte[] hmacKey;

    public Poc3DataSeeder(Poc3Repository repo,
                          @Value("${encryption.hmac-secret}") String hmacSecret) {
        this.repo    = repo;
        this.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    @Override
    public void run(String... args) {
        if (repo.count() > 0) return;

        log.info("POC 3 seeder: aanmaken van {} records...", SeedHelper.TOTAAL);
        long start = System.currentTimeMillis();

        List<Poc3Entity> batch = new ArrayList<>(SeedHelper.BATCH);
        for (int i = 0; i < SeedHelper.TOTAAL; i++) {
            String waarde = SeedHelper.vertrouwelijk(i);
            Poc3Entity e = new Poc3Entity();
            e.setVertrouwelijk(waarde);
            e.setVertrouwelijkHmac(CryptoUtil.hmacBase64(waarde, hmacKey));
            e.setOpenbaar("record-" + i);
            batch.add(e);
            if (batch.size() == SeedHelper.BATCH) {
                repo.saveAll(batch);
                batch.clear();
            }
        }
        if (!batch.isEmpty()) repo.saveAll(batch);

        log.info("POC 3 seeder: klaar in {} ms.", System.currentTimeMillis() - start);
    }
}
