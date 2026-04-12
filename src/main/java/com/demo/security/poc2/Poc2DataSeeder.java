package com.demo.security.poc2;

import com.demo.security.seeder.SeedHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** Vult poc2 met 10.000 records voor performance vergelijking. */
@Component
@Order(12)
public class Poc2DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(Poc2DataSeeder.class);

    private final Poc2Repository repo;

    public Poc2DataSeeder(Poc2Repository repo) {
        this.repo = repo;
    }

    @Override
    public void run(String... args) {
        if (repo.count() > 0) return;

        log.info("POC 2 seeder: aanmaken van {} records...", SeedHelper.TOTAAL);
        long start = System.currentTimeMillis();

        List<Poc2Entity> batch = new ArrayList<>(SeedHelper.BATCH);
        for (int i = 0; i < SeedHelper.TOTAAL; i++) {
            Poc2Entity e = new Poc2Entity();
            e.setVertrouwelijk(SeedHelper.vertrouwelijk(i));
            e.setOpenbaar("record-" + i);
            batch.add(e);
            if (batch.size() == SeedHelper.BATCH) {
                repo.saveAll(batch);
                batch.clear();
            }
        }
        if (!batch.isEmpty()) repo.saveAll(batch);

        log.info("POC 2 seeder: klaar in {} ms.", System.currentTimeMillis() - start);
    }
}
