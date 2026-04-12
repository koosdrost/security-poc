package com.demo.security.poc4;

import com.demo.security.seeder.SeedHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** Vult poc4 met 10.000 records voor performance vergelijking. */
@Component
@Order(14)
public class Poc4DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(Poc4DataSeeder.class);

    private final Poc4Repository repo;

    public Poc4DataSeeder(Poc4Repository repo) {
        this.repo = repo;
    }

    @Override
    public void run(String... args) {
        if (repo.count() > 0) return;

        log.info("POC 4 seeder: aanmaken van {} records...", SeedHelper.TOTAAL);
        long start = System.currentTimeMillis();

        List<Poc4Entity> batch = new ArrayList<>(SeedHelper.BATCH);
        for (int i = 0; i < SeedHelper.TOTAAL; i++) {
            Poc4Entity e = new Poc4Entity();
            e.setVertrouwelijk(SeedHelper.vertrouwelijk(i));
            e.setOpenbaar("record-" + i);
            batch.add(e);
            if (batch.size() == SeedHelper.BATCH) {
                repo.saveAll(batch);
                batch.clear();
            }
        }
        if (!batch.isEmpty()) repo.saveAll(batch);

        log.info("POC 4 seeder: klaar in {} ms.", System.currentTimeMillis() - start);
    }
}
