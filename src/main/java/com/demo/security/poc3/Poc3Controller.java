package com.demo.security.poc3;

import com.demo.security.crypto.CryptoUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 3 — AES-GCM + HMAC zoekindex
 *
 * POST /v1/poc-3             { "vertrouwelijk": "geheim", "openbaar": "zichtbaar" }
 * GET  /v1/poc-3             Lijst van alle records
 * GET  /v1/poc-3?value=      Zoeken via HMAC-index
 * GET  /v1/poc-3/{id}        Enkel record
 *
 * ADR: zoekfilter als query-parameter op de collectie.
 */
@RestController
@RequestMapping("/v1/poc-3")
public class Poc3Controller {

    private final Poc3Repository repo;

    @Value("${encryption.hmac-secret}")
    private String hmacSecret;

    private byte[] hmacKey;

    public Poc3Controller(Poc3Repository repo) {
        this.repo = repo;
    }

    @PostConstruct
    public void init() {
        this.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc3Entity opslaan(@RequestBody Request req) {
        Poc3Entity entity = new Poc3Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        entity.setVertrouwelijkHmac(CryptoUtil.hmacBase64(req.vertrouwelijk(), hmacKey));
        entity.setOpenbaar(req.openbaar());
        return repo.save(entity);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc3Entity> ophalen(@PathVariable Long id) {
        return repo.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Lijst alle records, of zoek via HMAC-index als ?value= opgegeven.
     * HMAC van de zoekterm wordt berekend en vergeleken met de opgeslagen index.
     */
    @GetMapping
    public List<Poc3Entity> lijst(@RequestParam(required = false) String value) {
        if (value != null) {
            String hmac = CryptoUtil.hmacBase64(value, hmacKey);
            return repo.findByVertrouwelijkHmac(hmac);
        }
        return repo.findAll();
    }
}
