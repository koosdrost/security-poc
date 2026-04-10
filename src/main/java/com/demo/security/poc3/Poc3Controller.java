package com.demo.security.poc3;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
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
    private final AuditService audit;

    @Value("${encryption.hmac-secret}")
    private String hmacSecret;

    private byte[] hmacKey;

    public Poc3Controller(Poc3Repository repo, AuditService audit) {
        this.repo = repo;
        this.audit = audit;
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
        Poc3Entity saved = repo.save(entity);
        audit.success(Event.DATA_WRITE, "poc-3/" + saved.getId(), "openbaar=" + req.openbaar());
        return saved;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc3Entity> ophalen(@PathVariable Long id) {
        return repo.findById(id)
            .map(entity -> {
                audit.success(Event.DATA_READ, "poc-3/" + id, "openbaar=" + entity.getOpenbaar());
                return ResponseEntity.ok(entity);
            })
            .orElseGet(() -> {
                audit.failure(Event.DATA_READ, "poc-3/" + id, "NotFound", "record niet gevonden");
                return ResponseEntity.notFound().build();
            });
    }

    /**
     * Lijst alle records, of zoek via HMAC-index als ?value= opgegeven.
     * HMAC van de zoekterm wordt berekend en vergeleken met de opgeslagen index.
     * Let op: de zoekterm zelf wordt NIET gelogd (zou plaintext data bevatten).
     */
    @GetMapping
    public List<Poc3Entity> lijst(@RequestParam(required = false) String value) {
        if (value != null) {
            String hmac = CryptoUtil.hmacBase64(value, hmacKey);
            List<Poc3Entity> result = repo.findByVertrouwelijkHmac(hmac);
            audit.success(Event.DATA_SEARCH, "poc-3", "aantalResultaten=" + result.size());
            return result;
        }
        List<Poc3Entity> result = repo.findAll();
        audit.success(Event.DATA_READ, "poc-3/lijst", "aantalRecords=" + result.size());
        return result;
    }
}
