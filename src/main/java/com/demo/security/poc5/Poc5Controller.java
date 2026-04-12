package com.demo.security.poc5;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import com.demo.security.crypto.CryptoUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 5 — Gecombineerde encryptie-strategieën
 *
 * Demonstreert drie encryptie-aanpakken op één entity, zodat de afwegingen
 * direct zichtbaar zijn:
 *
 *   naam        → deterministisch (POC 2 stijl)  — ?naam= voor exact zoeken
 *   notitie     → AES-GCM + HMAC-index (POC 3)   — ?notitie= voor HMAC-zoeken
 *   referentie  → @ColumnTransformer SQL (POC 4)  — geen zoekondersteuning
 *
 * POST /v1/poc-5      { "naam": "...", "notitie": "...", "referentie": "...", "openbaar": "..." }
 * GET  /v1/poc-5      Lijst van alle records
 * GET  /v1/poc-5?naam=          Filter op exacte naam (deterministisch)
 * GET  /v1/poc-5?notitie=       Filter via HMAC-index van notitie
 * GET  /v1/poc-5/{id}           Enkel record
 *
 * ADR: zoekfilters als query-parameters op de collectie.
 */
@RestController
@RequestMapping("/v1/poc-5")
public class Poc5Controller {

    private final Poc5Repository repo;
    private final AuditService audit;

    @Value("${encryption.hmac-secret}")
    private String hmacSecret;

    private byte[] hmacKey;

    public Poc5Controller(Poc5Repository repo, AuditService audit) {
        this.repo = repo;
        this.audit = audit;
    }

    @PostConstruct
    public void init() {
        this.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    record Request(String naam, String notitie, String referentie, String openbaar) {}

    @PostMapping
    public Poc5Entity opslaan(@RequestBody Request req) {
        Poc5Entity entity = new Poc5Entity();
        entity.setNaam(req.naam());
        entity.setNotitie(req.notitie());
        entity.setNotitieHmac(CryptoUtil.hmacBase64(req.notitie(), hmacKey));
        entity.setReferentie(req.referentie());
        entity.setOpenbaar(req.openbaar());
        Poc5Entity saved = repo.save(entity);
        audit.success(Event.DATA_WRITE, "poc-5/" + saved.getId(), "openbaar=" + req.openbaar());
        return saved;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc5Entity> ophalen(@PathVariable Long id) {
        return repo.findById(id)
            .map(entity -> {
                audit.success(Event.DATA_READ, "poc-5/" + id, "openbaar=" + entity.getOpenbaar());
                return ResponseEntity.ok(entity);
            })
            .orElseGet(() -> {
                audit.failure(Event.DATA_READ, "poc-5/" + id, "NotFound", "record niet gevonden");
                return ResponseEntity.notFound().build();
            });
    }

    /**
     * Lijst alle records, of filter via één van de twee zoekstrategieën:
     *
     *   ?naam=     → deterministisch: Hibernate versleutelt zoekterm → ciphertext-vergelijking
     *   ?notitie=  → HMAC-index: HMAC van zoekterm wordt vergeleken met opgeslagen index
     *
     * Beide zoektermen worden NIET gelogd (plaintext gevoelige data).
     * Combineren van ?naam= en ?notitie= geeft voorrang aan ?naam=.
     */
    @GetMapping
    public List<Poc5Entity> lijst(
            @RequestParam(required = false) String naam,
            @RequestParam(required = false) String notitie) {

        if (naam != null) {
            List<Poc5Entity> result = repo.findByNaam(naam);
            audit.success(Event.DATA_SEARCH, "poc-5", "strategie=deterministisch aantalResultaten=" + result.size());
            return result;
        }
        if (notitie != null) {
            String hmac = CryptoUtil.hmacBase64(notitie, hmacKey);
            List<Poc5Entity> result = repo.findByNotitieHmac(hmac);
            audit.success(Event.DATA_SEARCH, "poc-5", "strategie=hmac aantalResultaten=" + result.size());
            return result;
        }
        List<Poc5Entity> result = repo.findAll();
        audit.success(Event.DATA_READ, "poc-5/lijst", "aantalRecords=" + result.size());
        return result;
    }
}
