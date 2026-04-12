package com.demo.security.poc6;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import com.demo.security.crypto.CryptoUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

import java.util.List;
import java.util.function.Supplier;

/**
 * POC 6 — Dubbele encryptie (app + DB) met HMAC zoekindex
 *
 * Elk vertrouwelijk veld is dubbel versleuteld:
 *   - AES-GCM via AttributeConverter (Java/app-laag)
 *   - ENCRYPT_STRING via @ColumnTransformer (database-laag)
 *
 * Zoeken werkt via een aparte HMAC-kolom per veld (berekend van de plaintext).
 *
 * POST /v1/poc-6             { "naam": "...", "notitie": "...", "openbaar": "..." }
 * GET  /v1/poc-6             Lijst van alle records
 * GET  /v1/poc-6?naam=       Zoeken via HMAC-index van naam
 * GET  /v1/poc-6?notitie=    Zoeken via HMAC-index van notitie
 * GET  /v1/poc-6/{id}        Enkel record
 *
 * ADR: zoekfilters als query-parameters op de collectie.
 */
@RestController
@RequestMapping("/v1/poc-6")
public class Poc6Controller {

    private final Poc6Repository repo;
    private final AuditService audit;

    @Value("${encryption.hmac-secret}")
    private String hmacSecret;

    private byte[] hmacKey;

    public Poc6Controller(Poc6Repository repo, AuditService audit) {
        this.repo = repo;
        this.audit = audit;
    }

    @PostConstruct
    public void init() {
        this.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    record Request(String naam, String notitie, String openbaar) {}

    @PostMapping
    public Poc6Entity opslaan(@RequestBody Request req) {
        Poc6Entity entity = new Poc6Entity();
        entity.setNaam(req.naam());
        entity.setNaamHmac(CryptoUtil.hmacBase64(req.naam(), hmacKey));
        entity.setNotitie(req.notitie());
        entity.setNotitieHmac(CryptoUtil.hmacBase64(req.notitie(), hmacKey));
        entity.setOpenbaar(req.openbaar());
        Poc6Entity saved = repo.save(entity);
        audit.success(Event.DATA_WRITE, "poc-6/" + saved.getId(), "openbaar=" + req.openbaar());
        return saved;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc6Entity> ophalen(@PathVariable Long id) {
        return repo.findById(id)
            .map(entity -> {
                audit.success(Event.DATA_READ, "poc-6/" + id, "openbaar=" + entity.getOpenbaar());
                return ResponseEntity.ok(entity);
            })
            .orElseGet(() -> {
                audit.failure(Event.DATA_READ, "poc-6/" + id, "NotFound", "record niet gevonden");
                return ResponseEntity.notFound().build();
            });
    }

    /**
     * Performance meting: voer een operatie uit en retourneer timing + metadata.
     *
     * GET /v1/poc-6/_perf?operatie=lijst          — alle records ophalen
     * GET /v1/poc-6/_perf?operatie=zoek-naam&q=   — zoeken op naam via HMAC
     * GET /v1/poc-6/_perf?operatie=zoek-notitie&q= — zoeken op notitie via HMAC
     * GET /v1/poc-6/_perf?operatie=enkel&q=1       — enkel record ophalen op ID
     */
    @GetMapping("/_perf")
    public Map<String, Object> perf(
            @RequestParam String operatie,
            @RequestParam(required = false, defaultValue = "") String q) {

        return gemeten(operatie, switch (operatie) {
            case "lijst"         -> () -> repo.findAll().size();
            case "zoek-naam"     -> () -> repo.findByNaamHmac(CryptoUtil.hmacBase64(q, hmacKey)).size();
            case "zoek-notitie"  -> () -> repo.findByNotitieHmac(CryptoUtil.hmacBase64(q, hmacKey)).size();
            case "enkel"         -> () -> repo.findById(Long.parseLong(q)).isPresent() ? 1 : 0;
            default              -> throw new IllegalArgumentException("Onbekende operatie: " + operatie);
        });
    }

    private Map<String, Object> gemeten(String operatie, Supplier<Integer> actie) {
        long start     = System.currentTimeMillis();
        int  aantal    = actie.get();
        long duurMs    = System.currentTimeMillis() - start;
        long totaal    = repo.count();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("operatie",       operatie);
        result.put("aantalResultaten", aantal);
        result.put("totaalRecords",  totaal);
        result.put("duurMs",         duurMs);
        return result;
    }

    /**
     * Lijst alle records, of zoek via HMAC-index.
     * ?naam= en ?notitie= kunnen niet gecombineerd worden — naam heeft voorrang.
     * Zoektermen worden NIET gelogd (plaintext gevoelige data).
     */
    @GetMapping
    public List<Poc6Entity> lijst(
            @RequestParam(required = false) String naam,
            @RequestParam(required = false) String notitie) {

        if (naam != null) {
            List<Poc6Entity> result = repo.findByNaamHmac(CryptoUtil.hmacBase64(naam, hmacKey));
            audit.success(Event.DATA_SEARCH, "poc-6", "veld=naam aantalResultaten=" + result.size());
            return result;
        }
        if (notitie != null) {
            List<Poc6Entity> result = repo.findByNotitieHmac(CryptoUtil.hmacBase64(notitie, hmacKey));
            audit.success(Event.DATA_SEARCH, "poc-6", "veld=notitie aantalResultaten=" + result.size());
            return result;
        }
        List<Poc6Entity> result = repo.findAll();
        audit.success(Event.DATA_READ, "poc-6/lijst", "aantalRecords=" + result.size());
        return result;
    }
}
