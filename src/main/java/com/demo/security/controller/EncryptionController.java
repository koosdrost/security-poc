package com.demo.security.controller;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import com.demo.security.domain.EncryptedRecord;
import com.demo.security.rls.RlsContext;
import com.demo.security.service.EncryptionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Gecombineerde demo: dubbele encryptie (app + DB), HMAC-zoekindex én Row Level Security.
 *
 * <h3>Reguliere endpoints (RLS actief via {@code X-Eigenaar-Id} header)</h3>
 * <pre>
 * POST /v1/poc-6                       { "naam": "...", "notitie": "...", "openbaar": "..." }
 *                                       Header: X-Eigenaar-Id: gebruiker-1  (verplicht)
 * GET  /v1/poc-6                       Eigen records
 * GET  /v1/poc-6?naam=&lt;waarde&gt;         Eigen records, gefilterd op naam (HMAC-index)
 * GET  /v1/poc-6?notitie=&lt;waarde&gt;      Eigen records, gefilterd op notitie (HMAC-index)
 * GET  /v1/poc-6/{id}                  Enkel record — 404 als niet van jou
 * </pre>
 *
 * <h3>Admin endpoints (geen RLS-filter)</h3>
 * <pre>
 * GET  /v1/poc-6/_admin                Alle records van alle eigenaren
 * GET  /v1/poc-6/_perf?operatie=...    Performance meting (geen RLS)
 * </pre>
 */
@RestController
@RequestMapping("/v1/poc-6")
public class EncryptionController {

    private final EncryptionService service;
    private final AuditService audit;

    public EncryptionController(EncryptionService service, AuditService audit) {
        this.service = service;
        this.audit = audit;
    }

    record OpslaanRequest(String naam, String notitie, String openbaar) {}

    // =========================================================================
    // Reguliere endpoints — RLS actief
    // =========================================================================

    @PostMapping
    public ResponseEntity<?> opslaan(@RequestBody OpslaanRequest req) {
        String eigenaarId = RlsContext.get();
        if (eigenaarId == null) {
            return ResponseEntity.badRequest().body("X-Eigenaar-Id header verplicht");
        }
        EncryptedRecord saved = service.opslaan(req.naam(), req.notitie(), req.openbaar(), eigenaarId);
        audit.success(Event.DATA_WRITE, "poc-6/" + saved.getId(), "eigenaar=" + eigenaarId);
        return ResponseEntity.ok(saved);
    }

    /**
     * Lijst eigen records of zoek via HMAC-index — altijd gefilterd op de huidige eigenaar.
     * Zonder {@code X-Eigenaar-Id} header: lege lijst.
     * {@code ?naam=} heeft voorrang als beide parameters aanwezig zijn.
     */
    @GetMapping
    public List<EncryptedRecord> lijst(
            @RequestParam(required = false) String naam,
            @RequestParam(required = false) String notitie) {

        if (naam != null) {
            List<EncryptedRecord> result = service.zoekOpNaam(naam);
            audit.success(Event.DATA_SEARCH, "poc-6",
                "eigenaar=" + RlsContext.get() + " veld=naam aantalResultaten=" + result.size());
            return result;
        }
        if (notitie != null) {
            List<EncryptedRecord> result = service.zoekOpNotitie(notitie);
            audit.success(Event.DATA_SEARCH, "poc-6",
                "eigenaar=" + RlsContext.get() + " veld=notitie aantalResultaten=" + result.size());
            return result;
        }
        List<EncryptedRecord> result = service.findVanEigenaar();
        audit.success(Event.DATA_READ, "poc-6/lijst",
            "eigenaar=" + RlsContext.get() + " aantalRecords=" + result.size());
        return result;
    }

    /** Retourneert een enkel record — 404 als het niet van de huidige eigenaar is. */
    @GetMapping("/{id}")
    public ResponseEntity<EncryptedRecord> ophalen(@PathVariable Long id) {
        return service.findById(id)
            .map(record -> {
                audit.success(Event.DATA_READ, "poc-6/" + id, "eigenaar=" + RlsContext.get());
                return ResponseEntity.ok(record);
            })
            .orElseGet(() -> {
                // Bewust 404, niet 403: onthult niet of het record voor een andere eigenaar bestaat
                audit.failure(Event.DATA_READ, "poc-6/" + id,
                    "NotFound", "record niet gevonden of geen toegang");
                return ResponseEntity.notFound().<EncryptedRecord>build();
            });
    }

    // =========================================================================
    // Admin endpoints — geen RLS-filter (BYPASSRLS equivalent)
    // =========================================================================

    /** Alle records van alle eigenaren, zonder RLS. */
    @GetMapping("/_admin")
    public List<EncryptedRecord> admin() {
        return service.findAlles();
    }

    /**
     * Performance meting zonder RLS-filter (crypto-laag isoleren).
     *
     * <p>Ondersteunde operaties:
     * <ul>
     *   <li>{@code lijst} — alle records ophalen</li>
     *   <li>{@code zoek-naam&q=<waarde>} — zoeken op naam via HMAC</li>
     *   <li>{@code zoek-notitie&q=<waarde>} — zoeken op notitie via HMAC</li>
     *   <li>{@code enkel&q=<id>} — enkel record ophalen op ID</li>
     * </ul>
     */
    @GetMapping("/_perf")
    public Map<String, Object> perf(
            @RequestParam String operatie,
            @RequestParam(required = false, defaultValue = "") String q) {

        return gemeten(operatie, switch (operatie) {
            case "lijst"         -> () -> service.findAlles().size();
            case "zoek-naam"     -> () -> service.zoekOpNaamAdmin(q).size();
            case "zoek-notitie"  -> () -> service.zoekOpNotitieAdmin(q).size();
            case "enkel"         -> () -> service.findByIdAdmin(Long.parseLong(q)).isPresent() ? 1 : 0;
            default              -> throw new IllegalArgumentException("Onbekende operatie: " + operatie);
        });
    }

    // =========================================================================

    private Map<String, Object> gemeten(String operatie, Supplier<Integer> actie) {
        long start  = System.currentTimeMillis();
        int  aantal = actie.get();
        long duurMs = System.currentTimeMillis() - start;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("operatie",        operatie);
        result.put("aantalResultaten", aantal);
        result.put("totaalRecords",   service.count());
        result.put("duurMs",          duurMs);
        return result;
    }
}
