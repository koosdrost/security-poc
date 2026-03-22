package com.demo.security.envelope;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Envelope encryption POC
 *
 * POST /api/envelope/dek/init?context=users    Initialiseer DEK voor context
 * POST /api/envelope                           { "context": "users", "data": "geheim" }
 * GET  /api/envelope/{id}                      Record ophalen + ontsleutelen
 * POST /api/envelope/{context}/rotate-dek      DEK rotatie voor context
 */
@RestController
@RequestMapping("/api/envelope")
public class EnvelopeController {

    private final KeyManagementService kms;
    private final EnvelopeRepository  envelopeRepo;

    public EnvelopeController(KeyManagementService kms, EnvelopeRepository envelopeRepo) {
        this.kms          = kms;
        this.envelopeRepo = envelopeRepo;
    }

    record SaveRequest(String context, String data) {}

    record EnvelopeResponse(Long id, String context, int dekVersion, String data) {}

    /** Stap 1: initialiseer een DEK voor een context voordat data opgeslagen kan worden. */
    @PostMapping("/dek/init")
    public DataEncryptionKey initDek(@RequestParam String context) {
        return kms.generateDek(context);
    }

    /** Opslaan: data wordt versleuteld met de actieve DEK voor de context. */
    @PostMapping
    public EnvelopeEntity save(@RequestBody SaveRequest req) {
        return kms.save(req.context(), req.data());
    }

    /** Ophalen: data wordt ontsleuteld met de DEK-versie die bij het record hoort. */
    @GetMapping("/{id}")
    public ResponseEntity<EnvelopeResponse> get(@PathVariable Long id) {
        return envelopeRepo.findById(id)
            .map(entity -> {
                String plaintext = kms.decrypt(entity);
                return ResponseEntity.ok(new EnvelopeResponse(
                    entity.getId(), entity.getContext(), entity.getDekVersion(), plaintext));
            })
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * DEK-rotatie: genereert nieuwe DEK, her-versleutelt alle rijen voor de context.
     * Referentie: CLAUDE.md 5.3, 5.5
     */
    @PostMapping("/{context}/rotate-dek")
    public Map<String, Object> rotateDek(@PathVariable String context) {
        int count = kms.rotateDek(context);
        return Map.of(
            "context",             context,
            "herversleuteldRijen", count,
            "status",              "DEK rotatie voltooid"
        );
    }
}
