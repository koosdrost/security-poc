package com.demo.security.envelope;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Envelope encryption POC
 *
 * POST /v1/envelope/dek/_initialiseer?context=   Initialiseer DEK voor context
 * POST /v1/envelope                              { "context": "gebruikers", "data": "geheim" }
 * GET  /v1/envelope/{id}                         Record ophalen + ontsleutelen
 * POST /v1/envelope/{context}/dek-rotatie        DEK rotatie voor context
 *
 * URI-structuur conform NL GOV API Design Rules v2.1.0:
 *  - Versie in pad (/v1/)
 *  - Kebab-case padsegmenten
 *  - Operaties als sub-resources met _ prefix (_initialiseer)
 */
@RestController
@RequestMapping("/v1/envelope")
public class EnvelopeController {

    private final KeyManagementService kms;
    private final EnvelopeRepository  envelopeRepo;

    public EnvelopeController(KeyManagementService kms, EnvelopeRepository envelopeRepo) {
        this.kms          = kms;
        this.envelopeRepo = envelopeRepo;
    }

    record OpslaanVerzoek(String context, String data) {}

    record EnvelopeReactie(Long id, String context, int dekVersie, String data) {}

    /** Stap 1: initialiseer een DEK voor een context voordat data opgeslagen kan worden. */
    @PostMapping("/dek/_initialiseer")
    public DataEncryptionKey initialiseerDek(@RequestParam String context) {
        return kms.generateDek(context);
    }

    /** Opslaan: data wordt versleuteld met de actieve DEK voor de context. */
    @PostMapping
    public EnvelopeEntity opslaan(@RequestBody OpslaanVerzoek req) {
        return kms.save(req.context(), req.data());
    }

    /** Ophalen: data wordt ontsleuteld met de DEK-versie die bij het record hoort. */
    @GetMapping("/{id}")
    public ResponseEntity<EnvelopeReactie> ophalen(@PathVariable Long id) {
        return envelopeRepo.findById(id)
            .map(entity -> {
                String plaintext = kms.decrypt(entity);
                return ResponseEntity.ok(new EnvelopeReactie(
                    entity.getId(), entity.getContext(), entity.getDekVersion(), plaintext));
            })
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * DEK-rotatie: genereert nieuwe DEK, her-versleutelt alle rijen voor de context.
     * Referentie: CLAUDE.md 5.3, 5.5
     */
    @PostMapping("/{context}/dek-rotatie")
    public Map<String, Object> rotateerDek(@PathVariable String context) {
        int aantal = kms.rotateDek(context);
        return Map.of(
            "context",             context,
            "herversleuteldRijen", aantal,
            "status",              "DEK rotatie voltooid"
        );
    }
}
