package com.demo.security.envelope;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
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
    private final EnvelopeRepository   envelopeRepo;
    private final AuditService         audit;

    public EnvelopeController(KeyManagementService kms, EnvelopeRepository envelopeRepo, AuditService audit) {
        this.kms          = kms;
        this.envelopeRepo = envelopeRepo;
        this.audit        = audit;
    }

    record OpslaanVerzoek(String context, String data) {}

    record EnvelopeReactie(Long id, String context, int dekVersie, String data) {}

    /** Stap 1: initialiseer een DEK voor een context voordat data opgeslagen kan worden. */
    @PostMapping("/dek/_initialiseer")
    public DataEncryptionKey initialiseerDek(@RequestParam String context) {
        DataEncryptionKey dek = kms.generateDek(context);
        audit.success(Event.DEK_INIT, "envelope/dek", "context=" + context + " versie=" + dek.getVersion());
        return dek;
    }

    /** Opslaan: data wordt versleuteld met de actieve DEK voor de context. */
    @PostMapping
    public EnvelopeEntity opslaan(@RequestBody OpslaanVerzoek req) {
        EnvelopeEntity saved = kms.save(req.context(), req.data());
        audit.success(Event.DATA_WRITE, "envelope/" + saved.getId(),
            "context=" + req.context() + " dekVersie=" + saved.getDekVersion());
        return saved;
    }

    /** Ophalen: data wordt ontsleuteld met de DEK-versie die bij het record hoort. */
    @GetMapping("/{id}")
    public ResponseEntity<EnvelopeReactie> ophalen(@PathVariable Long id) {
        return envelopeRepo.findById(id)
            .map(entity -> {
                String plaintext = kms.decrypt(entity);
                audit.success(Event.DATA_READ, "envelope/" + id,
                    "context=" + entity.getContext() + " dekVersie=" + entity.getDekVersion());
                return ResponseEntity.ok(new EnvelopeReactie(
                    entity.getId(), entity.getContext(), entity.getDekVersion(), plaintext));
            })
            .orElseGet(() -> {
                audit.failure(Event.DATA_READ, "envelope/" + id, "NotFound", "record niet gevonden");
                return ResponseEntity.notFound().build();
            });
    }

    /**
     * DEK-rotatie: genereert nieuwe DEK, her-versleutelt alle rijen voor de context.
     * Referentie: CLAUDE.md 5.3, 5.5
     */
    @PostMapping("/{context}/dek-rotatie")
    public Map<String, Object> rotateerDek(@PathVariable String context) {
        int aantal = kms.rotateDek(context);
        audit.success(Event.DEK_ROTATION, "envelope/dek",
            "context=" + context + " herversleuteldRijen=" + aantal);
        return Map.of(
            "context",             context,
            "herversleuteldRijen", aantal,
            "status",              "DEK rotatie voltooid"
        );
    }
}
