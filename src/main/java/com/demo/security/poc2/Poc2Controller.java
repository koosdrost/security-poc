package com.demo.security.poc2;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 2 — Deterministisch versleuteld (AES-SIV concept)
 *
 * POST /v1/poc-2             { "vertrouwelijk": "geheim", "openbaar": "zichtbaar" }
 * GET  /v1/poc-2             Lijst van alle records
 * GET  /v1/poc-2?value=      Filter op exacte waarde (werkt dankzij determinisme)
 * GET  /v1/poc-2/{id}        Enkel record
 *
 * ADR: zoekfilter als query-parameter op de collectie (geen aparte /search sub-resource).
 */
@RestController
@RequestMapping("/v1/poc-2")
public class Poc2Controller {

    private final Poc2Repository repo;
    private final AuditService audit;

    public Poc2Controller(Poc2Repository repo, AuditService audit) {
        this.repo = repo;
        this.audit = audit;
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc2Entity opslaan(@RequestBody Request req) {
        Poc2Entity entity = new Poc2Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        entity.setOpenbaar(req.openbaar());
        Poc2Entity saved = repo.save(entity);
        audit.success(Event.DATA_WRITE, "poc-2/" + saved.getId(), "openbaar=" + req.openbaar());
        return saved;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc2Entity> ophalen(@PathVariable Long id) {
        return repo.findById(id)
            .map(entity -> {
                audit.success(Event.DATA_READ, "poc-2/" + id, "openbaar=" + entity.getOpenbaar());
                return ResponseEntity.ok(entity);
            })
            .orElseGet(() -> {
                audit.failure(Event.DATA_READ, "poc-2/" + id, "NotFound", "record niet gevonden");
                return ResponseEntity.notFound().build();
            });
    }

    /**
     * Lijst alle records, of filter op exacte waarde als ?value= opgegeven.
     * findByVertrouwelijk geeft de plaintext door aan de DeterministicConverter,
     * die er de ciphertext van maakt — Hibernate zoekt op die ciphertext.
     * Let op: de zoekterm zelf wordt NIET gelogd (zou plaintext data bevatten).
     */
    @GetMapping
    public List<Poc2Entity> lijst(@RequestParam(required = false) String value) {
        if (value != null) {
            List<Poc2Entity> result = repo.findByVertrouwelijk(value);
            audit.success(Event.DATA_SEARCH, "poc-2", "aantalResultaten=" + result.size());
            return result;
        }
        List<Poc2Entity> result = repo.findAll();
        audit.success(Event.DATA_READ, "poc-2/lijst", "aantalRecords=" + result.size());
        return result;
    }
}
