package com.demo.security.poc4;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 4 — @ColumnTransformer + H2 SQL functies
 * Encryptie/decryptie vindt plaats in de database (SQL laag), niet in Java.
 *
 * POST /v1/poc-4      { "vertrouwelijk": "geheim", "openbaar": "zichtbaar" }
 * GET  /v1/poc-4/{id} Enkel record (SQL roept DECRYPT_STRING aan bij ophalen)
 * GET  /v1/poc-4      Lijst van alle records
 */
@RestController
@RequestMapping("/v1/poc-4")
public class Poc4Controller {

    private final Poc4Repository repo;
    private final AuditService audit;

    public Poc4Controller(Poc4Repository repo, AuditService audit) {
        this.repo = repo;
        this.audit = audit;
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc4Entity opslaan(@RequestBody Request req) {
        Poc4Entity entity = new Poc4Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        entity.setOpenbaar(req.openbaar());
        Poc4Entity saved = repo.save(entity);
        audit.success(Event.DATA_WRITE, "poc-4/" + saved.getId(), "openbaar=" + req.openbaar());
        return saved;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc4Entity> ophalen(@PathVariable Long id) {
        return repo.findById(id)
            .map(entity -> {
                audit.success(Event.DATA_READ, "poc-4/" + id, "openbaar=" + entity.getOpenbaar());
                return ResponseEntity.ok(entity);
            })
            .orElseGet(() -> {
                audit.failure(Event.DATA_READ, "poc-4/" + id, "NotFound", "record niet gevonden");
                return ResponseEntity.notFound().build();
            });
    }

    @GetMapping
    public List<Poc4Entity> lijst() {
        List<Poc4Entity> result = repo.findAll();
        audit.success(Event.DATA_READ, "poc-4/lijst", "aantalRecords=" + result.size());
        return result;
    }
}
