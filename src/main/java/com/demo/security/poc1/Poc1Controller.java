package com.demo.security.poc1;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 1 — AES-GCM AttributeConverter
 *
 * POST /v1/poc-1          { "vertrouwelijk": "geheim", "openbaar": "zichtbaar" }
 * GET  /v1/poc-1          Lijst van alle records (ontsleuteld)
 * GET  /v1/poc-1/{id}     Enkel record (ontsleuteld)
 *
 * URI-structuur conform NL GOV API Design Rules v2.1.0:
 *  - Versie in pad (/v1/)
 *  - Kebab-case padsegmenten (poc-1)
 *  - Meervoud voor collecties via GET op basis-pad
 */
@RestController
@RequestMapping("/v1/poc-1")
public class Poc1Controller {

    private final Poc1Repository repo;
    private final AuditService audit;

    public Poc1Controller(Poc1Repository repo, AuditService audit) {
        this.repo = repo;
        this.audit = audit;
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc1Entity opslaan(@RequestBody Request req) {
        Poc1Entity entity = new Poc1Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        entity.setOpenbaar(req.openbaar());
        Poc1Entity saved = repo.save(entity);
        audit.success(Event.DATA_WRITE, "poc-1/" + saved.getId(), "openbaar=" + req.openbaar());
        return saved;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc1Entity> ophalen(@PathVariable Long id) {
        return repo.findById(id)
            .map(entity -> {
                audit.success(Event.DATA_READ, "poc-1/" + id, "openbaar=" + entity.getOpenbaar());
                return ResponseEntity.ok(entity);
            })
            .orElseGet(() -> {
                audit.failure(Event.DATA_READ, "poc-1/" + id, "NotFound", "record niet gevonden");
                return ResponseEntity.notFound().build();
            });
    }

    @GetMapping
    public List<Poc1Entity> lijst() {
        List<Poc1Entity> result = repo.findAll();
        audit.success(Event.DATA_READ, "poc-1/lijst", "aantalRecords=" + result.size());
        return result;
    }
}
