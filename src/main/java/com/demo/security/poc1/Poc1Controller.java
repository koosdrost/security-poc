package com.demo.security.poc1;

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

    public Poc1Controller(Poc1Repository repo) {
        this.repo = repo;
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc1Entity opslaan(@RequestBody Request req) {
        Poc1Entity entity = new Poc1Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        entity.setOpenbaar(req.openbaar());
        return repo.save(entity);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc1Entity> ophalen(@PathVariable Long id) {
        return repo.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping
    public List<Poc1Entity> lijst() {
        return repo.findAll();
    }
}
