package com.demo.security.poc1;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 1 — AES-GCM AttributeConverter
 *
 * POST /api/poc1          { "vertrouwelijk": "geheim", "openbaar": "zichtbaar" }
 * GET  /api/poc1          Lijst van alle records (ontsleuteld)
 * GET  /api/poc1/{id}     Enkel record (ontsleuteld)
 */
@RestController
@RequestMapping("/api/poc1")
public class Poc1Controller {

    private final Poc1Repository repo;

    public Poc1Controller(Poc1Repository repo) {
        this.repo = repo;
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc1Entity save(@RequestBody Request req) {
        Poc1Entity entity = new Poc1Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        entity.setOpenbaar(req.openbaar());
        return repo.save(entity);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc1Entity> get(@PathVariable Long id) {
        return repo.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping
    public List<Poc1Entity> list() {
        return repo.findAll();
    }
}
