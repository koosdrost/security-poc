package com.demo.security.poc4;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 4 — @ColumnTransformer + H2 SQL functies
 * Encryptie/decryptie vindt plaats in de database (SQL laag), niet in Java.
 *
 * POST /api/poc4      { "vertrouwelijk": "geheim", "openbaar": "zichtbaar" }
 * GET  /api/poc4/{id} Enkel record (SQL roept DECRYPT_STRING aan bij ophalen)
 * GET  /api/poc4      Lijst van alle records
 */
@RestController
@RequestMapping("/api/poc4")
public class Poc4Controller {

    private final Poc4Repository repo;

    public Poc4Controller(Poc4Repository repo) {
        this.repo = repo;
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc4Entity save(@RequestBody Request req) {
        Poc4Entity entity = new Poc4Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        entity.setOpenbaar(req.openbaar());
        return repo.save(entity);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc4Entity> get(@PathVariable Long id) {
        return repo.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping
    public List<Poc4Entity> list() {
        return repo.findAll();
    }
}
