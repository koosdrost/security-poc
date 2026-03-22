package com.demo.security.poc2;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 2 — Deterministisch versleuteld (AES-SIV concept)
 *
 * POST /api/poc2                      { "vertrouwelijk": "geheim", "openbaar": "zichtbaar" }
 * GET  /api/poc2/{id}                 Enkel record
 * GET  /api/poc2/search?value=geheim  Zoeken op exacte waarde (werkt dankzij determinisme)
 */
@RestController
@RequestMapping("/api/poc2")
public class Poc2Controller {

    private final Poc2Repository repo;

    public Poc2Controller(Poc2Repository repo) {
        this.repo = repo;
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc2Entity save(@RequestBody Request req) {
        Poc2Entity entity = new Poc2Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        entity.setOpenbaar(req.openbaar());
        return repo.save(entity);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc2Entity> get(@PathVariable Long id) {
        return repo.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/search")
    public List<Poc2Entity> search(@RequestParam String value) {
        // findByVertrouwelijk geeft de plaintext door aan de converter,
        // die er de ciphertext van maakt — dan zoekt Hibernate op die ciphertext
        return repo.findByVertrouwelijk(value);
    }
}
