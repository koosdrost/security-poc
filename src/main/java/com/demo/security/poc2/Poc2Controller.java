package com.demo.security.poc2;

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

    public Poc2Controller(Poc2Repository repo) {
        this.repo = repo;
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc2Entity opslaan(@RequestBody Request req) {
        Poc2Entity entity = new Poc2Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        entity.setOpenbaar(req.openbaar());
        return repo.save(entity);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc2Entity> ophalen(@PathVariable Long id) {
        return repo.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Lijst alle records, of filter op exacte waarde als ?value= opgegeven.
     * findByVertrouwelijk geeft de plaintext door aan de DeterministicConverter,
     * die er de ciphertext van maakt — Hibernate zoekt op die ciphertext.
     */
    @GetMapping
    public List<Poc2Entity> lijst(@RequestParam(required = false) String value) {
        if (value != null) {
            return repo.findByVertrouwelijk(value);
        }
        return repo.findAll();
    }
}
