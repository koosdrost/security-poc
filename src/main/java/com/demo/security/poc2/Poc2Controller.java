package com.demo.security.poc2;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

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
    /** GET /v1/poc-2/_perf?operatie=lijst|zoek|enkel&q= */
    @GetMapping("/_perf")
    public Map<String, Object> perf(@RequestParam String operatie,
                                    @RequestParam(required = false, defaultValue = "1") String q) {
        return gemeten(operatie, switch (operatie) {
            case "lijst" -> () -> repo.findAll().size();
            case "zoek"  -> () -> repo.findByVertrouwelijk(q).size();
            case "enkel" -> () -> repo.findById(Long.parseLong(q)).isPresent() ? 1 : 0;
            default -> throw new IllegalArgumentException("Onbekende operatie: " + operatie);
        });
    }

    private Map<String, Object> gemeten(String operatie, Supplier<Integer> actie) {
        long start  = System.currentTimeMillis();
        int  aantal = actie.get();
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("poc",             "poc-2 (deterministisch AES-CBC)");
        r.put("operatie",        operatie);
        r.put("aantalResultaten", aantal);
        r.put("totaalRecords",   repo.count());
        r.put("duurMs",          System.currentTimeMillis() - start);
        return r;
    }

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
