package com.demo.security.poc4;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

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

    /** GET /v1/poc-4/_perf?operatie=lijst|enkel&q= */
    @GetMapping("/_perf")
    public Map<String, Object> perf(@RequestParam String operatie,
                                    @RequestParam(required = false, defaultValue = "1") String q) {
        return gemeten(operatie, switch (operatie) {
            case "lijst" -> () -> repo.findAll().size();
            case "enkel" -> () -> repo.findById(Long.parseLong(q)).isPresent() ? 1 : 0;
            default -> throw new IllegalArgumentException("Onbekende operatie: " + operatie);
        });
    }

    private Map<String, Object> gemeten(String operatie, Supplier<Integer> actie) {
        long start  = System.currentTimeMillis();
        int  aantal = actie.get();
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("poc",             "poc-4 (@ColumnTransformer H2-SQL)");
        r.put("operatie",        operatie);
        r.put("aantalResultaten", aantal);
        r.put("totaalRecords",   repo.count());
        r.put("duurMs",          System.currentTimeMillis() - start);
        return r;
    }
}
