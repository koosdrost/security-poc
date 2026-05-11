package com.demo.security.poc7;

import com.demo.security.audit.AuditService;
import com.demo.security.audit.AuditService.Event;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 7 — Row Level Security
 *
 * POST /v1/poc-7              { "inhoud": "geheim", "openbaar": "zichtbaar" }
 *                             Header: X-Eigenaar-Id: gebruiker-1
 *
 * GET  /v1/poc-7              Lijst van EIGEN records (RLS actief via X-Eigenaar-Id header)
 * GET  /v1/poc-7/{id}         Enkel record — 404 als niet van jou (RLS blokkeert)
 * GET  /v1/poc-7/_admin       Alle records zonder RLS (simuleert BYPASSRLS / superuser)
 *
 * Productie: vervang X-Eigenaar-Id door JWT sub-claim uit Authorization: Bearer header.
 */
@RestController
@RequestMapping("/v1/poc-7")
public class Poc7Controller {

    private final Poc7Service service;
    private final AuditService audit;

    public Poc7Controller(Poc7Service service, AuditService audit) {
        this.service = service;
        this.audit = audit;
    }

    record Request(String inhoud, String openbaar) {}

    @PostMapping
    public ResponseEntity<?> opslaan(@RequestBody Request req) {
        String eigenaarId = RlsContext.get();
        if (eigenaarId == null) {
            return ResponseEntity.badRequest().body("X-Eigenaar-Id header verplicht");
        }
        Poc7Entity entity = new Poc7Entity();
        entity.setEigenaarId(eigenaarId);
        entity.setInhoud(req.inhoud());
        entity.setOpenbaar(req.openbaar());
        Poc7Entity saved = service.opslaan(entity);
        audit.success(Event.DATA_WRITE, "poc-7/" + saved.getId(), "eigenaar=" + eigenaarId);
        return ResponseEntity.ok(saved);
    }

    @GetMapping
    public List<Poc7Entity> lijst() {
        List<Poc7Entity> result = service.findVanEigenaar();
        audit.success(Event.DATA_READ, "poc-7/lijst",
            "eigenaar=" + RlsContext.get() + " aantalResultaten=" + result.size());
        return result;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc7Entity> ophalen(@PathVariable Long id) {
        return service.findById(id)
            .map(entity -> {
                audit.success(Event.DATA_READ, "poc-7/" + id, "eigenaar=" + RlsContext.get());
                return ResponseEntity.ok(entity);
            })
            .orElseGet(() -> {
                // Bewust 404 (niet 403): onthult niet of het record bestaat
                audit.failure(Event.DATA_READ, "poc-7/" + id,
                    "NotFound", "record niet gevonden of geen toegang");
                return ResponseEntity.notFound().build();
            });
    }

    @GetMapping("/_admin")
    public List<Poc7Entity> adminLijst() {
        return service.findAlles();
    }
}
