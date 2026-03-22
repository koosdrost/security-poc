package com.demo.security.poc3;

import com.demo.security.crypto.CryptoUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * POC 3 — AES-GCM + HMAC zoekindex
 *
 * POST /api/poc3                      { "vertrouwelijk": "geheim", "openbaar": "zichtbaar" }
 * GET  /api/poc3/{id}                 Enkel record
 * GET  /api/poc3/search?value=geheim  Zoeken via HMAC-index
 */
@RestController
@RequestMapping("/api/poc3")
public class Poc3Controller {

    private final Poc3Repository repo;

    @Value("${encryption.hmac-secret}")
    private String hmacSecret;

    private byte[] hmacKey;

    public Poc3Controller(Poc3Repository repo) {
        this.repo = repo;
    }

    @PostConstruct
    public void init() {
        this.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    record Request(String vertrouwelijk, String openbaar) {}

    @PostMapping
    public Poc3Entity save(@RequestBody Request req) {
        Poc3Entity entity = new Poc3Entity();
        entity.setVertrouwelijk(req.vertrouwelijk());
        // HMAC wordt berekend op plaintext en apart opgeslagen als zoekindex
        entity.setVertrouwelijkHmac(CryptoUtil.hmacBase64(req.vertrouwelijk(), hmacKey));
        entity.setOpenbaar(req.openbaar());
        return repo.save(entity);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Poc3Entity> get(@PathVariable Long id) {
        return repo.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/search")
    public List<Poc3Entity> search(@RequestParam String value) {
        // Bereken HMAC van de zoekterm — zoek op de index kolom
        String hmac = CryptoUtil.hmacBase64(value, hmacKey);
        return repo.findByVertrouwelijkHmac(hmac);
    }
}
