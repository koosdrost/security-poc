package com.demo.security.rotation;

import com.demo.security.crypto.CryptoUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * KEK-rotatie POC via Shamir's Secret Sharing (5 shares, drempel 3).
 *
 * WAARSCHUWING: Dit is een POC. In productie worden shares nooit via HTTP uitgeleverd
 * en verdeelt de ceremoniemeester ze out-of-band naar sleutelbeheerders.
 * Referentie: CLAUDE.md 5.1 t/m 5.5, 6.4
 *
 * POST /v1/kek-rotatie/_initialiseer       Splits huidige KEK in 5 shares
 * POST /v1/kek-rotatie/_reconstrueer       { "shares": ["base64...", ...] } (minimaal 3)
 *
 * URI-structuur conform NL GOV API Design Rules v2.1.0:
 *  - Kebab-case padsegmenten (kek-rotatie)
 *  - Operaties als sub-resources met _ prefix (_initialiseer, _reconstrueer)
 *  - Foutresponses via ApiExceptionHandler (problem+json, RFC 9457)
 */
@RestController
@RequestMapping("/v1/kek-rotatie")
public class RotationController {

    private static final int N = 5; // totaal aantal shares (technisch sleutelbeheerders)
    private static final int K = 3; // drempelwaarde (Shamir's Secret Sharing)

    @Value("${encryption.kek}")
    private String kekPassphrase;

    private byte[] kek;

    @PostConstruct
    public void init() {
        this.kek = CryptoUtil.deriveKey(kekPassphrase);
    }

    /**
     * Stap 1: Split de KEK in N shares.
     * In productie: elk share wordt apart aangeboden aan een sleutelbeheerder.
     * Referentie: CLAUDE.md 5.1, 5.2
     */
    @PostMapping("/_initialiseer")
    public Map<String, Object> initialiseerRotatie() {
        byte[][] rawShares = ShamirSecretSharing.split(kek, N, K);
        List<String> gecodeerdeShares = Arrays.stream(rawShares)
            .map(share -> Base64.getEncoder().encodeToString(share))
            .toList();

        return Map.of(
            "aantalShares",  N,
            "drempelwaarde", K,
            "uitleg",        "Verdeel de shares over " + N + " sleutelbeheerders. " +
                             "Minimaal " + K + " shares zijn nodig voor reconstructie.",
            "shares",        gecodeerdeShares
        );
    }

    /**
     * Stap 2: Reconstrueer de KEK uit minstens K shares.
     * Gooit IllegalArgumentException bij te weinig shares (→ 400 problem+json via ApiExceptionHandler).
     * Referentie: CLAUDE.md 5.3
     */
    @PostMapping("/_reconstrueer")
    public Map<String, Object> reconstrueer(@RequestBody Map<String, List<String>> body) {
        List<String> gecodeerdeShares = body.get("shares");
        if (gecodeerdeShares == null || gecodeerdeShares.size() < K) {
            throw new IllegalArgumentException(
                "Minimaal " + K + " shares vereist, ontvangen: " +
                (gecodeerdeShares == null ? 0 : gecodeerdeShares.size()));
        }

        byte[][] shares = gecodeerdeShares.stream()
            .map(s -> Base64.getDecoder().decode(s))
            .toArray(byte[][]::new);

        byte[] gereconstrueerdeKek = ShamirSecretSharing.reconstruct(shares);
        boolean correct = Arrays.equals(gereconstrueerdeKek, kek);

        return Map.of(
            "aantalSharesIngediend",  gecodeerdeShares.size(),
            "reconstructieGeslaagd",  correct,
            "gereconstrueerdeKekHex", bytesToHex(gereconstrueerdeKek),
            "origineleKekHex",        bytesToHex(kek),
            "uitleg",                 correct
                ? "KEK succesvol gereconstrueerd. In productie worden hiermee de DEKs her-versleuteld."
                : "Reconstructie mislukt — verkeerde of beschadigde shares."
        );
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
