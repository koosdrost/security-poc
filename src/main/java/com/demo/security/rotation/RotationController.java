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
 * en verdeeld de ceremoniemeester ze out-of-band naar sleutelbeheerders.
 * Referentie: CLAUDE.md 5.1 t/m 5.5, 6.4
 *
 * POST /api/rotation/init         Splits huidige KEK in 5 shares
 * POST /api/rotation/reconstruct  { "shares": ["base64...", ...] }  (minimaal 3)
 */
@RestController
@RequestMapping("/api/rotation")
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
    @PostMapping("/init")
    public Map<String, Object> initRotation() {
        byte[][] rawShares = ShamirSecretSharing.split(kek, N, K);

        List<String> encodedShares = Arrays.stream(rawShares)
            .map(share -> Base64.getEncoder().encodeToString(share))
            .toList();

        return Map.of(
            "aantalShares",  N,
            "drempelwaarde", K,
            "uitleg",        "Verdeel de shares over " + N + " sleutelbeheerders. " +
                             "Minimaal " + K + " shares zijn nodig voor reconstructie.",
            "shares",        encodedShares
        );
    }

    /**
     * Stap 2: Reconstrueer de KEK uit minstens K shares.
     * Demonstreert dat de oorspronkelijke KEK correct wordt hersteld.
     * Referentie: CLAUDE.md 5.3
     */
    @PostMapping("/reconstruct")
    public Map<String, Object> reconstruct(@RequestBody Map<String, List<String>> body) {
        List<String> encodedShares = body.get("shares");
        if (encodedShares == null || encodedShares.size() < K) {
            return Map.of("fout", "Minimaal " + K + " shares vereist, ontvangen: " +
                (encodedShares == null ? 0 : encodedShares.size()));
        }

        byte[][] shares = encodedShares.stream()
            .map(s -> Base64.getDecoder().decode(s))
            .toArray(byte[][]::new);

        byte[] gereconstrueerdeKek = ShamirSecretSharing.reconstruct(shares);
        boolean correct = Arrays.equals(gereconstrueerdeKek, kek);

        return Map.of(
            "aantalSharesIngediend",   encodedShares.size(),
            "reconstructieGeslaagd",   correct,
            "gereconstrueerdeKekHex",  bytesToHex(gereconstrueerdeKek),
            "origineleKekHex",         bytesToHex(kek),
            "uitleg",                  correct
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
