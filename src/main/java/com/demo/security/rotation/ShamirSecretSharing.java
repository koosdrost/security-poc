package com.demo.security.rotation;

import java.security.SecureRandom;

/**
 * Shamir's Secret Sharing over GF(256).
 *
 * Werkt byte-per-byte over het Galois-veld GF(256) met het AES irreducible polynoom
 * x^8 + x^4 + x^3 + x + 1 (0x11B). Optelling = XOR, vermenigvuldiging via tabelopzoek.
 *
 * Referentie: CLAUDE.md 5.1
 */
public class ShamirSecretSharing {

    // -------------------------------------------------------------------------
    // GF(256) rekenkunde
    // -------------------------------------------------------------------------

    /** Vermenigvuldiging in GF(256) via carry-less multiply + reductie mod 0x11B. */
    private static int gfMul(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) p ^= a;
            boolean carry = (a & 0x80) != 0;
            a = (a << 1) & 0xFF;
            if (carry) a ^= 0x1B; // 0x11B mod 0x100
            b >>= 1;
        }
        return p;
    }

    /** a^exp in GF(256). */
    private static int gfPow(int a, int exp) {
        int result = 1;
        for (int i = 0; i < exp; i++) result = gfMul(result, a);
        return result;
    }

    /** Inverse van a in GF(256): a^254 (Fermat: a^255 = 1 voor a ≠ 0). */
    private static int gfInv(int a) {
        if (a == 0) throw new ArithmeticException("Geen inverse voor 0 in GF(256)");
        return gfPow(a, 254);
    }

    // -------------------------------------------------------------------------
    // Shamir's Secret Sharing
    // -------------------------------------------------------------------------

    /**
     * Splits een geheim in n shares met drempelwaarde k.
     * Elk share: byte[0] = x-coördinaat (1..n), rest = polynoom-evaluatie per secretbyte.
     *
     * @param secret Het te splitsen geheim (bijv. 32-byte KEK)
     * @param n      Totaal aantal shares
     * @param k      Minimaal aantal shares om te reconstrueren
     */
    public static byte[][] split(byte[] secret, int n, int k) {
        if (k > n) throw new IllegalArgumentException("k mag niet groter zijn dan n");
        if (n > 255) throw new IllegalArgumentException("n mag maximaal 255 zijn");

        SecureRandom random = new SecureRandom();
        byte[][] shares = new byte[n][1 + secret.length];

        for (int byteIdx = 0; byteIdx < secret.length; byteIdx++) {
            // Polynoom: coeff[0] = secretbyte, coeff[1..k-1] = willekeurig
            int[] coeff = new int[k];
            coeff[0] = secret[byteIdx] & 0xFF;
            for (int i = 1; i < k; i++) coeff[i] = random.nextInt(256);

            // Evalueer polynoom op x = 1..n (Horner's methode)
            for (int x = 1; x <= n; x++) {
                int y = 0;
                for (int i = k - 1; i >= 0; i--) y = gfMul(y, x) ^ coeff[i];
                shares[x - 1][0]            = (byte) x;            // x-coördinaat
                shares[x - 1][byteIdx + 1]  = (byte) y;            // f(x) voor deze byte
            }
        }
        return shares;
    }

    /**
     * Reconstrueert het geheim uit minstens k shares via Lagrange-interpolatie bij x=0.
     *
     * @param shares Array van shares (elk share[0] bevat de x-coördinaat)
     */
    public static byte[] reconstruct(byte[][] shares) {
        int secretLength = shares[0].length - 1;
        byte[] secret    = new byte[secretLength];
        int k            = shares.length;

        int[] xCoords = new int[k];
        for (int i = 0; i < k; i++) xCoords[i] = shares[i][0] & 0xFF;

        for (int byteIdx = 0; byteIdx < secretLength; byteIdx++) {
            int result = 0;
            for (int i = 0; i < k; i++) {
                int yi = shares[i][byteIdx + 1] & 0xFF;

                // Lagrange-basispoly bij x=0: product_{j≠i}(0-x_j) / product_{j≠i}(x_i-x_j)
                // In GF(256): aftrekken = XOR
                int num = 1, den = 1;
                for (int j = 0; j < k; j++) {
                    if (i != j) {
                        num = gfMul(num, xCoords[j]);               // 0 XOR x_j = x_j
                        den = gfMul(den, xCoords[i] ^ xCoords[j]);  // x_i XOR x_j
                    }
                }
                result ^= gfMul(yi, gfMul(num, gfInv(den)));
            }
            secret[byteIdx] = (byte) result;
        }
        return secret;
    }
}
