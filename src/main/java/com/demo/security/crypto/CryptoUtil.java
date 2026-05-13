package com.demo.security.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Crypto utilities voor AES-GCM encryptie en HMAC-SHA256 zoekindexen.
 *
 * Bewust geen Spring bean — wordt aangeroepen door JPA converters (AesGcmConverter)
 * vóórdat de Spring-context volledig is opgebouwd.
 */
public final class CryptoUtil {

    /** 96-bit IV, aanbevolen door NIST voor AES-GCM (maximale GCM-performance + veiligheid). */
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS  = 128;

    private CryptoUtil() {}

    // -------------------------------------------------------------------------
    // Sleutelafleiding
    // -------------------------------------------------------------------------

    /**
     * Leidt een 32-byte AES-256 sleutel af van een passphrase via SHA-256.
     * In productie wordt de passphrase beheerd via een keystore (Elytron / Vault).
     */
    public static byte[] deriveKey(String passphrase) {
        try {
            return MessageDigest.getInstance("SHA-256")
                .digest(passphrase.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Key derivation mislukt", e);
        }
    }

    // -------------------------------------------------------------------------
    // AES-GCM encryptie (niet-deterministisch)
    //
    // Opslagformaat: Base64( IV[12] ‖ ciphertext ‖ GCM-tag[16] )
    //
    // Elke aanroep genereert een willekeurige IV, zodat dezelfde plaintext
    // altijd een andere ciphertext oplevert. Hierdoor is exact zoeken op het
    // versleutelde veld niet mogelijk — gebruik een HMAC-index daarvoor (zie onder).
    // -------------------------------------------------------------------------

    public static String aesGcmEncrypt(String plaintext, byte[] key) {
        if (plaintext == null) return null;
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // IV vooraan zodat decrypt hem kan terugvinden zonder aparte opslag
            byte[] result = new byte[GCM_IV_LENGTH + encrypted.length];
            System.arraycopy(iv,        0, result, 0,              GCM_IV_LENGTH);
            System.arraycopy(encrypted, 0, result, GCM_IV_LENGTH,  encrypted.length);
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryptie mislukt", e);
        }
    }

    public static String aesGcmDecrypt(String encoded, byte[] key) {
        if (encoded == null) return null;
        try {
            byte[] data       = Base64.getDecoder().decode(encoded);
            byte[] iv         = Arrays.copyOfRange(data, 0,              GCM_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(data, GCM_IV_LENGTH,  data.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));

            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decryptie mislukt", e);
        }
    }

    // -------------------------------------------------------------------------
    // HMAC-SHA256 zoekindex
    //
    // Slaat een deterministisch hash van de plaintext op als aparte kolom.
    // Zoeken: bereken HMAC van de zoekterm en vergelijk met de opgeslagen index.
    // De HMAC onthult niets over de plaintext (one-way, met geheime sleutel).
    // -------------------------------------------------------------------------

    /**
     * Berekent HMAC-SHA256 van {@code value} met {@code key}.
     * Retourneert een Base64-gecodeerde string geschikt als DB-zoekindex.
     */
    public static String hmacBase64(String value, byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Base64.getEncoder().encodeToString(
                mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException("HMAC berekening mislukt", e);
        }
    }
}
