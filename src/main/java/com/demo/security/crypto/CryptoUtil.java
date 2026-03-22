package com.demo.security.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Gedeelde crypto utilities voor alle POCs.
 * Bewust geen Spring bean - wordt gebruikt door JPA converters vóór de context volledig is opgebouwd.
 */
public final class CryptoUtil {

    private static final int GCM_IV_LENGTH = 12;   // 96 bits, aanbevolen door NIST
    private static final int GCM_TAG_BITS  = 128;
    private static final int CBC_IV_LENGTH = 16;

    private CryptoUtil() {}

    // -------------------------------------------------------------------------
    // Sleutels
    // -------------------------------------------------------------------------

    /** Leidt een 32-byte AES-256 sleutel af van een passphrase via SHA-256. */
    public static byte[] deriveKey(String passphrase) {
        try {
            return MessageDigest.getInstance("SHA-256")
                .digest(passphrase.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Key derivation mislukt", e);
        }
    }

    /** Genereert een willekeurige 32-byte AES-256 sleutel. */
    public static byte[] generateRandomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    // -------------------------------------------------------------------------
    // POC 1 & 3 — AES-GCM (niet-deterministisch)
    // Opslag formaat: Base64(IV[12] || ciphertext || tag[16])
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

            byte[] result = new byte[GCM_IV_LENGTH + encrypted.length];
            System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
            System.arraycopy(encrypted, 0, result, GCM_IV_LENGTH, encrypted.length);
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryptie mislukt", e);
        }
    }

    public static String aesGcmDecrypt(String encoded, byte[] key) {
        if (encoded == null) return null;
        try {
            byte[] data       = Base64.getDecoder().decode(encoded);
            byte[] iv         = Arrays.copyOfRange(data, 0, GCM_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(data, GCM_IV_LENGTH, data.length);

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
    // POC 2 — Deterministisch (AES-SIV concept)
    // IV = HMAC(hmacKey, plaintext)[0..15] → zelfde plaintext = zelfde ciphertext
    // Opslag formaat: Base64(IV[16] || ciphertext)
    // -------------------------------------------------------------------------

    public static String deterministicEncrypt(String plaintext, byte[] encKey, byte[] hmacKey) {
        if (plaintext == null) return null;
        try {
            byte[] iv = Arrays.copyOfRange(
                hmacRaw(plaintext.getBytes(StandardCharsets.UTF_8), hmacKey), 0, CBC_IV_LENGTH);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(encKey, "AES"),
                new IvParameterSpec(iv));

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] result    = new byte[CBC_IV_LENGTH + encrypted.length];
            System.arraycopy(iv, 0, result, 0, CBC_IV_LENGTH);
            System.arraycopy(encrypted, 0, result, CBC_IV_LENGTH, encrypted.length);
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("Deterministisch encryptie mislukt", e);
        }
    }

    public static String deterministicDecrypt(String encoded, byte[] encKey) {
        if (encoded == null) return null;
        try {
            byte[] data       = Base64.getDecoder().decode(encoded);
            byte[] iv         = Arrays.copyOfRange(data, 0, CBC_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(data, CBC_IV_LENGTH, data.length);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(encKey, "AES"),
                new IvParameterSpec(iv));

            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Deterministisch decryptie mislukt", e);
        }
    }

    // -------------------------------------------------------------------------
    // POC 3 — HMAC-SHA256 zoekindex
    // -------------------------------------------------------------------------

    /** Berekent HMAC-SHA256, retourneert Base64-gecodeerde waarde als zoekindex. */
    public static String hmacBase64(String value, byte[] key) {
        return Base64.getEncoder().encodeToString(
            hmacRaw(value.getBytes(StandardCharsets.UTF_8), key));
    }

    private static byte[] hmacRaw(byte[] data, byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC berekening mislukt", e);
        }
    }

    // -------------------------------------------------------------------------
    // Envelope encryption — DEK wrapping met KEK
    // -------------------------------------------------------------------------

    /** Wraps (versleutelt) een DEK met de KEK via AES-GCM. */
    public static String wrapKey(byte[] dek, byte[] kek) {
        return aesGcmEncrypt(Base64.getEncoder().encodeToString(dek), kek);
    }

    /** Unwraps (ontsleutelt) een met KEK versleutelde DEK. */
    public static byte[] unwrapKey(String wrappedDek, byte[] kek) {
        return Base64.getDecoder().decode(aesGcmDecrypt(wrappedDek, kek));
    }
}
