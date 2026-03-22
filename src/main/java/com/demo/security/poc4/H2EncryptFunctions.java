package com.demo.security.poc4;

import com.demo.security.crypto.CryptoUtil;

/**
 * POC 4 — H2 custom SQL functies voor encrypt/decrypt.
 * Simuleert de PostgreSQL pgcrypto functies encrypt_string / decrypt_string.
 *
 * H2 roept deze static methoden aan via CREATE ALIAS.
 * De sleutel wordt gezet door H2FunctionRegistrar vóór het eerste gebruik.
 *
 * Referentie: CLAUDE.md 3.4 / 4.2
 */
public class H2EncryptFunctions {

    // Volatile: gezet door H2FunctionRegistrar, gelezen door H2 worker threads
    static volatile byte[] kek;

    /** H2 roept deze methode aan bij INSERT/UPDATE via ENCRYPT_STRING(?). */
    public static String encryptString(String plaintext) {
        if (kek == null) throw new IllegalStateException("H2EncryptFunctions niet geïnitialiseerd");
        return CryptoUtil.aesGcmEncrypt(plaintext, kek);
    }

    /** H2 roept deze methode aan bij SELECT via DECRYPT_STRING(kolom). */
    public static String decryptString(String ciphertext) {
        if (kek == null) throw new IllegalStateException("H2EncryptFunctions niet geïnitialiseerd");
        return CryptoUtil.aesGcmDecrypt(ciphertext, kek);
    }
}
