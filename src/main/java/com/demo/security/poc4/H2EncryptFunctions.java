package com.demo.security.poc4;

import com.demo.security.crypto.CryptoUtil;

/**
 * POC 4 — H2 custom SQL functies voor encrypt/decrypt.
 * Simuleert de PostgreSQL pgcrypto functies encrypt_string / decrypt_string.
 *
 * H2 laadt deze klasse via reflectie met zijn eigen classloader — een andere instantie
 * dan de Spring-context gebruikt. Daarom kan de static 'kek' niet direct worden gezet
 * vanuit Spring. In plaats daarvan wordt de passphrase via System.getProperty doorgegeven
 * (gedeeld over alle classloaders) en de sleutel lazy geïnitialiseerd.
 *
 * Referentie: CLAUDE.md 3.4 / 4.2
 */
public class H2EncryptFunctions {

    public static final String SYSPROP = "security.poc.kek.passphrase";

    private static volatile byte[] kek;

    private static byte[] kek() {
        if (kek == null) {
            synchronized (H2EncryptFunctions.class) {
                if (kek == null) {
                    String passphrase = System.getProperty(SYSPROP);
                    if (passphrase == null) {
                        throw new IllegalStateException("H2EncryptFunctions niet geïnitialiseerd: sysprop " + SYSPROP + " ontbreekt");
                    }
                    kek = CryptoUtil.deriveKey(passphrase);
                }
            }
        }
        return kek;
    }

    /** H2 roept deze methode aan bij INSERT/UPDATE via ENCRYPT_STRING(?). */
    public static String encryptString(String plaintext) {
        return CryptoUtil.aesGcmEncrypt(plaintext, kek());
    }

    /** H2 roept deze methode aan bij SELECT via DECRYPT_STRING(kolom). */
    public static String decryptString(String ciphertext) {
        return CryptoUtil.aesGcmDecrypt(ciphertext, kek());
    }
}
