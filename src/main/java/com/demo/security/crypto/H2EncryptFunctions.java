package com.demo.security.crypto;

/**
 * H2 custom SQL functies voor encrypt/decrypt.
 * Simuleert de PostgreSQL pgcrypto functies encrypt_string / decrypt_string.
 *
 * H2 laadt deze klasse via reflectie met zijn eigen classloader. Daarom wordt de
 * passphrase via System.getProperty doorgegeven (gedeeld over alle classloaders)
 * en de sleutel lazy geïnitialiseerd.
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
                        throw new IllegalStateException(
                            "H2EncryptFunctions niet geïnitialiseerd: sysprop " + SYSPROP + " ontbreekt");
                    }
                    kek = CryptoUtil.deriveKey(passphrase);
                }
            }
        }
        return kek;
    }

    public static String encryptString(String plaintext) {
        return CryptoUtil.aesGcmEncrypt(plaintext, kek());
    }

    public static String decryptString(String ciphertext) {
        return CryptoUtil.aesGcmDecrypt(ciphertext, kek());
    }
}
