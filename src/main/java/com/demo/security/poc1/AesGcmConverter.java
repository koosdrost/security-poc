package com.demo.security.poc1;

import com.demo.security.crypto.CryptoUtil;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * POC 1 — AES-GCM AttributeConverter (niet-deterministisch).
 * Zelfde plaintext geeft elke keer een andere ciphertext (random IV).
 * Zoeken op versleuteld veld is NIET mogelijk.
 *
 * Referentie: CLAUDE.md 3.1
 */
@Component
@Converter
public class AesGcmConverter implements AttributeConverter<String, String> {

    // Static field: werkt ongeacht of Hibernate of Spring de instantie beheert
    private static byte[] key;

    @Value("${encryption.kek}")
    public void setPassphrase(String passphrase) {
        AesGcmConverter.key = CryptoUtil.deriveKey(passphrase);
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        return CryptoUtil.aesGcmEncrypt(attribute, key);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        return CryptoUtil.aesGcmDecrypt(dbData, key);
    }
}
