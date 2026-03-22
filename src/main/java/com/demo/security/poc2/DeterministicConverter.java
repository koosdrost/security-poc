package com.demo.security.poc2;

import com.demo.security.crypto.CryptoUtil;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * POC 2 — Deterministisch versleuteld via AES/CBC met HMAC-afgeleid IV (AES-SIV concept).
 * Zelfde plaintext → zelfde ciphertext → zoeken op versleuteld veld IS mogelijk.
 *
 * Referentie: CLAUDE.md 3.2
 */
@Component
@Converter
public class DeterministicConverter implements AttributeConverter<String, String> {

    private static byte[] encKey;
    private static byte[] hmacKey;

    @Value("${encryption.kek}")
    public void setEncPassphrase(String passphrase) {
        DeterministicConverter.encKey = CryptoUtil.deriveKey(passphrase);
    }

    @Value("${encryption.hmac-secret}")
    public void setHmacPassphrase(String hmacSecret) {
        DeterministicConverter.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        return CryptoUtil.deterministicEncrypt(attribute, encKey, hmacKey);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        return CryptoUtil.deterministicDecrypt(dbData, encKey);
    }

    /** Exposé voor de controller: versleutel een zoekterm met dezelfde methode. */
    public String encryptForSearch(String plaintext) {
        return convertToDatabaseColumn(plaintext);
    }
}
