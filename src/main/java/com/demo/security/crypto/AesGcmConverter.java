package com.demo.security.crypto;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * JPA {@link AttributeConverter} die String-kolommen transparant versleutelt met AES-GCM.
 *
 * <p>De converter wordt zowel door Spring als door Hibernate geïnstantieerd. Omdat Hibernate
 * soms zijn eigen instantie aanmaakt buiten de Spring-context, wordt de sleutel opgeslagen
 * in een {@code static} veld. Spring roept {@link #setPassphrase} aan via {@code @Value},
 * waarna de sleutel beschikbaar is voor <em>alle</em> instanties — inclusief die van Hibernate.
 *
 * <p>AES-GCM is niet-deterministisch: dezelfde plaintext levert elke keer een andere ciphertext
 * (willekeurige IV). Zoeken op het versleutelde veld is daardoor niet mogelijk. Gebruik een
 * HMAC-zoekindex voor dat doel (zie {@link CryptoUtil#hmacBase64}).
 */
@Component
@Converter
public class AesGcmConverter implements AttributeConverter<String, String> {

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
