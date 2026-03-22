package com.demo.security.envelope;

import com.demo.security.crypto.CryptoUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Beheert de DEK-levenscyclus voor envelope encryption.
 *
 * Flow opslaan:
 *   1. Haal actieve DEK op voor context
 *   2. Ontsleutel DEK met KEK
 *   3. Versleutel data met DEK (AES-GCM)
 *   4. Sla op met dekVersion
 *
 * Flow ophalen:
 *   1. Lees entity → haal dekVersion op
 *   2. Zoek DEK op context + version
 *   3. Ontsleutel DEK met KEK
 *   4. Ontsleutel data met DEK
 *
 * Referentie: CLAUDE.md 2.1 t/m 2.4
 */
@Service
public class KeyManagementService {

    private final DekRepository dekRepo;
    private final EnvelopeRepository envelopeRepo;

    @Value("${encryption.kek}")
    private String kekPassphrase;

    private byte[] kek;

    public KeyManagementService(DekRepository dekRepo, EnvelopeRepository envelopeRepo) {
        this.dekRepo       = dekRepo;
        this.envelopeRepo  = envelopeRepo;
    }

    @PostConstruct
    public void init() {
        this.kek = CryptoUtil.deriveKey(kekPassphrase);
    }

    // -------------------------------------------------------------------------
    // DEK beheer
    // -------------------------------------------------------------------------

    /** Genereert een nieuwe DEK voor een context. Deactiveert de huidige actieve DEK. */
    @Transactional
    public DataEncryptionKey generateDek(String context) {
        dekRepo.deactivateAllByContext(context);

        byte[] dek       = CryptoUtil.generateRandomKey();
        int    version   = dekRepo.findMaxVersionByContext(context) + 1;
        String wrappedDek = CryptoUtil.wrapKey(dek, kek);

        DataEncryptionKey entity = new DataEncryptionKey();
        entity.setContext(context);
        entity.setVersion(version);
        entity.setEncryptedKey(wrappedDek);
        entity.setActive(true);
        return dekRepo.save(entity);
    }

    /** Geeft de byte[] DEK terug, ontsleuteld met de KEK. */
    public byte[] getDek(String context, int version) {
        DataEncryptionKey dek = dekRepo.findByContextAndVersion(context, version)
            .orElseThrow(() -> new IllegalArgumentException(
                "Geen DEK gevonden voor context=" + context + " version=" + version));
        return CryptoUtil.unwrapKey(dek.getEncryptedKey(), kek);
    }

    public byte[] getActiveDek(String context) {
        DataEncryptionKey dek = dekRepo.findByContextAndActiveTrue(context)
            .orElseThrow(() -> new IllegalStateException(
                "Geen actieve DEK voor context: " + context +
                " — roep eerst POST /api/envelope/dek/init?context=" + context + " aan"));
        return CryptoUtil.unwrapKey(dek.getEncryptedKey(), kek);
    }

    public int getActiveDekVersion(String context) {
        return dekRepo.findByContextAndActiveTrue(context)
            .orElseThrow(() -> new IllegalStateException("Geen actieve DEK voor context: " + context))
            .getVersion();
    }

    // -------------------------------------------------------------------------
    // Data encryptie / decryptie
    // -------------------------------------------------------------------------

    /** Versleutelt data met de actieve DEK voor de gegeven context. */
    @Transactional
    public EnvelopeEntity save(String context, String plaintext) {
        byte[] dek     = getActiveDek(context);
        int    version = getActiveDekVersion(context);

        EnvelopeEntity entity = new EnvelopeEntity();
        entity.setContext(context);
        entity.setDekVersion(version);
        entity.setEncryptedData(CryptoUtil.aesGcmEncrypt(plaintext, dek));
        return envelopeRepo.save(entity);
    }

    /** Ontsleutelt een EnvelopeEntity met de bijbehorende DEK-versie. */
    public String decrypt(EnvelopeEntity entity) {
        byte[] dek = getDek(entity.getContext(), entity.getDekVersion());
        return CryptoUtil.aesGcmDecrypt(entity.getEncryptedData(), dek);
    }

    // -------------------------------------------------------------------------
    // DEK-rotatie
    // -------------------------------------------------------------------------

    /**
     * Roteert de DEK voor een context:
     * 1. Genereer nieuwe DEK
     * 2. Her-versleutel alle EnvelopeEntity rijen in REPEATABLE READ transactie
     * 3. Verwijder de oude DEK
     *
     * Referentie: CLAUDE.md 5.3, 5.5
     */
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    public int rotateDek(String context) {
        // Snapshot van actieve DEK vóór deactivatie
        DataEncryptionKey oudeDek = dekRepo.findByContextAndActiveTrue(context)
            .orElseThrow(() -> new IllegalStateException("Geen actieve DEK voor context: " + context));
        byte[] oudeSleutel = CryptoUtil.unwrapKey(oudeDek.getEncryptedKey(), kek);

        // Nieuwe DEK genereren (deactiveert de oude)
        DataEncryptionKey nieuweDek = generateDek(context);
        byte[] nieuweSleutel        = CryptoUtil.unwrapKey(nieuweDek.getEncryptedKey(), kek);

        // Her-versleutel alle rijen voor deze context
        List<EnvelopeEntity> rijen = envelopeRepo.findByContext(context);
        for (EnvelopeEntity rij : rijen) {
            String plaintext = CryptoUtil.aesGcmDecrypt(rij.getEncryptedData(), oudeSleutel);
            rij.setEncryptedData(CryptoUtil.aesGcmEncrypt(plaintext, nieuweSleutel));
            rij.setDekVersion(nieuweDek.getVersion());
        }
        envelopeRepo.saveAll(rijen);

        // Verwijder de oude DEK
        dekRepo.delete(oudeDek);

        return rijen.size();
    }
}
