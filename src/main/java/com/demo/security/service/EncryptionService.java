package com.demo.security.service;

import com.demo.security.crypto.CryptoUtil;
import com.demo.security.domain.EncryptedRecord;
import com.demo.security.repository.EncryptedRecordRepository;
import com.demo.security.rls.RlsContext;
import jakarta.annotation.PostConstruct;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Business logic voor de gecombineerde demo: dubbele encryptie + HMAC-zoekindex + Row Level Security.
 *
 * <h3>Methodegroepen</h3>
 * <ul>
 *   <li><strong>Schrijven</strong> — {@link #opslaan}: vereist eigenaar-id.</li>
 *   <li><strong>Lezen (RLS actief)</strong> — activeren het Hibernate-filter op basis van
 *       {@link RlsContext}. Retourneren een lege lijst/empty als er geen eigenaar bekend is.</li>
 *   <li><strong>Admin (geen filter)</strong> — {@code findAlles} en de {@code *Admin}-varianten
 *       slaan het filter over. Simuleren het PostgreSQL {@code BYPASSRLS}-privilege.</li>
 * </ul>
 */
@Service
@Transactional(readOnly = true)
public class EncryptionService {

    @PersistenceContext
    private EntityManager em;

    private final EncryptedRecordRepository repo;

    @Value("${encryption.hmac-secret}")
    private String hmacSecret;

    private byte[] hmacKey;

    public EncryptionService(EncryptedRecordRepository repo) {
        this.repo = repo;
    }

    @PostConstruct
    void init() {
        this.hmacKey = CryptoUtil.deriveKey(hmacSecret);
    }

    // -------------------------------------------------------------------------
    // Schrijven
    // -------------------------------------------------------------------------

    @Transactional
    public EncryptedRecord opslaan(String naam, String notitie, String openbaar, String eigenaarId) {
        EncryptedRecord record = new EncryptedRecord();
        record.setEigenaarId(eigenaarId);
        record.setNaam(naam);
        record.setNaamHmac(CryptoUtil.hmacBase64(naam, hmacKey));
        record.setNotitie(notitie);
        record.setNotitieHmac(CryptoUtil.hmacBase64(notitie, hmacKey));
        record.setOpenbaar(openbaar);
        return repo.save(record);
    }

    // -------------------------------------------------------------------------
    // Lezen — RLS actief (lege uitkomst als eigenaar onbekend)
    // -------------------------------------------------------------------------

    /** Retourneert alle records van de huidige eigenaar. Leeg als er geen eigenaar in de context zit. */
    public List<EncryptedRecord> findVanEigenaar() {
        if (RlsContext.get() == null) return List.of();
        activeerRlsFilter();
        return repo.findAll();
    }

    /**
     * Zoekt een record op ID, gefilterd op de huidige eigenaar.
     * Retourneert {@link Optional#empty()} als eigenaar onbekend is of het record niet van jou is.
     */
    public Optional<EncryptedRecord> findById(Long id) {
        if (RlsContext.get() == null) return Optional.empty();
        activeerRlsFilter();
        return repo.findByIdMetFilter(id);
    }

    /** Zoekt op naam-HMAC, gefilterd op de huidige eigenaar. */
    public List<EncryptedRecord> zoekOpNaam(String zoekterm) {
        if (RlsContext.get() == null) return List.of();
        activeerRlsFilter();
        return repo.findByNaamHmac(CryptoUtil.hmacBase64(zoekterm, hmacKey));
    }

    /** Zoekt op notitie-HMAC, gefilterd op de huidige eigenaar. */
    public List<EncryptedRecord> zoekOpNotitie(String zoekterm) {
        if (RlsContext.get() == null) return List.of();
        activeerRlsFilter();
        return repo.findByNotitieHmac(CryptoUtil.hmacBase64(zoekterm, hmacKey));
    }

    // -------------------------------------------------------------------------
    // Admin — geen RLS-filter (BYPASSRLS equivalent)
    // -------------------------------------------------------------------------

    public List<EncryptedRecord> findAlles() {
        return repo.findAll();
    }

    public Optional<EncryptedRecord> findByIdAdmin(Long id) {
        return repo.findById(id);
    }

    public List<EncryptedRecord> zoekOpNaamAdmin(String zoekterm) {
        return repo.findByNaamHmac(CryptoUtil.hmacBase64(zoekterm, hmacKey));
    }

    public List<EncryptedRecord> zoekOpNotitieAdmin(String zoekterm) {
        return repo.findByNotitieHmac(CryptoUtil.hmacBase64(zoekterm, hmacKey));
    }

    public long count() {
        return repo.count();
    }

    // -------------------------------------------------------------------------

    /**
     * Activeert het Hibernate RLS-filter voor de huidige transactie-sessie.
     *
     * <p>PostgreSQL-equivalent: {@code SET LOCAL app.current_user_id = '<eigenaarId>'}.
     * Voegt automatisch {@code WHERE eigenaar_id = :huidigeEigenaarId} toe aan elke query
     * op {@link EncryptedRecord} binnen deze transactie.
     */
    private void activeerRlsFilter() {
        String eigenaarId = RlsContext.get();
        if (eigenaarId == null) return;
        em.unwrap(Session.class)
          .enableFilter("rls")
          .setParameter("huidigeEigenaarId", eigenaarId);
    }
}
