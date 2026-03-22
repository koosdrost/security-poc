package com.demo.security.envelope;

import jakarta.persistence.*;

/**
 * Envelope encryption — Data Encryption Key (DEK).
 * DEK wordt versleuteld opgeslagen met de KEK (Key Encryption Key).
 *
 * Referentie: CLAUDE.md 2.1, 2.2, 2.4
 */
@Entity
@Table(name = "data_encryption_key")
public class DataEncryptionKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Context waarvoor deze DEK geldt, bijv. "users", "payments". */
    @Column(name = "context", nullable = false)
    private String context;

    /** Versienummer — loopt op bij DEK-rotatie. */
    @Column(name = "version", nullable = false)
    private int version;

    /**
     * De DEK, versleuteld met de KEK via AES-GCM.
     * Formaat: Base64(IV || ciphertext || tag)
     * Referentie: CLAUDE.md 2.3
     */
    @Column(name = "encrypted_key", columnDefinition = "VARCHAR(256)", nullable = false)
    private String encryptedKey;

    /** Alleen de actieve DEK wordt gebruikt voor nieuwe encryptie. */
    @Column(name = "active", nullable = false)
    private boolean active;

    public Long getId()                    { return id; }
    public String getContext()             { return context; }
    public void setContext(String c)       { this.context = c; }
    public int getVersion()                { return version; }
    public void setVersion(int v)          { this.version = v; }
    public String getEncryptedKey()        { return encryptedKey; }
    public void setEncryptedKey(String k)  { this.encryptedKey = k; }
    public boolean isActive()              { return active; }
    public void setActive(boolean a)       { this.active = a; }
}
