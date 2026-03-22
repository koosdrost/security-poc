package com.demo.security.envelope;

import jakarta.persistence.*;

/**
 * Envelope encryption — versleutelde data opgeslagen met DEK-referentie.
 * Bij lezen wordt de DEK opgezocht op basis van context + dekVersion.
 *
 * Referentie: CLAUDE.md 2.1
 */
@Entity
@Table(name = "envelope_data")
public class EnvelopeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "context", nullable = false)
    private String context;

    /** Versie van de DEK waarmee deze data is versleuteld — nodig bij DEK-rotatie. */
    @Column(name = "dek_version", nullable = false)
    private int dekVersion;

    /** Data versleuteld met de DEK. Formaat: Base64(IV || ciphertext || tag). */
    @Column(name = "encrypted_data", columnDefinition = "VARCHAR(1024)", nullable = false)
    private String encryptedData;

    public Long getId()                    { return id; }
    public String getContext()             { return context; }
    public void setContext(String c)       { this.context = c; }
    public int getDekVersion()             { return dekVersion; }
    public void setDekVersion(int v)       { this.dekVersion = v; }
    public String getEncryptedData()       { return encryptedData; }
    public void setEncryptedData(String d) { this.encryptedData = d; }
}
