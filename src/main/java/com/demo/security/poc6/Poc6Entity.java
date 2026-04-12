package com.demo.security.poc6;

import com.demo.security.poc1.AesGcmConverter;
import jakarta.persistence.*;
import org.hibernate.annotations.ColumnTransformer;

/**
 * POC 6 — Dubbele encryptie (app + DB) met HMAC zoekindex per veld.
 *
 * Elke vertrouwelijke kolom heeft drie onderdelen:
 *
 *   veld          — dubbel versleuteld:
 *                   1. AesGcmConverter (Java, AES-GCM) vóór de SQL-laag
 *                   2. ENCRYPT_STRING / DECRYPT_STRING (@ColumnTransformer, DB-laag)
 *                   Datastroom write: plaintext → AES-GCM → ENCRYPT_STRING → DB
 *                   Datastroom read:  DB → DECRYPT_STRING → AES-GCM decrypt → plaintext
 *
 *   veld_hmac     — HMAC-SHA256 van de plaintext, opgeslagen als zoekindex.
 *                   Berekend vóór encryptie; onthult niets over de plaintext.
 *
 * Referentie: CLAUDE.md 3.1, 3.3, 3.4
 */
@Entity
@Table(name = "poc6")
public class Poc6Entity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Convert(converter = AesGcmConverter.class)
    @Column(name = "naam", columnDefinition = "VARCHAR(512)")
    @ColumnTransformer(
        read  = "DECRYPT_STRING(naam)",
        write = "ENCRYPT_STRING(?)"
    )
    private String naam;

    @Column(name = "naam_hmac", columnDefinition = "VARCHAR(64)")
    private String naamHmac;

    @Convert(converter = AesGcmConverter.class)
    @Column(name = "notitie", columnDefinition = "VARCHAR(512)")
    @ColumnTransformer(
        read  = "DECRYPT_STRING(notitie)",
        write = "ENCRYPT_STRING(?)"
    )
    private String notitie;

    @Column(name = "notitie_hmac", columnDefinition = "VARCHAR(64)")
    private String notitieHmac;

    @Column(name = "openbaar")
    private String openbaar;

    public Long getId()                    { return id; }
    public String getNaam()                { return naam; }
    public void setNaam(String n)          { this.naam = n; }
    public String getNaamHmac()            { return naamHmac; }
    public void setNaamHmac(String h)      { this.naamHmac = h; }
    public String getNotitie()             { return notitie; }
    public void setNotitie(String n)       { this.notitie = n; }
    public String getNotitieHmac()         { return notitieHmac; }
    public void setNotitieHmac(String h)   { this.notitieHmac = h; }
    public String getOpenbaar()            { return openbaar; }
    public void setOpenbaar(String o)      { this.openbaar = o; }
}
