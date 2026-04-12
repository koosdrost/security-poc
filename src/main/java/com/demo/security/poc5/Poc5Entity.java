package com.demo.security.poc5;

import com.demo.security.poc1.AesGcmConverter;
import com.demo.security.poc2.DeterministicConverter;
import jakarta.persistence.*;
import org.hibernate.annotations.ColumnTransformer;

/**
 * POC 5 — Gecombineerde encryptie-strategieën op één entity.
 *
 * Drie versleutelde velden, elk met een andere aanpak:
 *
 *   naam        — Deterministisch (AES-CBC, HMAC-IV) via AttributeConverter (POC 2 stijl)
 *                 Exact zoeken mogelijk: zelfde plaintext → zelfde ciphertext.
 *
 *   notitie     — Niet-deterministisch (AES-GCM) via AttributeConverter + aparte HMAC-kolom (POC 3 stijl)
 *                 Zoeken via HMAC-index (notitie_hmac), nooit via de versleutelde kolom zelf.
 *
 *   referentie  — Versleuteld op databaseniveau via @ColumnTransformer + H2 SQL-functies (POC 4 stijl)
 *                 Encryptie/decryptie vindt buiten Java plaats (simuleert pgcrypto).
 *                 Geen zoekondersteuning: AES-GCM is niet-deterministisch.
 *
 * Referentie: CLAUDE.md 3.2, 3.3, 3.4
 */
@Entity
@Table(name = "poc5")
public class Poc5Entity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Strategie 1: deterministisch — exact zoeken via findByNaam(). */
    @Convert(converter = DeterministicConverter.class)
    @Column(name = "naam", columnDefinition = "VARCHAR(512)")
    private String naam;

    /** Strategie 2a: AES-GCM — niet-deterministisch, niet doorzoekbaar op ciphertext. */
    @Convert(converter = AesGcmConverter.class)
    @Column(name = "notitie", columnDefinition = "VARCHAR(512)")
    private String notitie;

    /** Strategie 2b: HMAC-SHA256 van notitie als zoekindex (eenrichtingsfunctie). */
    @Column(name = "notitie_hmac", columnDefinition = "VARCHAR(64)")
    private String notitieHmac;

    /** Strategie 3: encryptie/decryptie in de SQL-laag via @ColumnTransformer. */
    @Column(name = "referentie", columnDefinition = "VARCHAR(512)")
    @ColumnTransformer(
        read  = "DECRYPT_STRING(referentie)",
        write = "ENCRYPT_STRING(?)"
    )
    private String referentie;

    @Column(name = "openbaar")
    private String openbaar;

    public Long getId()                    { return id; }
    public String getNaam()                { return naam; }
    public void setNaam(String n)          { this.naam = n; }
    public String getNotitie()             { return notitie; }
    public void setNotitie(String n)       { this.notitie = n; }
    public String getNotitieHmac()         { return notitieHmac; }
    public void setNotitieHmac(String h)   { this.notitieHmac = h; }
    public String getReferentie()          { return referentie; }
    public void setReferentie(String r)    { this.referentie = r; }
    public String getOpenbaar()            { return openbaar; }
    public void setOpenbaar(String o)      { this.openbaar = o; }
}
