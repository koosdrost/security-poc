package com.demo.security.poc3;

import com.demo.security.poc1.AesGcmConverter;
import jakarta.persistence.*;

/**
 * POC 3 — AES-GCM + HMAC zoekindex.
 * 'vertrouwelijk' is niet-deterministisch versleuteld (AES-GCM).
 * 'vertrouwelijkHmac' is de HMAC-SHA256 van de plaintext — gebruikt als zoekindex.
 *
 * Referentie: CLAUDE.md 3.3
 */
@Entity
@Table(name = "poc3")
public class Poc3Entity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Convert(converter = AesGcmConverter.class)
    @Column(name = "vertrouwelijk", columnDefinition = "VARCHAR(512)")
    private String vertrouwelijk;

    /** HMAC is een eenrichtingsfunctie — onthult niets over de plaintext, maakt zoeken wel mogelijk. */
    @Column(name = "vertrouwelijk_hmac", columnDefinition = "VARCHAR(64)")
    private String vertrouwelijkHmac;

    @Column(name = "openbaar")
    private String openbaar;

    public Long getId()                        { return id; }
    public String getVertrouwelijk()           { return vertrouwelijk; }
    public void setVertrouwelijk(String v)     { this.vertrouwelijk = v; }
    public String getVertrouwelijkHmac()       { return vertrouwelijkHmac; }
    public void setVertrouwelijkHmac(String h) { this.vertrouwelijkHmac = h; }
    public String getOpenbaar()                { return openbaar; }
    public void setOpenbaar(String o)          { this.openbaar = o; }
}
