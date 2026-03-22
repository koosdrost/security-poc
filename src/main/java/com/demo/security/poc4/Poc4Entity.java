package com.demo.security.poc4;

import jakarta.persistence.*;
import org.hibernate.annotations.ColumnTransformer;

/**
 * POC 4 — @ColumnTransformer met H2 custom SQL functies.
 * Simuleert de PostgreSQL referentie-implementatie (CLAUDE.md 4.2, 4.5).
 *
 * In productie worden ENCRYPT_STRING / DECRYPT_STRING vervangen door
 * de pgcrypto functies op PostgreSQL niveau.
 *
 * Referentie: CLAUDE.md 3.4
 */
@Entity
@Table(name = "poc4")
public class Poc4Entity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "vertrouwelijk", columnDefinition = "VARCHAR(512)")
    @ColumnTransformer(
        read  = "DECRYPT_STRING(vertrouwelijk)",
        write = "ENCRYPT_STRING(?)"
    )
    private String vertrouwelijk;

    @Column(name = "openbaar")
    private String openbaar;

    public Long getId()                    { return id; }
    public String getVertrouwelijk()       { return vertrouwelijk; }
    public void setVertrouwelijk(String v) { this.vertrouwelijk = v; }
    public String getOpenbaar()            { return openbaar; }
    public void setOpenbaar(String o)      { this.openbaar = o; }
}
