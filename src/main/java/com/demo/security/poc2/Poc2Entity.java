package com.demo.security.poc2;

import jakarta.persistence.*;

/**
 * POC 2 — Deterministisch versleuteld.
 * Zoeken via findByVertrouwelijk() werkt omdat ciphertext reproduceerbaar is.
 */
@Entity
@Table(name = "poc2")
public class Poc2Entity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Convert(converter = DeterministicConverter.class)
    @Column(name = "vertrouwelijk", columnDefinition = "VARCHAR(512)")
    private String vertrouwelijk;

    @Column(name = "openbaar")
    private String openbaar;

    public Long getId()                    { return id; }
    public String getVertrouwelijk()       { return vertrouwelijk; }
    public void setVertrouwelijk(String v) { this.vertrouwelijk = v; }
    public String getOpenbaar()            { return openbaar; }
    public void setOpenbaar(String o)      { this.openbaar = o; }
}
