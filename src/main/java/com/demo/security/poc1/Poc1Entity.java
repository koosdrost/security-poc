package com.demo.security.poc1;

import jakarta.persistence.*;

/**
 * POC 1 — AES-GCM via AttributeConverter.
 * 'vertrouwelijk' wordt versleuteld opgeslagen, 'openbaar' niet.
 */
@Entity
@Table(name = "poc1")
public class Poc1Entity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Convert(converter = AesGcmConverter.class)
    @Column(name = "vertrouwelijk", columnDefinition = "VARCHAR(512)")
    private String vertrouwelijk;

    @Column(name = "openbaar")
    private String openbaar;

    public Long getId()                        { return id; }
    public String getVertrouwelijk()           { return vertrouwelijk; }
    public void setVertrouwelijk(String v)     { this.vertrouwelijk = v; }
    public String getOpenbaar()                { return openbaar; }
    public void setOpenbaar(String o)          { this.openbaar = o; }
}
