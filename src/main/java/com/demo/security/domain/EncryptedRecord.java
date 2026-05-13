package com.demo.security.domain;

import com.demo.security.crypto.AesGcmConverter;
import jakarta.persistence.*;
import org.hibernate.annotations.ColumnTransformer;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.FilterDef;
import org.hibernate.annotations.ParamDef;

/**
 * Gecombineerde entiteit: dubbele encryptie (app + DB), HMAC-zoekindex én Row Level Security.
 *
 * <h3>Encryptie (dubbele laag)</h3>
 * <ul>
 *   <li>Java-laag: {@link AesGcmConverter} (AES-GCM, willekeurige IV per opslag)</li>
 *   <li>DB-laag: {@code ENCRYPT_STRING}/{@code DECRYPT_STRING} via {@link ColumnTransformer}</li>
 * </ul>
 * Datastroom write: {@code plaintext → AES-GCM (Java) → ENCRYPT_STRING (DB) → opslag}<br>
 * Datastroom read:  {@code DB → DECRYPT_STRING (DB) → AES-GCM decrypt (Java) → plaintext}
 *
 * <h3>HMAC-zoekindex</h3>
 * {@code naam_hmac} en {@code notitie_hmac} bevatten HMAC-SHA256 van de plaintext.
 * Zoeken: {@code WHERE naam_hmac = hmacBase64(zoekterm)} — plaintext verschijnt nooit in de query.
 *
 * <h3>Row Level Security</h3>
 * {@code @FilterDef} + {@code @Filter} beperken queries tot records van de huidige eigenaar.
 * PostgreSQL-equivalent:
 * <pre>{@code
 * CREATE POLICY rls_eigen_data ON poc6
 *   USING (eigenaar_id = current_setting('app.current_user_id'));
 * ALTER TABLE poc6 ENABLE ROW LEVEL SECURITY;
 * }</pre>
 */
@Entity
@Table(name = "poc6")
@FilterDef(
    name = "rls",
    defaultCondition = "eigenaar_id = :huidigeEigenaarId",
    parameters = @ParamDef(name = "huidigeEigenaarId", type = String.class)
)
@Filter(name = "rls")
public class EncryptedRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "eigenaar_id")
    private String eigenaarId;

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
    public String getEigenaarId()          { return eigenaarId; }
    public void setEigenaarId(String e)    { this.eigenaarId = e; }
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
