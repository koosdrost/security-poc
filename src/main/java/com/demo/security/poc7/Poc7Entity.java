package com.demo.security.poc7;

import com.demo.security.poc1.AesGcmConverter;
import jakarta.persistence.*;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.FilterDef;
import org.hibernate.annotations.ParamDef;

/**
 * POC 7 — Row Level Security via Hibernate @Filter.
 *
 * PostgreSQL-equivalent:
 *   CREATE POLICY user_ziet_eigen_data ON poc7
 *     USING (eigenaar_id = current_setting('app.current_user_id'));
 *   ALTER TABLE poc7 ENABLE ROW LEVEL SECURITY;
 *
 * Het Hibernate-filter wordt geactiveerd door Poc7Service.activeerRlsFilter().
 * Rijen van andere eigenaren zijn onzichtbaar — niet 403, maar 404 (best practice).
 */
@Entity
@Table(name = "poc7")
@FilterDef(
    name = "rls",
    defaultCondition = "eigenaar_id = :huidigeEigenaarId",
    parameters = @ParamDef(name = "huidigeEigenaarId", type = String.class)
)
@Filter(name = "rls")
public class Poc7Entity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "eigenaar_id", nullable = false)
    private String eigenaarId;

    @Convert(converter = AesGcmConverter.class)
    @Column(name = "inhoud", columnDefinition = "VARCHAR(512)")
    private String inhoud;

    @Column(name = "openbaar")
    private String openbaar;

    public Long getId()                  { return id; }
    public String getEigenaarId()        { return eigenaarId; }
    public void setEigenaarId(String e)  { eigenaarId = e; }
    public String getInhoud()            { return inhoud; }
    public void setInhoud(String i)      { inhoud = i; }
    public String getOpenbaar()          { return openbaar; }
    public void setOpenbaar(String o)    { openbaar = o; }
}
