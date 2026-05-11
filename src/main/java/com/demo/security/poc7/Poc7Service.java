package com.demo.security.poc7;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Activeert het RLS-filter vóór elke leesoperatie — analoog aan hoe PostgreSQL automatisch
 * de policy toepast zodra current_setting('app.current_user_id') gezet is.
 *
 * findAlles() activeert het filter NIET: simuleert DB superuser / admin-toegang
 * (BYPASSRLS privilege in PostgreSQL).
 */
@Service
@Transactional(readOnly = true)
public class Poc7Service {

    @PersistenceContext
    private EntityManager em;

    private final Poc7Repository repo;

    public Poc7Service(Poc7Repository repo) {
        this.repo = repo;
    }

    public List<Poc7Entity> findVanEigenaar() {
        if (RlsContext.get() == null) return List.of();
        activeerRlsFilter();
        return repo.findAll();
    }

    public Optional<Poc7Entity> findById(Long id) {
        if (RlsContext.get() == null) return Optional.empty();
        activeerRlsFilter();
        // findById() gebruikt EntityManager.find() dat Hibernate-filters bypast;
        // JPQL-query in repository respecteert het filter wel
        return repo.findByIdMetFilter(id);
    }

    /** Zonder filter — simuleert BYPASSRLS / superuser in PostgreSQL */
    public List<Poc7Entity> findAlles() {
        return repo.findAll();
    }

    @Transactional
    public Poc7Entity opslaan(Poc7Entity entity) {
        return repo.save(entity);
    }

    private void activeerRlsFilter() {
        String eigenaarId = RlsContext.get();
        if (eigenaarId == null) return;
        em.unwrap(Session.class)
          .enableFilter("rls")
          .setParameter("huidigeEigenaarId", eigenaarId);
    }
}
