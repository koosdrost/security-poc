package com.demo.security.poc7;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface Poc7Repository extends JpaRepository<Poc7Entity, Long> {

    // EntityManager.find() bypast Hibernate-filters; JPQL wel gefilterd
    @Query("SELECT e FROM Poc7Entity e WHERE e.id = :id")
    Optional<Poc7Entity> findByIdMetFilter(@Param("id") Long id);
}
