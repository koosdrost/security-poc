package com.demo.security.envelope;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EnvelopeRepository extends JpaRepository<EnvelopeEntity, Long> {

    List<EnvelopeEntity> findByContext(String context);
}
