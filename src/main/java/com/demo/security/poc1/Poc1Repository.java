package com.demo.security.poc1;

import org.springframework.data.jpa.repository.JpaRepository;

// Geen zoekfunctie: AES-GCM is niet-deterministisch, zoeken is niet mogelijk (POC 3.1)
public interface Poc1Repository extends JpaRepository<Poc1Entity, Long> {}
