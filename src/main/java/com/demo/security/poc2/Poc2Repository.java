package com.demo.security.poc2;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface Poc2Repository extends JpaRepository<Poc2Entity, Long> {

    /**
     * Zoekt op de versleutelde waarde.
     * Hibernate past de DeterministicConverter toe op de zoekwaarde vóór de query,
     * waardoor de ciphertext vergeleken wordt — dit werkt omdat encryptie deterministisch is.
     */
    List<Poc2Entity> findByVertrouwelijk(String plaintext);
}
