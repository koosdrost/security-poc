package com.demo.security.poc5;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface Poc5Repository extends JpaRepository<Poc5Entity, Long> {

    /**
     * Zoekt op 'naam' via de DeterministicConverter.
     * Hibernate versleutelt de zoekterm vóór de query — werkt omdat encryptie deterministisch is.
     */
    List<Poc5Entity> findByNaam(String plaintext);

    /** Zoekt op de HMAC-index van 'notitie', niet op de versleutelde data zelf. */
    List<Poc5Entity> findByNotitieHmac(String hmac);
}
