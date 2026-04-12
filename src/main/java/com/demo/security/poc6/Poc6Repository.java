package com.demo.security.poc6;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface Poc6Repository extends JpaRepository<Poc6Entity, Long> {

    /** Zoekt op HMAC-index van 'naam'. */
    List<Poc6Entity> findByNaamHmac(String hmac);

    /** Zoekt op HMAC-index van 'notitie'. */
    List<Poc6Entity> findByNotitieHmac(String hmac);
}
