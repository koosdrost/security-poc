package com.demo.security.poc3;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface Poc3Repository extends JpaRepository<Poc3Entity, Long> {

    /** Zoekt op de HMAC-index kolom, niet op de versleutelde data zelf. */
    List<Poc3Entity> findByVertrouwelijkHmac(String hmac);
}
