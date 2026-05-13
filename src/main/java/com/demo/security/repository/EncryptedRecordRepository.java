package com.demo.security.repository;

import com.demo.security.domain.EncryptedRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface EncryptedRecordRepository extends JpaRepository<EncryptedRecord, Long> {

    /** Zoekt op HMAC-index van {@code naam}. */
    List<EncryptedRecord> findByNaamHmac(String hmac);

    /** Zoekt op HMAC-index van {@code notitie}. */
    List<EncryptedRecord> findByNotitieHmac(String hmac);

    /**
     * Zoekt op ID via JPQL zodat Hibernate-filters van kracht blijven.
     * {@code EntityManager.find()} bypast filters; een JPQL-query niet.
     */
    @Query("SELECT r FROM EncryptedRecord r WHERE r.id = :id")
    Optional<EncryptedRecord> findByIdMetFilter(@Param("id") Long id);
}
