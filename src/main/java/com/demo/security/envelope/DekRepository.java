package com.demo.security.envelope;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface DekRepository extends JpaRepository<DataEncryptionKey, Long> {

    Optional<DataEncryptionKey> findByContextAndActiveTrue(String context);

    Optional<DataEncryptionKey> findByContextAndVersion(String context, int version);

    List<DataEncryptionKey> findByContext(String context);

    @Query("SELECT COALESCE(MAX(d.version), 0) FROM DataEncryptionKey d WHERE d.context = :context")
    int findMaxVersionByContext(String context);

    @Modifying
    @Query("UPDATE DataEncryptionKey d SET d.active = false WHERE d.context = :context")
    void deactivateAllByContext(String context);
}
