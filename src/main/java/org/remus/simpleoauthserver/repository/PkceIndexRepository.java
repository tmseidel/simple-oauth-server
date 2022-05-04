package org.remus.simpleoauthserver.repository;

import org.remus.simpleoauthserver.entity.PkceIndex;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.Optional;

public interface PkceIndexRepository extends CrudRepository<PkceIndex, String> {

    Optional<PkceIndex> findByAccessCode(String accessCode);

    @Transactional
    @Modifying
    @Query("DELETE FROM PkceIndex m WHERE m.invalidationDate < :date")
    void deleteOldPkceEntries(@Param("date") Date date);


}
