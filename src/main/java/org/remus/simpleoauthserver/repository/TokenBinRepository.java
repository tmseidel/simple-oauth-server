package org.remus.simpleoauthserver.repository;

import org.remus.simpleoauthserver.entity.TokenBin;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.web.bind.annotation.CrossOrigin;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@CrossOrigin(origins = "*")
public interface TokenBinRepository extends CrudRepository<TokenBin, UUID> {

    Optional<TokenBin> findTokenBinByToken(String token);

    List<TokenBin> findTokenBinByIndexHelp(String indexHelp);

    @Transactional
    @Modifying
    @Query("DELETE FROM TokenBin m WHERE m.invalidationDate < :date")
    void deleteOldTokens(@Param("date") Date date);

}
