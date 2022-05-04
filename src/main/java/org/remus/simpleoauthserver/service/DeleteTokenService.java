package org.remus.simpleoauthserver.service;

import org.remus.simpleoauthserver.repository.PkceIndexRepository;
import org.remus.simpleoauthserver.repository.TokenBinRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class DeleteTokenService {

    private TokenBinRepository repository;

    private PkceIndexRepository pkceIndexRepository;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public DeleteTokenService(TokenBinRepository repository, PkceIndexRepository pkceIndexRepository) {
        this.repository = repository;
        this.pkceIndexRepository = pkceIndexRepository;
    }


    /**
     * Executed once in an day. Delete all tokens that are expired.
     */
    @Scheduled(fixedRate = 86400000)
    public void deleteExpiredTokens() {
        if (logger.isInfoEnabled()) {
            logger.info("About to delete all expired tokens");
        }
        Date now = new Date();
        repository.deleteOldTokens(now);
        pkceIndexRepository.deleteOldPkceEntries(now);
    }
}
