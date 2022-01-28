package org.remus.simpleoauthserver.service;

import org.remus.simpleoauthserver.entity.TokenBin;
import org.remus.simpleoauthserver.repository.TokenBinRepository;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class TokenBinService {

    private final TokenBinRepository tokenBinRepository;

    public TokenBinService(TokenBinRepository tokenBinRepository) {
        this.tokenBinRepository = tokenBinRepository;
    }

    public void invalidateToken(String token, Date expirationDateFromToken) {
        TokenBin bin = new TokenBin();
        bin.setInvalidationDate(expirationDateFromToken);
        bin.setToken(token);
        tokenBinRepository.save(bin);
    }

    public boolean isTokenInvalidated(String token) {
        List<TokenBin> tokenBinByIndexHelp = tokenBinRepository.findTokenBinByIndexHelp(TokenBin.calculateIndex(token));
        return tokenBinByIndexHelp.stream().anyMatch(e -> e.getToken().equals(token));
    }


}
