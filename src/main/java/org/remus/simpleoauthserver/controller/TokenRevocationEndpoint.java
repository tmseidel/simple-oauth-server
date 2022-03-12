package org.remus.simpleoauthserver.controller;

import io.jsonwebtoken.Claims;
import org.remus.simpleoauthserver.service.InvalidInputException;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.remus.simpleoauthserver.service.TokenBinService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;

@RestController
public class TokenRevocationEndpoint {

    private TokenBinService tokenBinService;
    private JwtTokenService tokenService;

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenRevocationEndpoint.class);

    @Inject
    public TokenRevocationEndpoint(TokenBinService tokenBinService, JwtTokenService tokenService) {
        this.tokenBinService = tokenBinService;
        this.tokenService = tokenService;
    }

    @PostMapping(path = "/auth/oauth/revoke",
           consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public void revokeToken(@RequestBody MultiValueMap<String, String> body, HttpServletRequest request) {
        String token = extractValue(body, "token").orElseThrow(() -> new InvalidInputException("Token must be present in request"));
        String tokenTypeHint = extractValue(body, "token_type_hint").orElse("access_token");
        JwtTokenService.TokenType tokenType[] = new JwtTokenService.TokenType[2];
        if ("access_token".equals(tokenTypeHint)) {
            tokenType[0] = JwtTokenService.TokenType.ACCESS;
            tokenType[1] = JwtTokenService.TokenType.REFRESH;
        } else if ("refresh_token".equals(tokenTypeHint)) {
            tokenType[0] = JwtTokenService.TokenType.REFRESH;
            tokenType[1] = JwtTokenService.TokenType.ACCESS;
        }
        if (tokenType != null) {
            Claims claims = null;
                for (JwtTokenService.TokenType type : tokenType) {
                    try {
                        claims = tokenService.getAllClaimsFromToken(token, type);
                        break;
                    } catch (Exception e) {
                        // we skip all errors that occur while reading the token
                        LOGGER.warn("Error while decompiling token {} with type {}", token, tokenType, e);
                    }
                }
            if (claims != null) {
                tokenBinService.invalidateToken(token,claims.getExpiration());
            }
        }


    }

}
