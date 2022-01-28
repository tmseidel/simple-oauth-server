package org.remus.simpleoauthserver.service;

import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.remus.simpleoauthserver.service.JwtTokenService.TokenType.FORM;

@Service
public class TokenHelper {

    private JwtTokenService jwtTokenService;

    public TokenHelper(JwtTokenService jwtTokenService) {
        this.jwtTokenService = jwtTokenService;
    }

    public String encode(Map<String, Object> data) {
        return jwtTokenService.createToken("form",data, FORM);
    }

    public Map<String, Object> decode(String token, String... claims) {
        Map<String, Object> returnValue = new HashMap<>();
        Claims allClaimsFromToken1 = jwtTokenService.getAllClaimsFromToken(token,FORM);
        Arrays.stream(claims).forEach(e -> returnValue.put(e,allClaimsFromToken1.get(e)));
        return returnValue;
    }
}
