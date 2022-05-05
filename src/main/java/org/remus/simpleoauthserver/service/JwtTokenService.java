/**
 * Copyright(c) 2022 Tom Seidel, Remus Software
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.remus.simpleoauthserver.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenService {

    public enum TokenType {
        FORM,
        ACCESS,
        AUTH,
        REFRESH
    }

    @Value("${jwt.clientcredential.access.token.expiration}")
    private Long accessTokenExpiration;

    @Value("${jwt.authorization.auth.token.expiration}")
    private Long authTokenExpiration;

    @Value("${jwt.authorization.refresh.token.expiration}")
    private Long refreshTokenExpiration;

    @Value("${jwt.formsubmission.data.token.expiration}")
    private Long formSubmissionExpiration;

    @Value("${jwt.issuer}")
    private String issuer;

    private KeyService keyService;

    public JwtTokenService(KeyService keyService) {
        this.keyService = keyService;
    }

    public String createToken(String subject, Map<String,Object> data, TokenType type) {
        final Date createdDate = new Date();
        JwtBuilder jwtBuilder = Jwts.builder()
                .setClaims(data)
                .setSubject(subject)
                .setIssuer(issuer)
                .setIssuedAt(createdDate);
        switch (type) {
            case AUTH:
                jwtBuilder.setExpiration(calculateExpirationDate(authTokenExpiration))
                        .signWith(SignatureAlgorithm.HS512, keyService.getAuthorizationTokenKey());
                break;
            case FORM:
                jwtBuilder.setExpiration(calculateExpirationDate(formSubmissionExpiration))
                        .signWith(SignatureAlgorithm.HS512, keyService.getFormTokenKey());
                break;
            case ACCESS:
                jwtBuilder.setExpiration(calculateExpirationDate(accessTokenExpiration))
                        .signWith(SignatureAlgorithm.RS256, keyService.getPrivateKey());
                break;
            case REFRESH:
                jwtBuilder.setExpiration(calculateExpirationDate(refreshTokenExpiration))
                        .signWith(SignatureAlgorithm.HS512, keyService.getRefrehTokenKey());
                break;


        }
        return jwtBuilder.compact();
    }

    public static Date calculateExpirationDate(long expirationInSeconds) {
        return new Date(new Date().getTime() + expirationInSeconds * 1000);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver, TokenType type) {
        final Claims claims = getAllClaimsFromToken(token,type);
        return claimsResolver.apply(claims);
    }

    public Claims getAllClaimsFromToken(String token, TokenType type) {
        JwtParser parser = Jwts.parser();
        switch (type) {
            case FORM:
                parser.setSigningKey(keyService.getFormTokenKey());
                break;
            case ACCESS:
                parser.setSigningKey(keyService.getPublicKey());
                break;
            case AUTH:
                parser.setSigningKey(keyService.getAuthorizationTokenKey());
                break;
            case REFRESH:
                parser.setSigningKey(keyService.getRefrehTokenKey());
                break;
        }
        return parser.parseClaimsJws(token)
                .getBody();
    }
}
