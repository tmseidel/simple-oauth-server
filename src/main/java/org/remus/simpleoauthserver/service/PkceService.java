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

import org.apache.commons.lang3.StringUtils;
import org.remus.simpleoauthserver.entity.PkceIndex;
import org.remus.simpleoauthserver.repository.PkceIndexRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
public class PkceService {

    @Value("${jwt.authorization.auth.token.expiration}")
    private Long authTokenExpiration;

    private PkceIndexRepository pkceIndexRepository;

    public PkceService(PkceIndexRepository pkceIndexRepository) {
        this.pkceIndexRepository = pkceIndexRepository;
    }

    public boolean isPkceAccessToken(String accessToken) {
        return pkceIndexRepository.findByAccessCode(accessToken).isPresent();
    }

    public void checkVerifier(String accessCode, String codeVerifier) {
        PkceIndex pkceIndex = pkceIndexRepository.findByAccessCode(accessCode).orElseThrow(() -> new InvalidTokenException("Access code not found for verifiication"));
        String codeChallenge = pkceIndex.getCodeChallenge();
        calculateVerifier(codeChallenge, codeVerifier);
    }

    private void calculateVerifier(String codeChallenge, String codeVerifier) {
        // some clients does not fill up the mod 4 characters with '='
        String fulFilledChallenge = codeChallenge + StringUtils.repeat('=', (4 - (codeChallenge.length() % 4)) % 4);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            String urlEncoded = Base64.getUrlEncoder().encodeToString(bytes);
            boolean equals = StringUtils.equals(urlEncoded, fulFilledChallenge);
            if (!equals) {
                throw new PkceFailedException("PKCE Code-Challenge was not successful.");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA256 Algorithm not found", e);
        }
    }

    public void createEntry(String authorizationToken, String codeChallenge) {
        PkceIndex pkceIndex = new PkceIndex();
        pkceIndex.setCodeChallenge(codeChallenge);
        pkceIndex.setAccessCode(authorizationToken);
        pkceIndex.setCodeChallengeMethod("S256");
        pkceIndex.setInvalidationDate(JwtTokenService.calculateExpirationDate(authTokenExpiration));
        pkceIndexRepository.save(pkceIndex);
    }

    public void invalidateToken(String code) {
        if (pkceIndexRepository.existsById(code)) {
            pkceIndexRepository.deleteById(code);
        }
    }
}
