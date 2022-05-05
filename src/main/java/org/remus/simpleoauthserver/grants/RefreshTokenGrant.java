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
package org.remus.simpleoauthserver.grants;

import io.jsonwebtoken.Claims;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.InvalidInputException;
import org.remus.simpleoauthserver.service.InvalidTokenException;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.remus.simpleoauthserver.service.TokenBinService;
import org.remus.simpleoauthserver.service.UserNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

import java.util.Optional;

import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;

@Component
public class RefreshTokenGrant extends OAuthGrant {

    @Value("${jwt.clientcredential.access.token.expiration}")
    private Long expiration;

    private final TokenBinService tokenBinService;

    public RefreshTokenGrant(ApplicationRepository applicationRepository, UserRepository userRepository, JwtTokenService jwtTokenService, PasswordEncoder passwordEncoder, TokenBinService tokenBinService) {
        super(applicationRepository, userRepository, jwtTokenService, passwordEncoder);
        this.tokenBinService = tokenBinService;
    }

    public AccessTokenResponse execute(MultiValueMap<String, String> body, String authorization) {
        String clientId = extractClientId(body, authorization);
        String clientSecret = extractClientSecret(body, authorization);
        String refreshToken = extractValue(body, "refresh_token").orElseThrow(() -> new InvalidInputException("refres_token parameter not set"));
        if (tokenBinService.isTokenInvalidated(refreshToken)) {
            throw new InvalidTokenException("The token is already invalidated.");
        }
        Optional<Application> application = applicationRepository.findApplicationByClientIdAndClientSecretAndActivated(clientId, clientSecret, true);
        if (application.isEmpty()) {
            throw new ApplicationNotFoundException("No application found");
        }
        Claims claims = jwtTokenService.getAllClaimsFromToken(refreshToken, JwtTokenService.TokenType.REFRESH);
        ApplicationType applicationType = ApplicationType.valueOf(claims.get("type", String.class));
        String userName = claims.getSubject();
        if (applicationType == ApplicationType.M2M) {
            if (claims.getSubject() == null
                    || !claims.getSubject().equals(clientId)) {
                throw new InvalidInputException("subject does not match");
            }
        } else if (applicationType == ApplicationType.REGULAR) {
            if (claims.get(CLIENT_ID, String.class) == null
                    || !claims.get(CLIENT_ID, String.class).equals(clientId)) {
                throw new InvalidInputException("client_id not correct");
            }
            Optional<User> foundUser = userRepository.findOneByEmailAndActivated(userName, true);
            if (foundUser.isEmpty()) {
                throw new UserNotFoundException(String.format("User %s not found", userName));
            }
        }
        AccessTokenResponse response = createResponse(userName, claims);
        tokenBinService.invalidateToken(refreshToken,claims.getExpiration());
        return response;
    }


}
