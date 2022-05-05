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

import org.apache.commons.lang3.StringUtils;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.response.TokenType;
import org.remus.simpleoauthserver.service.InvalidGrandException;
import org.remus.simpleoauthserver.service.InvalidInputException;
import org.remus.simpleoauthserver.service.InvalidIpException;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.remus.simpleoauthserver.service.ScopeNotFoundException;
import org.remus.simpleoauthserver.service.UserLockedException;
import org.remus.simpleoauthserver.service.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.MultiValueMap;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import static org.owasp.encoder.Encode.forJava;
import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;

public abstract class OAuthGrant {

    public static final String BASIC_WITH_WHITESPACE = "basic ";

    public static final String CLIENT_ID = "client_id";
    public static final String CODE_CHALLENGE = "code_challenge";

    public static final String REDIRECT_URI = "redirect_uri";
    public static final String CODE = "code";
    public static final String SCOPE = "scope";

    protected ApplicationRepository applicationRepository;

    protected UserRepository userRepository;

    protected JwtTokenService jwtTokenService;

    protected PasswordEncoder passwordEncoder;

    @Value("${jwt.clientcredential.access.token.expiration}")
    private Long expiration;

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthGrant.class);

    protected OAuthGrant(ApplicationRepository applicationRepository, UserRepository userRepository, JwtTokenService jwtTokenService, PasswordEncoder passwordEncoder) {
        this.applicationRepository = applicationRepository;
        this.userRepository = userRepository;
        this.jwtTokenService = jwtTokenService;
        this.passwordEncoder = passwordEncoder;
    }

    protected void checkScope(String[] scopes, Application application) {
        Set<String> scopesAsString = application.getScopeList().stream().map(Scope::getName).collect(Collectors.toSet());
        boolean requestedScopesAreValid = Arrays.stream(scopes).anyMatch(scopesAsString::contains);
        if (!requestedScopesAreValid) {
            throw new InvalidGrandException(String.format("The requested scopes %s are not available", scopes));
        }
    }

    public User checkUser(String username, String password, String clientId, String ipAdress) {
        Optional<User> user = userRepository.findOneByEmail(username);

        User foundUser = user.orElseThrow(() -> new UserNotFoundException("Error checking user, Either passowrd, username or client-id does not match."));
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("checkUser() called with: username = [{}], clientId = [{}], ipAdress = [{}]", forJava(username), forJava(clientId), forJava(ipAdress));
        }
        if (!StringUtils.isEmpty(foundUser.getOrganization().getIpRestriction())) {
            try {
                if (!ipAdress.matches(foundUser.getOrganization().getIpRestriction())) {
                    throw new InvalidIpException(MessageFormat.format("The ip {0} doesn''t match the given ip-restriction {1}", forJava(ipAdress), foundUser.getOrganization().getIpRestriction()));
                }
            } catch (PatternSyntaxException e) {
                throw new InvalidIpException(MessageFormat.format("The pattern {1} doesn''t compile for user {0}", foundUser.getId(), foundUser.getOrganization().getIpRestriction()));
            }
        }
        if (!foundUser.isActivated()) {
            throw new UserLockedException(MessageFormat.format("The user {0} is locked. Exiting", foundUser.getEmail()));
        }
        if (passwordEncoder.matches(password, foundUser.getPassword())) {
            return foundUser;
        }
        throw new UserNotFoundException("Error checking user, Either password, username or client-id does not match.");

    }

    public void checkScope(User targetUser, String[] scopes) {
        Set<String> stringSet = targetUser.getScopeList().stream().map(Scope::getName).collect(Collectors.toSet());
        for (String scope : scopes) {
            if (!stringSet.contains(scope)) {
                throw new ScopeNotFoundException("The requested scope " + scope + " was not found for user " + targetUser.getEmail());
            }
        }
    }

    public boolean needsUserPermissionForApp(User user, String clientId) {
        Application applicationByClientId = applicationRepository.findApplicationByClientId(clientId).orElseThrow();
        return !user.getApplications().contains(applicationByClientId) && !applicationByClientId.isTrustworthy();
    }

    public static String extractClientSecret(MultiValueMap<String, String> data, String authorizationHeader) {
        String clientSecret = null;
        if (!StringUtils.isEmpty(authorizationHeader) && authorizationHeader.toLowerCase().startsWith(BASIC_WITH_WHITESPACE)) {
            String s = new String(Base64.getDecoder().decode(authorizationHeader.replaceFirst("(?i)" + BASIC_WITH_WHITESPACE,"")));
            if (!StringUtils.isEmpty(s)) {
                String[] split = s.split(":");
                if (split.length == 2) {
                    clientSecret = split[1];
                }
            }
        }
        if (clientSecret == null) {
            clientSecret = extractValue(data, "client_secret").orElse(null);
        }
        return clientSecret;
    }

    public static String extractClientId(MultiValueMap<String, String> data, String authorizationHeader) {
        String clientId = null;
        if (!StringUtils.isEmpty(authorizationHeader) && authorizationHeader.toLowerCase().startsWith(BASIC_WITH_WHITESPACE)) {
            String s = new String(Base64.getDecoder().decode(authorizationHeader.replaceFirst("(?i)" + BASIC_WITH_WHITESPACE,"")));
            if (!StringUtils.isEmpty(s)) {
                String[] split = s.split(":");
                if (split.length == 2) {
                    clientId = split[0];
                }
            }
        }
        if (clientId == null) {
            clientId = extractValue(data, CLIENT_ID).orElseThrow(() -> new InvalidInputException("No client_id present"));
        }
        return clientId;
    }

   protected AccessTokenResponse createResponse(String userName, Map<String,Object> tokenData) {
        String accessToken = jwtTokenService.createToken(userName, tokenData, JwtTokenService.TokenType.ACCESS);
        String refreshToken = jwtTokenService.createToken(userName, tokenData, JwtTokenService.TokenType.REFRESH);
        AccessTokenResponse response = new AccessTokenResponse();
        response.setTokenType(TokenType.BEARER.getStringValue());
        response.setRefreshToken(refreshToken);
        response.setAccessToken(accessToken);
        response.setExpiration(Math.toIntExact(expiration));
        return response;
    }



}
