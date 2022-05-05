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

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.Map;

import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;

@Controller
public class ClientCredentialsGrant extends OAuthGrant {


    public ClientCredentialsGrant(ApplicationRepository applicationRepository, UserRepository userRepository, JwtTokenService jwtTokenService, PasswordEncoder passwordEncoder) {
        super(applicationRepository, userRepository, jwtTokenService, passwordEncoder);
    }

    public AccessTokenResponse execute(MultiValueMap<String, String> data, String authorizationHeader) {
        String clientId = extractClientId(data, authorizationHeader);
        String clientSecret = extractClientSecret(data,authorizationHeader);
        String[] scopes = extractValue(data, "scope").orElse("").split(",");

        Application application = applicationRepository.findApplicationByClientIdAndClientSecretAndActivated(clientId, clientSecret, true)
                .orElseThrow(() -> new ApplicationNotFoundException(String.format("The application with client_id %s was not found",clientId)));
        checkScope(scopes, application);
        Map<String,Object> claims = new HashMap<>();
        claims.put("type",application.getApplicationType().name());
        claims.put("scope",String.join(",",scopes));

        return createResponse(application.getClientId(), claims);

    }
}
