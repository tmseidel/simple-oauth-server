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
package org.remus.simpleoauthserver.controller;

import org.remus.simpleoauthserver.grants.AuthorizationGrant;
import org.remus.simpleoauthserver.grants.ClientCredentialsGrant;
import org.remus.simpleoauthserver.grants.GrantController;
import org.remus.simpleoauthserver.grants.RefreshTokenGrant;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.response.ErrorResponse;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.InvalidTokenException;
import org.remus.simpleoauthserver.service.OAuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class TokenEndpoint {

    private GrantController flowController;

    private ClientCredentialsGrant clientCredentialsGrant;

    private AuthorizationGrant authorizationGrant;

    private RefreshTokenGrant refreshTokenGrant;

    public TokenEndpoint(GrantController flowController,
                         ClientCredentialsGrant clientCredentialsGrant,
                         AuthorizationGrant authorizationGrant,
                         RefreshTokenGrant refreshTokenGrant) {
        this.flowController = flowController;
        this.clientCredentialsGrant = clientCredentialsGrant;
        this.authorizationGrant = authorizationGrant;
        this.refreshTokenGrant = refreshTokenGrant;
    }

    @PostMapping(path = "/auth/oauth/token",
            produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public AccessTokenResponse acquireAccessToken(
            @RequestBody MultiValueMap<String, String> body, HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (flowController.isClientCredentialGrant(body)) {
            return clientCredentialsGrant.execute(body, authorization);
        } else if (flowController.isAuthorizationGrant(body)) {
            return authorizationGrant.execute(body,authorization);
        } else if (flowController.isRefrehTokenGrant(body)) {
            return refreshTokenGrant.execute(body,authorization);
        }
        return new AccessTokenResponse();

    }


    @ResponseBody
    @ExceptionHandler({OAuthException.class, ApplicationNotFoundException.class})
    public ResponseEntity<ErrorResponse> handleUnsupportedGrantTypeException(HttpServletRequest request, Throwable ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return new ResponseEntity<>(new ErrorResponse("invalid_client", ex.getMessage()), status);
    }
    @ResponseBody
    @ExceptionHandler({InvalidTokenException.class})
    public ResponseEntity<ErrorResponse> handleInvalidTokenException(HttpServletRequest request, Throwable ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return new ResponseEntity<>(new ErrorResponse("invalid_grant", ex.getMessage()), status);
    }

}
