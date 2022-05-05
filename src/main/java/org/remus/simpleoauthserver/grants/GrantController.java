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

import org.remus.simpleoauthserver.controller.ValueExtractionUtil;
import org.remus.simpleoauthserver.service.InvalidInputException;
import org.remus.simpleoauthserver.service.UnsupportedGrantTypeException;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;

import java.util.Set;

import static java.lang.String.format;
import static org.owasp.encoder.Encode.forJava;

/**
 * This controller is used in the Token-Endpoint to decide which Flow is in progress.
 */
@Controller
public class GrantController {

    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String REFRESH_TOKEN = "refresh_token";
    private static final Set<String> VALID_GRANT_TYPES = Set.of(CLIENT_CREDENTIALS, AUTHORIZATION_CODE, REFRESH_TOKEN);

    public boolean isClientCredentialGrant(MultiValueMap<String, String> data) {
        String type = getGrantType(data);
        return CLIENT_CREDENTIALS.equals(type);
    }

    public boolean isAuthorizationGrant(MultiValueMap<String, String> data) {
        String type = getGrantType(data);
        return AUTHORIZATION_CODE.equals(type);
    }

    public boolean isRefrehTokenGrant(MultiValueMap<String, String> data) {
        String type = getGrantType(data);
        return REFRESH_TOKEN.equals(type);
    }

    private String getGrantType(MultiValueMap<String, String> data) {
        String type = ValueExtractionUtil.extractValue(data, "grant_type").orElseThrow(() -> new InvalidInputException("No grant_type present"));
        if (!VALID_GRANT_TYPES.contains(type)) {
            throw new UnsupportedGrantTypeException(format("Grant type %s not supported", forJava(type)));
        }
        return type;
    }

}
