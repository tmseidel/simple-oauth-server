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
