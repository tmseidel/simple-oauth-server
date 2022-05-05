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

import org.remus.simpleoauthserver.entity.TokenBin;
import org.remus.simpleoauthserver.repository.TokenBinRepository;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class TokenBinService {

    private final TokenBinRepository tokenBinRepository;

    public TokenBinService(TokenBinRepository tokenBinRepository) {
        this.tokenBinRepository = tokenBinRepository;
    }

    public void invalidateToken(String token, Date expirationDateFromToken) {
        TokenBin bin = new TokenBin();
        bin.setInvalidationDate(expirationDateFromToken);
        bin.setToken(token);
        tokenBinRepository.save(bin);
    }

    public boolean isTokenInvalidated(String token) {
        List<TokenBin> tokenBinByIndexHelp = tokenBinRepository.findTokenBinByIndexHelp(TokenBin.calculateIndex(token));
        return tokenBinByIndexHelp.stream().anyMatch(e -> e.getToken().equals(token));
    }


}
