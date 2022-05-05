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

import org.remus.simpleoauthserver.repository.PkceIndexRepository;
import org.remus.simpleoauthserver.repository.TokenBinRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class DeleteTokenService {

    private TokenBinRepository repository;

    private PkceIndexRepository pkceIndexRepository;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public DeleteTokenService(TokenBinRepository repository, PkceIndexRepository pkceIndexRepository) {
        this.repository = repository;
        this.pkceIndexRepository = pkceIndexRepository;
    }


    /**
     * Executed once in an day. Delete all tokens that are expired.
     */
    @Scheduled(fixedRate = 86400000)
    public void deleteExpiredTokens() {
        if (logger.isInfoEnabled()) {
            logger.info("About to delete all expired tokens");
        }
        Date now = new Date();
        repository.deleteOldTokens(now);
        pkceIndexRepository.deleteOldPkceEntries(now);
    }
}
