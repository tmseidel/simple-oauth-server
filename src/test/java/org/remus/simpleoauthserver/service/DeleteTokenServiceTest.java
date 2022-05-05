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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.remus.simpleoauthserver.repository.PkceIndexRepository;
import org.remus.simpleoauthserver.repository.TokenBinRepository;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class DeleteTokenServiceTest {

    @Mock
    private TokenBinRepository tokenBinRepository;

    @Mock
    private PkceIndexRepository pkceIndexRepository;

    @InjectMocks
    private DeleteTokenService testee;



    @Test
    void deleteExpiredTokens() {
        testee.deleteExpiredTokens();

        ArgumentCaptor<Date> captor = ArgumentCaptor.forClass(Date.class);
        verify(tokenBinRepository).deleteOldTokens(captor.capture());
        LocalDateTime value = captor.getValue().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        LocalDateTime now = LocalDateTime.now();
        assertTrue(value.isBefore(now) && value.isAfter(now.minusSeconds(10)));

        verify(tokenBinRepository).deleteOldTokens(captor.capture());
        value = captor.getValue().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        assertTrue(value.isBefore(now) && value.isAfter(now.minusSeconds(10)));
    }
}