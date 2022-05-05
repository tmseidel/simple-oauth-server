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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.remus.simpleoauthserver.entity.PkceIndex;
import org.remus.simpleoauthserver.repository.PkceIndexRepository;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PkceServiceTest {

    @Mock
    private PkceIndexRepository pkceIndexRepository;

    @InjectMocks
    private PkceService testee;
    private PkceIndex pkceIndex;

    @BeforeEach
    public void setup() {
        pkceIndex = new PkceIndex();
        pkceIndex.setCodeChallengeMethod("SHA256");
        pkceIndex.setAccessCode("12345");

        lenient().when(pkceIndexRepository.findByAccessCode("12345")).thenReturn(Optional.of(pkceIndex));
        lenient().when(pkceIndexRepository.findByAccessCode(not(eq("12345")))).thenReturn(Optional.empty());
    }

    @Test
    void isPkceAccessToken() {
        assertTrue(testee.isPkceAccessToken("12345"));
        assertFalse(testee.isPkceAccessToken("67890"));
    }

    @Test
    void checkVerifier() {
        pkceIndex.setCodeChallenge("yfEPnYhq9a7z33jRtnwXUYuiY7nWoEtr4BaVuFDjV1E");
        testee.checkVerifier("12345","OCsBdSZs0cpFEawNNswJakm8owM0iZmD4GooqiEQ7nI_bxTblKOFvO.3mLFy8arcR2~4P-71Xxb73VAYpDFP2XYiOFF5fm-_.ml-xZvMDSUrJZunr.ZXHH0-R8IzWUY2");

        pkceIndex.setCodeChallenge("OM5BZe5OPOvesDUuZ1wMO5NF76YZP4ieAZxKhQrCjyk");
        testee.checkVerifier("12345","NejTPj1PLo~Mm6sE2QOrC8vzqGi8tx5LR98MJToDpfuwK6-PQSYos4bEKC8FbptFanoBgNDqgQHnDED4ZHbZ848A1vCQ2IG375Zr8sp2Kts_Mmw6d0HpHqgVmyNNfSgZ");

        pkceIndex.setCodeChallenge("yCOILGdWMxXAJYdLeIsu5P0IH5IkbDlg6IiVezjAtT0");
        testee.checkVerifier("12345","QNk7t5ZUu69pMOW1S9LPZx88Wzt9CDQCmoIlT-6YOwSvEZqjEyLn2j.0iIvUn5cTG0fNluH3wOvrI3nWM7c7Od1lioPLJzPfk9YE_eNgvyeRCKQOG.lZQ2nYGifit3-U0H");

        pkceIndex.setCodeChallenge("bqzl9kwMvVHTt0IFdV0uHpMk5vfhKL0C510BpUPLUPk");
        testee.checkVerifier("12345","_j5508LIkkYIf5oSrjb0vai0yQj~SbF6H4YWOYBwoMPhlGo3Oq-6lhtXlkNaBu95hSOOe.");

    }
}