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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.remus.simpleoauthserver.controller.ValueExtractionUtil;
import org.springframework.util.MultiValueMap;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FlowControllerTest {

    private GrantController testee;

    @BeforeEach
    public void setup() {
        testee = new GrantController();
    }

    @Test
    void isClientCredentialFlow() {
        MultiValueMap<String, String> mock = mock(MultiValueMap.class);
        when(mock.getFirst("grant_type")).thenReturn(GrantController.CLIENT_CREDENTIALS);

        assertTrue(testee.isClientCredentialGrant(mock));
        assertFalse(testee.isAuthorizationGrant(mock));
    }

    @Test
    void isAuthorizationFlow() {
        MultiValueMap<String, String> mock = mock(MultiValueMap.class);
        when(mock.getFirst("grant_type")).thenReturn(GrantController.AUTHORIZATION_CODE);

        assertFalse(testee.isClientCredentialGrant(mock));
        assertTrue(testee.isAuthorizationGrant(mock));
    }

    @Test
    void extractValue() {
        MultiValueMap<String, String> mock = mock(MultiValueMap.class);
        when(mock.getFirst("junit")).thenReturn("theValue");
        assertEquals(Optional.of("theValue"), ValueExtractionUtil.extractValue(mock, "junit"));
        assertEquals(Optional.empty(), ValueExtractionUtil.extractValue(mock, "notPresent"));

    }
}