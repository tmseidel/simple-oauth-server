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

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.request.InitialApplicationRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.server.ResponseStatusException;

import javax.inject.Inject;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@TestPropertySource(
        locations = "classpath:application-integrationtest.properties")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FirstStartControllerIntegrationTest {

    @Inject
    private FirstStartController testee;

    @Inject
    private ApplicationRepository applicationRepository;

    @Test
    @Order(1)
    void runWithInvalidPassword() {
        InitialApplicationRequest request = createValidRequest();
        // invalidate the token
        request.setInitialAuthToken("wrongToken");

        assertThrows(ResponseStatusException.class, () -> testee.run(request), "Expected a 401");
    }

    @Test
    @Order(2)
    void runHappyPath() throws NoSuchAlgorithmException, IOException {
        InitialApplicationRequest request = createValidRequest();

        testee.run(request);

        Application application = applicationRepository.findAllApplicationWithSuperAdminScope().iterator().next();

        assertNotNull(application);
    }

    @Test
    @Order(3)
    void runAfterHappyPath() {
        InitialApplicationRequest request = createValidRequest();

        assertThrows(ResponseStatusException.class, () -> testee.run(request), "Expected a 401");
    }

    private InitialApplicationRequest createValidRequest() {
        InitialApplicationRequest request = new InitialApplicationRequest();
        request.setInitialAuthToken("testToken");
        return request;
    }
}