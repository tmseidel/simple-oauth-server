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


import org.remus.simpleoauthserver.request.InitialApplicationRequest;
import org.remus.simpleoauthserver.response.InitialApplicationResponse;
import org.remus.simpleoauthserver.service.KeyService;
import org.remus.simpleoauthserver.service.SetupService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@RestController
@RequestMapping(path = "/auth/firstStart")
public class FirstStartController {
    private SetupService setupService;

    private KeyService keyService;

    public FirstStartController(SetupService setupService, KeyService keyService) {
        this.setupService = setupService;
        this.keyService = keyService;
    }


    @PostMapping(path = "run")
    public InitialApplicationResponse run(@RequestBody InitialApplicationRequest request) throws NoSuchAlgorithmException, IOException {
        if (setupService.canCreateInitialSuperAdmin(request.getInitialAuthToken())) {
            keyService.createKeyPair();
            return setupService.createInitialApplication();
        } else {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "This operation is not available.");
        }
    }

    @GetMapping(produces = MediaType.TEXT_PLAIN_VALUE, path = "pub")
    public ResponseEntity<byte[]> streamPublicKey() {
        try {
            byte[] bytes = keyService.getPublicKey().getEncoded();
            return ResponseEntity.ok().contentLength(bytes.length).contentType(MediaType.APPLICATION_OCTET_STREAM).header("Content-Disposition", "attachment;filename=\"publicKey.pub\"").body(bytes);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping(produces = MediaType.TEXT_PLAIN_VALUE, path = "pubBase64")
    public ResponseEntity<String> streamPublicKeyBase64() {
        try {
            byte[] bytes = keyService.getPublicKey().getEncoded();
            String b64PublicKey = Base64.getEncoder().encodeToString(bytes);
            return ResponseEntity.ok().contentLength(b64PublicKey.getBytes().length).contentType(MediaType.TEXT_PLAIN).body(b64PublicKey);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }
}
