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
import org.junit.jupiter.api.io.TempDir;
import org.remus.simpleoauthserver.config.KeyServiceConfig;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

class KeyServiceTest {

    private KeyService testee;

    @TempDir
    Path tmpDir;

    private KeyServiceConfig config;

    @BeforeEach
    public void setup() throws NoSuchAlgorithmException, IOException {
        config = new KeyServiceConfig();
        config.setBasePath(tmpDir.toAbsolutePath().toString());
        config.setJwtKeysLocation(Paths.get(tmpDir.toAbsolutePath().toString(),"keys.json").toString());
        config.setPrivateKeyLocation(Paths.get(tmpDir.toAbsolutePath().toString(),"private.key").toString());
        config.setPublicKeyLocation(Paths.get(tmpDir.toAbsolutePath().toString(),"public.key").toString());
        var initialKeys = new KeyService(config);
        initialKeys.init();
        initialKeys.createKeyPair();

    }

    @Test
    void authorizationKey() throws NoSuchAlgorithmException, IOException {
        testee = new KeyService(config);

        var authorizationTokenKey = testee.getAuthorizationTokenKey();
        assertThat(authorizationTokenKey).hasSizeGreaterThanOrEqualTo(32);
    }
    @Test
    void formTokenKey() throws NoSuchAlgorithmException, IOException {
        testee = new KeyService(config);

        var formTokenKey = testee.getFormTokenKey();
        assertThat(formTokenKey).hasSizeGreaterThanOrEqualTo(32);
    }
    @Test
    void refreshTokenKey() throws NoSuchAlgorithmException, IOException {
        testee = new KeyService(config);

        var refreshTokenKey = testee.getRefrehTokenKey();
        assertThat(refreshTokenKey).hasSizeGreaterThanOrEqualTo(32);
    }
    @Test
    void checkPrivateAndPublic() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        testee = new KeyService(config);

        // create a challenge
        var challenge = new byte[10000];
        ThreadLocalRandom.current().nextBytes(challenge);

        var sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(testee.getPrivateKey());
        sig.update(challenge);
        var signature = sig.sign();

        sig.initVerify(testee.getPublicKey());
        sig.update(challenge);

        // we simply check if the public key can verify the signature
        assertThat(sig.verify(signature)).isTrue();
    }
}