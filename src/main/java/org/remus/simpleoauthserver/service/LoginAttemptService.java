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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.Thread.sleep;

@Service
public class LoginAttemptService {

    @Value("${login.max.attempts}")
    private int maxAttempts;

    @Value("${login.blocked.period}")
    private int blockedPeriod;

    private static final Object MUTEX = new Object();

    private static class ExpirationEntry {
        LocalDateTime expiration;
        int count;

        public ExpirationEntry() {
            this.expiration = LocalDateTime.now();
            this.count = 0;
        }
    }





    Map<String, ExpirationEntry> attemptsCache = new HashMap<>();



    public LoginAttemptService() {
        super();
    }


    @PostConstruct
    public void scheduleCheck() {
        new Thread(() -> {
            while(true) {
                List<String> elements2Delete = new ArrayList<>();
                attemptsCache.forEach((e, f) -> {
                            if (f.expiration.isBefore(LocalDateTime.now())) {
                                elements2Delete.add(e);
                            }
                        }
                );
                synchronized (MUTEX) {
                    elements2Delete.forEach(attemptsCache::remove);
                }
                try {
                    sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

        }).start();
    }

    public void loginSucceeded(String key) {
        attemptsCache.remove(key);
    }

    public void loginFailed(String key) {
        synchronized (MUTEX) {
            attemptsCache.computeIfAbsent(key, k -> new ExpirationEntry());
            attemptsCache.get(key).count = attemptsCache.get(key).count +1;
            attemptsCache.get(key).expiration = LocalDateTime.now().plusSeconds(blockedPeriod);
        }


    }

    public boolean isBlocked(String key) {
        synchronized (MUTEX) {
            return attemptsCache.containsKey(key) && attemptsCache.get(key).count >= maxAttempts;
        }
    }
}