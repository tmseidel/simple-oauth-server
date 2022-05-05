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
package org.remus.simpleoauthserver;

import org.apache.commons.lang3.RandomUtils;
import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;

import java.util.HashSet;
import java.util.Set;

public class TestUtils {

    public static class TestUser {
        private final String userName;
        private final String passWord;
        private final String clientId;
        private final String[] scope;
        private String codeChallenge;

        public TestUser(String userName, String passWord, String clientId, String... scope) {
            this.userName = userName;
            this.passWord = passWord;
            this.clientId = clientId;
            this.scope = scope;
        }

        public String getUserName() {
            return userName;
        }

        public String getPassWord() {
            return passWord;
        }

        public String getClientId() {
            return clientId;
        }

        public String[] getScope() {
            return scope;
        }

        public String getCodeChallenge() {
            return codeChallenge;
        }

        public void setCodeChallenge(String codeChallenge) {
            this.codeChallenge = codeChallenge;
        }
    }



    public static Set<Scope> createScope(String name) {
        HashSet<Scope> scopes = new HashSet<>();
        Scope scope = new Scope();
        scope.setName(name);
        scopes.add(scope);
        return scopes;
    }

    public static Organization createOrganization(int id) {
        Organization org = new Organization();
        org.setName("Junit-Org");
        org.setId(id);
        return org;
    }

    public static User createUser(String name, String mail) {
        User user = new User();
        user.setId(RandomUtils.nextInt());
        user.setName(name);
        user.setEmail(mail);
        user.setActivated(true);
        return user;
    }



}
