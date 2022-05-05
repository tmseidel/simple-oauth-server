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
package org.remus.simpleoauthserver.security;

import org.remus.simpleoauthserver.config.Configuration;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component(Configuration.BEAN_NAME_APPBASED_DETAILSERVICE)
public class AppBasedDetailService implements UserDetailsService {
    private ApplicationRepository applicationRepository;

    public AppBasedDetailService(ApplicationRepository applicationRepository) {
        this.applicationRepository = applicationRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Application application = applicationRepository.findApplicationByClientId(s).orElseThrow(() -> new ApplicationNotFoundException(String.format("Application %s not found", s)));
        User syntheticApplicationUser = new User();
        syntheticApplicationUser.setId(Integer.MAX_VALUE);
        syntheticApplicationUser.setScopeList(Set.of(application.getScopeList().toArray(new Scope[0])));
        syntheticApplicationUser.setName(s);

        return new JWTUser(syntheticApplicationUser);
    }
}
