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
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.service.UserNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component(Configuration.BEAN_NAME_USERBASED_DETAILSERVICE)
public class UserBasedDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserBasedDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<User> oneByEmail = userRepository.findOneByEmailAndActivated(s,true);
        User user = oneByEmail.orElseThrow(() -> new UserNotFoundException(String.format("User %s not found",s)));

        return new JWTUser(user);
    }




}
