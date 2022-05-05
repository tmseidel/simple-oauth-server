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
package org.remus.simpleoauthserver.entity.projection;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.remus.simpleoauthserver.entity.Scope;
import org.springframework.data.rest.core.config.Projection;

import java.util.Set;

@Projection(name = "configclient", types= Application.class)
public interface ApplicationProjection {
    Integer getId();

    String getName();

    String getClientId();

    Set<String> getLoginUrls();

    String getLogoutUrl();

    String getCss();

    boolean isActivated();

    String getClientSecret();

    Set<Scope> getScopeList();

    ApplicationType getApplicationType();

    boolean isTrustworthy();

}
