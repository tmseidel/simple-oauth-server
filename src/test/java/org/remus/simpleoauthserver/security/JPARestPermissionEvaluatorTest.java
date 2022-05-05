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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.remus.simpleoauthserver.TestUtils;
import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.User;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.remus.simpleoauthserver.TestUtils.createUser;

class JPARestPermissionEvaluatorTest {

    private Organization organization;
    private User orgAdmin;
    private User normalUser;
    private JPARestPermissionEvaluator testee;
    private Organization organization2;
    private User superAdmin;

    @BeforeEach
    public void setup() {
        organization = TestUtils.createOrganization(10);
        organization2 = TestUtils.createOrganization(11);
        orgAdmin = createUser("Hans Dampf", "hans.dampf@example.org");
        orgAdmin.setScopeList(TestUtils.createScope(ScopeRanking.ORGANIZATION_OWNER_SCOPE));
        orgAdmin.setOrganization(organization);
        normalUser = createUser("John Doe", "john.doe@example.org");
        normalUser.setScopeList(TestUtils.createScope("some.api.scope"));
        normalUser.setOrganization(organization);
        superAdmin = createUser("Jane Smith", "jane.smith@example.org");
        superAdmin.setScopeList(TestUtils.createScope(ScopeRanking.SUPERADMIN_SCOPE));
        orgAdmin.postLoad();
        normalUser.postLoad();
        superAdmin.postLoad();
        testee = new JPARestPermissionEvaluator();
    }

    @Test
    void hasOrgaizationAdminRightForUserEditing() {
        JWTUser jwtUser = new JWTUser(orgAdmin);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);
        normalUser.setActivated(false);

        boolean hasPermission = testee.hasPermission(authentication, normalUser, JPARestPermissionEvaluator.WRITE);

        assertTrue(hasPermission);
    }

    @Test()
    @DisplayName("Checks whenever a user with Org-Admin Scope tries to give a higher Scope than his own scope.")
    void hasOrgaizationAdminRightForPrivilegeEscalation() {
        JWTUser jwtUser = new JWTUser(orgAdmin);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);
        normalUser.getScopeList().addAll(TestUtils.createScope(ScopeRanking.SUPERADMIN_SCOPE));

        boolean hasPermission = testee.hasPermission(authentication, normalUser, JPARestPermissionEvaluator.WRITE);

        assertFalse(hasPermission);
    }

    @Test
    void hasNormalUserRightToEditHisSelf() {
        JWTUser jwtUser = new JWTUser(normalUser);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);


        boolean hasPermission = testee.hasPermission(authentication, normalUser, JPARestPermissionEvaluator.WRITE);

        assertTrue(hasPermission);
    }

    @Test
    void preventPrivilegeEscalationNormalUser() {
        JWTUser jwtUser = new JWTUser(normalUser);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);
        // the user tries to give itself an additional scope.
        normalUser.getScopeList().addAll(TestUtils.createScope(ScopeRanking.SUPERADMIN_SCOPE));


        boolean hasPermission = testee.hasPermission(authentication, normalUser, JPARestPermissionEvaluator.WRITE);

        assertFalse(hasPermission);
    }

    @Test
    void preventReactivationUser() {
        normalUser.setActivated(false);
        normalUser.postLoad();
        JWTUser jwtUser = new JWTUser(normalUser);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);
        // the user tries to reactivate hisself
        normalUser.setActivated(true);


        boolean hasPermission = testee.hasPermission(authentication, normalUser, JPARestPermissionEvaluator.WRITE);

        assertFalse(hasPermission);
    }

    @Test
    void preventSetOrganizationUser() {
        JWTUser jwtUser = new JWTUser(normalUser);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);
        // the user tries to reactivate hisself
        normalUser.setOrganization(organization2);


        boolean hasPermission = testee.hasPermission(authentication, normalUser, JPARestPermissionEvaluator.WRITE);

        assertFalse(hasPermission);
    }

    @Test
    void hasNormalUserRightToEditUser() {
        JWTUser jwtUser = new JWTUser(normalUser);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);


        boolean hasPermission = testee.hasPermission(authentication, orgAdmin, JPARestPermissionEvaluator.WRITE);

        assertFalse(hasPermission);
    }

    @Test
    void checkScopeForReading() {
        JWTUser jwtUser = new JWTUser(normalUser);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);

        boolean hasPermission = testee.hasPermission(authentication, TestUtils.createScope("some.data.api"), JPARestPermissionEvaluator.READ);

        assertTrue(hasPermission);
    }

    @Test
    void checkScopeForWriting() {
        JWTUser jwtUser = new JWTUser(orgAdmin);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);

        boolean hasPermission = testee.hasPermission(authentication, TestUtils.createScope("some.data.api"), JPARestPermissionEvaluator.WRITE);

        assertFalse(hasPermission);
    }

    @Test
    void checkScopeForWritingSuperAdmin() {
        JWTUser jwtUser = new JWTUser(superAdmin);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);

        boolean hasPermission = testee.hasPermission(authentication, TestUtils.createScope("some.data.api"), JPARestPermissionEvaluator.WRITE);

        assertTrue(hasPermission);
    }
}