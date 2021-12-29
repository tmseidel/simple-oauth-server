package org.remus.simpleoauthserver.security;

import io.jsonwebtoken.Jwt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.remus.simpleoauthserver.TestUtils;
import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.User;
import org.springframework.security.core.Authentication;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.remus.simpleoauthserver.TestUtils.createUser;

class JPARestPermissionEvaluatorTest {

    private Organization organization;
    private User orgAdmin;
    private User normalUser;
    private JPARestPermissionEvaluator testee;

    @BeforeEach
    public void setup() {
        organization = TestUtils.createOrganization(10);
        orgAdmin = createUser("Hans Dampf", "hans.dampf@example.org");
        orgAdmin.setScopeList(Collections.singleton(TestUtils.createScope(ScopeRanking.ORGANIZATION_OWNER_SCOPE)));
        orgAdmin.setOrganization(organization);
        normalUser = createUser("John Doe", "john.doe@example.org");
        normalUser.setScopeList(Collections.singleton(TestUtils.createScope("some.api.scope")));
        normalUser.setOrganization(organization);
        testee = new JPARestPermissionEvaluator();
    }

    @Test
    void hasOrgaizationAdminRightForUserEditing() {
        JWTUser jwtUser = new JWTUser(orgAdmin);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);

        boolean hasPermission = testee.hasPermission(authentication, normalUser, JPARestPermissionEvaluator.WRITE);

        assertTrue(hasPermission);
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
    void hasNormalUserRightToEditUser() {
        JWTUser jwtUser = new JWTUser(normalUser);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(jwtUser);


        boolean hasPermission = testee.hasPermission(authentication, orgAdmin, JPARestPermissionEvaluator.WRITE);

        assertFalse(hasPermission);
    }
}