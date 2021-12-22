package org.remus.simpleoauthserver.service;

import org.assertj.core.util.IterableUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.ScopeRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.springframework.test.util.ReflectionTestUtils;

import javax.persistence.EntityManager;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SetupServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private ScopeRepository scopeRepository;

    @Mock
    private EntityManager entityManager;

    @InjectMocks
    private SetupService testee;

    @BeforeEach
    public void init() {
        ReflectionTestUtils.setField(testee,"setupSecret","myToken");
    }

    @Test
    void canCreateInitialSuperAdmin() {
        lenient().when(userRepository.findAllSuperAdmins()).thenReturn(IterableUtil.iterable());

        boolean result = testee.canCreateInitialSuperAdmin("myToken");

        assertTrue(result);
    }

    @Test
    void canCreateInitialSuperAdminWrongPassword() {
        lenient().when(userRepository.findAllSuperAdmins()).thenReturn(IterableUtil.iterable());

        boolean result = testee.canCreateInitialSuperAdmin("wrong");

        assertFalse(result);
    }

    @Test
    void canCreateInitialSuperAdminAlreadyExists() {
        lenient().when(userRepository.findAllSuperAdmins()).thenReturn(IterableUtil.iterable(mock(User.class)));

        boolean result = testee.canCreateInitialSuperAdmin("myToken");

        assertFalse(result);
    }

    @Test
    void createInitialSuperAdmin() {
    }
}