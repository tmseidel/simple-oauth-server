package org.remus.simpleoauthserver.service;

import org.assertj.core.util.IterableUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class SetupServiceTest {

    @Mock
    private ApplicationRepository applicationRepository;

    @InjectMocks
    private SetupService testee;

    @BeforeEach
    public void init() {
        ReflectionTestUtils.setField(testee, "setupSecret", "myToken");
    }

    @Test
    void canCreateInitialSuperAdmin() {
        lenient().when(applicationRepository.findAllApplicationWithSuperAdminScope()).thenReturn(IterableUtil.iterable());

        boolean result = testee.canCreateInitialSuperAdmin("myToken");

        assertTrue(result);
    }

    @Test
    void canCreateInitialSuperAdminWrongPassword() {
        lenient().when(applicationRepository.findAllApplicationWithSuperAdminScope()).thenReturn(IterableUtil.iterable());

        boolean result = testee.canCreateInitialSuperAdmin("wrong");

        assertFalse(result);
    }

    @Test
    void canCreateInitialSuperAdminAlreadyExists() {
        lenient().when(applicationRepository.findAllApplicationWithSuperAdminScope()).thenReturn(IterableUtil.iterable(mock(Application.class)));

        boolean result = testee.canCreateInitialSuperAdmin("myToken");

        assertFalse(result);
    }

}