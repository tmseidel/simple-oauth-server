package org.remus.simpleoauthserver.grants;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.remus.simpleoauthserver.controller.ValueExtractionUtil;
import org.springframework.util.MultiValueMap;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FlowControllerTest {

    private GrantController testee;

    @BeforeEach
    public void setup() {
        testee = new GrantController();
    }

    @Test
    void isClientCredentialFlow() {
        MultiValueMap<String, String> mock = mock(MultiValueMap.class);
        when(mock.getFirst("grant_type")).thenReturn(GrantController.CLIENT_CREDENTIALS);

        assertTrue(testee.isClientCredentialGrant(mock));
        assertFalse(testee.isAuthorizationGrant(mock));
    }

    @Test
    void isAuthorizationFlow() {
        MultiValueMap<String, String> mock = mock(MultiValueMap.class);
        when(mock.getFirst("grant_type")).thenReturn(GrantController.AUTHORIZATION_CODE);

        assertFalse(testee.isClientCredentialGrant(mock));
        assertTrue(testee.isAuthorizationGrant(mock));
    }

    @Test
    void extractValue() {
        MultiValueMap<String, String> mock = mock(MultiValueMap.class);
        when(mock.getFirst("junit")).thenReturn("theValue");
        assertEquals(Optional.of("theValue"), ValueExtractionUtil.extractValue(mock, "junit"));
        assertEquals(Optional.empty(), ValueExtractionUtil.extractValue(mock, "notPresent"));

    }
}