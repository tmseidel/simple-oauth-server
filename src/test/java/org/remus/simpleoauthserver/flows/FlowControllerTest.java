package org.remus.simpleoauthserver.flows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.util.MultiValueMap;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FlowControllerTest {

    private FlowController testee;

    @BeforeEach
    public void setup() {
        testee = new FlowController();
    }

    @Test
    void isClientCredentialFlow() {
        MultiValueMap<String, String> mock = mock(MultiValueMap.class);
        when(mock.getFirst("grant_type")).thenReturn(FlowController.CLIENT_CREDENTIALS);

        assertTrue(testee.isClientCredentialFlow(mock));
        assertFalse(testee.isAuthorizationFlow(mock));
    }

    @Test
    void isAuthorizationFlow() {
        MultiValueMap<String, String> mock = mock(MultiValueMap.class);
        when(mock.getFirst("grant_type")).thenReturn(FlowController.AUTHORIZATION_CODE);

        assertFalse(testee.isClientCredentialFlow(mock));
        assertTrue(testee.isAuthorizationFlow(mock));
    }

    @Test
    void extractValue() {
        MultiValueMap<String, String> mock = mock(MultiValueMap.class);
        when(mock.getFirst("junit")).thenReturn("theValue");
        assertEquals(Optional.of("theValue"), FlowController.extractValue(mock, "junit"));
        assertEquals(Optional.empty(), FlowController.extractValue(mock, "notPresent"));

    }
}