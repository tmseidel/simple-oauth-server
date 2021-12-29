package org.remus.simpleoauthserver.controller;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.request.InitialApplicationRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.server.ResponseStatusException;

import javax.inject.Inject;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;
@ExtendWith(SpringExtension.class)
@SpringBootTest
@TestPropertySource(
        locations = "classpath:application-integrationtest.properties")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FirstStartControllerIntegrationTest {

    @Inject
    private FirstStartController testee;

    @Inject
    private ApplicationRepository applicationRepository;

    @Test
    @Order(1)
    void runWithInvalidPassword() {
        InitialApplicationRequest request = createValidRequest();
        // invalidate the token
        request.setInitialAuthToken("wrongToken");

        assertThrows(ResponseStatusException.class,() -> testee.run(request),"Expected a 401");
    }

    @Test
    @Order(2)
    void runHappyPath() throws NoSuchAlgorithmException, IOException {
        InitialApplicationRequest request = createValidRequest();

        testee.run(request);

        Application application = applicationRepository.findAllApplicationWithSuperAdminScope().iterator().next();

        assertNotNull(application);
    }

    @Test
    @Order(3)
    void runAfterHappyPath() {
        InitialApplicationRequest request = createValidRequest();

        assertThrows(ResponseStatusException.class,() -> testee.run(request),"Expected a 401");
    }

    private InitialApplicationRequest createValidRequest() {
        InitialApplicationRequest request = new InitialApplicationRequest();
        request.setInitialAuthToken("testToken");
        return request;
    }
}