package org.remus.simpleoauthserver.controller;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.request.CreateSuperAdminRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.junit4.SpringRunner;
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
    private UserRepository userRepository;

    @Test
    @Order(1)
    void runWithInvalidPassword() {
        CreateSuperAdminRequest request = createValidRequest();
        // invalidate the token
        request.setInitialAuthToken("wrongToken");

        assertThrows(ResponseStatusException.class,() -> testee.run(request),"Expected a 401");
    }

    @Test
    @Order(2)
    void runHappyPath() throws NoSuchAlgorithmException, IOException {
        CreateSuperAdminRequest request = createValidRequest();

        testee.run(request);

        User user = userRepository.findAllSuperAdmins().iterator().next();
        assertEquals("John Doe", user.getName());
        assertEquals("ich@junit.de", user.getEmail());
    }

    @Test
    @Order(3)
    void runAfterHappyPath() {
        CreateSuperAdminRequest request = createValidRequest();

        assertThrows(ResponseStatusException.class,() -> testee.run(request),"Expected a 401");
    }

    private CreateSuperAdminRequest createValidRequest() {
        CreateSuperAdminRequest request = new CreateSuperAdminRequest();
        request.setOrganization("MyTest");
        request.setInitialAuthToken("testToken");
        request.setSuperAdminEmail("ich@junit.de");
        request.setSuperAdminPassword("******");
        request.setSuperAdminName("John Doe");
        return request;
    }
}