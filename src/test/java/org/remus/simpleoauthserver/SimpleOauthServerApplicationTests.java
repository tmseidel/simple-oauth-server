package org.remus.simpleoauthserver;

import org.junit.jupiter.api.Test;
import org.remus.simpleoauthserver.controller.TokenEndpoint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.annotation.DirtiesContext;

import javax.inject.Inject;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
class SimpleOauthServerApplicationTests {

    @Inject
    private ApplicationContext context;

    @Test
    void contextLoads() {
        // simple check if the controller are up and running
        String applicationName = context.getApplicationName();
        assertNotNull(applicationName);
        TokenEndpoint bean = context.getBean(TokenEndpoint.class);
        assertNotNull(bean);
    }

}
