package org.remus.simpleoauthserver.systemtests;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This test shows the functionality of the Client Credential Flow
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(
        locations = "classpath:application-integrationtest.properties")
public class ClientCredentialsFlowIntegrationTest extends BaseRest {

    @Test
    void credentialFlowHappyPath() {
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(this.publicKey).parseClaimsJws(accessToken);

        assertTrue(Jwts.parser().setSigningKey(this.publicKey).isSigned(accessToken));
        assertEquals(clientId, claimsJws.getBody().getSubject());
    }
}
