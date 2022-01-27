package org.remus.simpleoauthserver.integrationtest;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
@TestPropertySource(
        locations = "classpath:application-integrationtest.properties")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RefreshGrantIntegrationTest extends BaseRest {

    @BeforeEach
    public void resetRefreshToken() {
        // before every test we reset our refreshToken
        acquireAccessToken();
    }

    @Test
    void happyPathWithTokenFromClientGrant() {
        // Step3: Get the access token for our user with the new scope
        String tokenRequestUrl = "/auth/oauth/token";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "refresh_token");
        formParams.put("client_id", clientId);
        formParams.put("client_secret", clientSecret);
        formParams.put("refresh_token", refreshToken);
        formParams.put("redirect_uri", "http://localhost:8085/myApplication/auth");

        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(200);
        String accessToken = answer.path("access_token");
        assertNotNull(accessToken);

        // We have our access token, now we check for the correct contents.
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(accessToken);
        assertEquals(clientId,claimsJws.getBody().getSubject());
        assertEquals("data.superadmin",claimsJws.getBody().get("scope",String.class));
    }
}
