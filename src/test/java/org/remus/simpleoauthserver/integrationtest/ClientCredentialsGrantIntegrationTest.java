package org.remus.simpleoauthserver.integrationtest;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This test shows the functionality of the Client Credential Flow
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
@TestPropertySource(
        locations = "classpath:application-integrationtest.properties")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ClientCredentialsGrantIntegrationTest extends BaseRest {

    @Test
    @DisplayName("Checks if the default application privides a correct access token, we check the token with the public-key.")
    void credentialFlowWithInitialApplication() {
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(accessToken);

        assertTrue(Jwts.parser().setSigningKey(publicKey).isSigned(accessToken));
        assertEquals(clientId, claimsJws.getBody().getSubject());
    }

    @Test
    @DisplayName("This test creates a new application with a defined scope and tests the Client-Credential Flow")
    @Order(2)
    void createNewAppForCredentialsFlowIntegration() {
        int scopeId = createNewScope("userdata.write", "The right to write some data");
        ExtractableResponse<Response> answer;
        int applicationId = registerNewApi(
                "Fq09P3T2YiXST8b6WJ54QO1LWDDUG7SM",
                "uIFeAD0OK56WD1N3BkhLjX9HGOoCNULsxv724TyYdHVpqPBEtQ8RZ",
                "My super API",
                ApplicationType.M2M);
        assignScopesToApi(applicationId,scopeId);

        // Step 4: Get the access token for our new application with the new scope
        String tokenRequestUrl = "/auth/oauth/token";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "client_credentials");
        formParams.put("client_id", "Fq09P3T2YiXST8b6WJ54QO1LWDDUG7SM");
        formParams.put("client_secret", "uIFeAD0OK56WD1N3BkhLjX9HGOoCNULsxv724TyYdHVpqPBEtQ8RZ");
        formParams.put("scope", "userdata.write");
        answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(200);
        String accessToken1 = answer.path("access_token");

        // Step 5: Validating the access token with the public-key and checking for the contents
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(accessToken1);
        assertEquals("Fq09P3T2YiXST8b6WJ54QO1LWDDUG7SM", claimsJws.getBody().getSubject());
        assertEquals("userdata.write", claimsJws.getBody().get("scope", String.class));
    }

    @Test
    @Order(3)
    @DisplayName("This test checks the error-response that comes with a wrong client-id")
    void requestAccessTokenWithInvalidClientId() {

        String tokenRequestUrl = "/auth/oauth/token";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "client_credentials");
        formParams.put("client_id", "someOtherClientId");
        formParams.put("client_secret", "uIFeAD0OK56WD1N3BkhLjX9HGOoCNULsxv724TyYdHVpqPBEtQ8RZ");
        formParams.put("scope", "userdata.write");
        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(400);
        String error = answer.path("error");

        assertEquals("invalid_client", error);
    }

    @Test
    @Order(4)
    @DisplayName("This test checks the error-response that comes with a wrong client-secret")
    void requestAccessTokenWithInvalidClientSecret() {

        String tokenRequestUrl = "/auth/oauth/token";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "client_credentials");
        formParams.put("client_id", "Fq09P3T2YiXST8b6WJ54QO1LWDDUG7SM");
        formParams.put("client_secret", "wrong-client-secret");
        formParams.put("scope", "userdata.write");
        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(400);
        String error = answer.path("error");

        assertEquals("invalid_client", error);
    }





}
