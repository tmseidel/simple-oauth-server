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
class ClientCredentialsFlowIntegrationTest extends BaseRest {

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
        int scopeId = createNewScope("userdata.write");
        ExtractableResponse<Response> answer;
        int applicationId = registerNewApi("Fq09P3T2YiXST8b6WJ54QO1LWDDUG7SM");
        assignScopeToApi(scopeId, applicationId);

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

    private void assignScopeToApi(int scopeId, int applicationId) {
        ExtractableResponse<Response> answer;
        // Step3: Assigning the scope to the registered application:
        String assignScopeListUri = "/auth/admin/data/applications/" + applicationId + "/scopeList";
        String uriList = getBaseUrl() + "/auth/admin/data/scopes/" + scopeId;
        answer = given().log().all().header(URI_LIST).header(auth(accessToken)).body(uriList).put(assignScopeListUri).then().extract();
    }

    private int registerNewApi(String clientId) {
        ExtractableResponse<Response> answer;
        // Step2: Registering the API
        String newApplicationUrl = "/auth/admin/data/applications";
        String createAppJson = "{\n" +
                "    \"name\": \"My Super-API\",\n" +
                "    \"clientId\": \"" + clientId + "\",\n" +
                "    \"clientSecret\": \"uIFeAD0OK56WD1N3BkhLjX9HGOoCNULsxv724TyYdHVpqPBEtQ8RZ\",\n" +
                "    \"activated\": true,\n" +
                "    \"applicationType\": \"M2M\"\n" +
                "}";
        answer = given().log().all().header(auth(accessToken)).header(JSON).body(createAppJson).post(newApplicationUrl).then().extract();
        int applicationId = answer.path("id");
        return applicationId;
    }

    private int createNewScope(String scopeName) {
        // Step1: Create the scope that is used for the API we want to secure
        String newScopeUrl = "/auth/admin/data/scopes";
        String createScopeJson = "{\n" +
                "    \"name\" : \"" + scopeName + "\",\n" +
                "    \"description\" : \"Right to write user-data\"\n" +
                "}";
        ExtractableResponse<Response> answer = given().log().all().header(auth(accessToken)).header(JSON).body(createScopeJson).post(newScopeUrl).then().extract();
        int scopeId = answer.path("id");
        return scopeId;
    }
}
