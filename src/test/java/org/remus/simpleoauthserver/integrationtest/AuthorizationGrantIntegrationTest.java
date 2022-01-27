package org.remus.simpleoauthserver.integrationtest;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.remus.simpleoauthserver.TestUtils;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * <pre>
 * This test demonstrates the implemented OAuth2 Authoriaztion Grant.
 * We create initially:
 *  - a user assigned to an organization
 *  - two scopes
 *  - a new API
 *  - assigning the scopes to the new API (the API may use the two scopes)
 *  - assigning the user to the API (the User can login at the API)
 * </pre>
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
@TestPropertySource(
        locations = "classpath:application-integrationtest.properties")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthorizationGrantIntegrationTest extends BaseRest {

    private static boolean dataSetup;
    private static int scope1;
    private static int scope2;
    private static int newApplication;
    private static int user;
    private static int myOrg;
    private static String accessToken;

    @BeforeEach
    public void setup() {
        if (!dataSetup) {
            scope1 = createNewScope("myapi.write", "Write some data");
            scope2 = createNewScope("myapi.send", "Send some stuff");

            newApplication = registerNewApi("jp98GC73RJ2VBqZB", "9OZhG274HP16FRQg58f0IADSQNV3UFiL", "Auth-Test", ApplicationType.REGULAR);
            assignScopesToApi(newApplication, scope1, scope2);
            user = createUser("John Doe", "test@example.org", "mypassword");
            myOrg = createOrganization("MyOrg");
            assignUserToOrganization(myOrg, user);
            dataSetup = true;
        }

    }

    @Test
    @Order(1)
    /**
     * This test is the normal authentication. A user uses the login form,
     * an access-code is generated and a second call with confidential client-information
     * will be sent to acquire an access token.
     */
    void happyPath() {
        // Step0: Give the user the scopes.
        assignScopesToUser(user, scope1, scope2);
        // Step0.5: Give the application the right to handle the user.
        assignApplicationsToUser(user, newApplication);
        // Step1: Login via Html-Form with username and password
        TestUtils.TestUser testUser = new TestUtils.TestUser("test@example.org", "mypassword", "jp98GC73RJ2VBqZB", new String[]{"myapi.write"});
        // Step2: "Grab" the access token from response-header.
        accessToken = loadAndSubmitLoginForm(testUser,false);
        assertNotNull(accessToken);

        // Step3: Get the access token for our user with the new scope
        String tokenRequestUrl = "/auth/oauth/token";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "authorization_code");
        formParams.put("client_id", "jp98GC73RJ2VBqZB");
        formParams.put("client_secret", "9OZhG274HP16FRQg58f0IADSQNV3UFiL");
        formParams.put("code", accessToken);
        formParams.put("redirect_uri", "http://localhost:8085/myApplication/auth");

        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(200);
        String accessToken = answer.path("access_token");
        assertNotNull(accessToken);

        // We have our access token, now we check for the correct contents.
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(accessToken);
        assertEquals("test@example.org",claimsJws.getBody().getSubject());
        assertEquals("myapi.write",claimsJws.getBody().get("scope",String.class));
    }

    @Test
    @Order(2)
    /**
     * This test ensures that the access token can only be used once for
     * getting an auth-token. we try to reuse the access-token we received from
     * our {@link #happyPath()} test.
     */
    void reuseOfAccessToken() {
        String tokenRequestUrl = "/auth/oauth/token";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "authorization_code");
        formParams.put("client_id", "jp98GC73RJ2VBqZB");
        formParams.put("client_secret", "9OZhG274HP16FRQg58f0IADSQNV3UFiL");
        formParams.put("code", accessToken);
        formParams.put("redirect_uri", "http://localhost:8085/myApplication/auth");

        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(400);
        assertEquals("invalid_client",answer.path("error"));
        assertNotNull(answer.path("error_description"));
    }

    @Test
    @Order(3)
    /**
     * This test ensures that the server will reject a request if
     * the redirect-uri in the auth-token request is different compared
     * to the uri from the access-token request.
     */
    void invalidRedirectUri() {
        TestUtils.TestUser testUser = new TestUtils.TestUser("test@example.org", "mypassword", "jp98GC73RJ2VBqZB", new String[]{"myapi.write"});
        // Step2: "Grab" the access token from response-header.
        String s = loadAndSubmitLoginForm(testUser,false);
        assertNotNull(s);

        // Step3: Get the access token for our user with the new scope
        String tokenRequestUrl = "/auth/oauth/token";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "authorization_code");
        formParams.put("client_id", "jp98GC73RJ2VBqZB");
        formParams.put("client_secret", "9OZhG274HP16FRQg58f0IADSQNV3UFiL");
        formParams.put("code", s );
        formParams.put("redirect_uri", "http://example.org/wrongRedirect/auth");

        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(400);
        assertEquals("invalid_client",answer.path("error"));
        assertNotNull(answer.path("error_description"));
    }

    @Test
    @Order(4)
    /**
     * This test ensures that the server will reject a request if
     * the scope is unknown.
     */
    void invalidScope() {
        var testUser = new TestUtils.TestUser("test@example.org", "mypassword", "jp98GC73RJ2VBqZB", new String[]{"unknown.scope"});
        // Step2: "Grab" the access token from response-header.
        String webResponse = loadAndSubmitLoginForm(testUser,false);

        assertThat(webResponse).contains("User has not sufficient authorizations to login");
    }

    @Test
    @Order(5)
    /**
     * This test ensures that the server will reject a request if
     * the scope is unknown.
     */
    void unknownUser() {
        var testUser = new TestUtils.TestUser("unknown@example.org", "mypassword", "jp98GC73RJ2VBqZB", new String[]{"myapi.write"});
        // Step2: "Grab" the access token from response-header.
        String webResponse = loadAndSubmitLoginForm(testUser,false);

        assertThat(webResponse).contains("User was not found or password not correct");
    }


    @Test
    @Order(6)
    /**
     * This test ensures that the server will reject a request if
     * the scope is unknown.
     */
    void wrongPassword() {
        var testUser = new TestUtils.TestUser("test@example.org", "wrongPassword", "jp98GC73RJ2VBqZB", new String[]{"myapi.write"});
        // Step2: "Grab" the access token from response-header.
        String webResponse = loadAndSubmitLoginForm(testUser,false);

        assertThat(webResponse).contains("User was not found or password not correct");
    }
    @Test
    @Order(7)
    /**
     * Creating a new user that has to authorize the requesting application
     */
    void assignApplication() {
        var secondUser = createUser("Jane Doe", "jane@example.org", "hello");
        assignUserToOrganization(myOrg, secondUser);
        assignScopesToUser(secondUser, scope1, scope2);

        TestUtils.TestUser testUser = new TestUtils.TestUser("jane@example.org", "hello", "jp98GC73RJ2VBqZB", new String[]{"myapi.write"});
        // Step2: "Grab" the access token from response-header.
        String newUserAccessToken = loadAndSubmitLoginForm(testUser,true);

        String tokenRequestUrl = "/auth/oauth/token";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "authorization_code");
        formParams.put("client_id", "jp98GC73RJ2VBqZB");
        formParams.put("client_secret", "9OZhG274HP16FRQg58f0IADSQNV3UFiL");
        formParams.put("code", newUserAccessToken);
        formParams.put("redirect_uri", "http://localhost:8085/myApplication/auth");

        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(200);
        String authToken = answer.path("access_token");
        assertNotNull(authToken);
    }

    @Test
    @Order(8)
    /**
     * This test is the normal authentication. A user uses the login form,
     * an access-code is generated and a second call with confidential client-information
     * will be sent to acquire an access token.
     */
    void happyPathWitRefreshToken() {
        // Step1: Login via Html-Form with username and password
        TestUtils.TestUser testUser = new TestUtils.TestUser("test@example.org", "mypassword", "jp98GC73RJ2VBqZB", new String[]{"myapi.write"});
        // Step2: "Grab" the access token from response-header.
        accessToken = loadAndSubmitLoginForm(testUser,false);
        assertNotNull(accessToken);

        // Step3: Get the access token for our user with the new scope
        String tokenRequestUrl = "/auth/oauth/token";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "authorization_code");
        formParams.put("client_id", "jp98GC73RJ2VBqZB");
        formParams.put("client_secret", "9OZhG274HP16FRQg58f0IADSQNV3UFiL");
        formParams.put("code", accessToken);
        formParams.put("redirect_uri", "http://localhost:8085/myApplication/auth");

        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(200);
        String refreshToken = answer.path("refresh_token");
        assertNotNull(refreshToken);

        // Step4:Trying to get an refreshToken
        formParams = new HashMap<>();
        formParams.put("grant_type", "refresh_token");
        formParams.put("client_id", "jp98GC73RJ2VBqZB");
        formParams.put("client_secret", "9OZhG274HP16FRQg58f0IADSQNV3UFiL");
        formParams.put("refresh_token", refreshToken);
        formParams.put("redirect_uri", "http://localhost:8085/myApplication/auth");

        answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(200);
        String accessTokenFromRefreshToken = answer.path("access_token");

        // We have our access token, now we check for the correct contents.
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(accessTokenFromRefreshToken);
        assertEquals("test@example.org",claimsJws.getBody().getSubject());
        assertEquals("myapi.write",claimsJws.getBody().get("scope",String.class));
    }
}
