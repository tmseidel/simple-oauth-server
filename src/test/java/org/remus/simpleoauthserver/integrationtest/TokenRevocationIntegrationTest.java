package org.remus.simpleoauthserver.integrationtest;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.json.JSONObject.quote;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
@TestPropertySource(
        locations = "classpath:application-integrationtest.properties")
class TokenRevocationIntegrationTest extends BaseRest {

    @BeforeEach
    public void resetRefreshToken() {
        // before every test we reset our refreshToken
        acquireAccessToken();
    }


    @ParameterizedTest
    @ValueSource(booleans =  {true, false})
    void refreshTokenWithTokenRevocation(boolean tokenHint) {
        // We try to get a new access token with a revoced refresh-token
        String tokenRevocationUrl = "/auth/oauth/revoke";
        Map<String, String> formParams = new HashMap<>();
        if (tokenHint) {
            formParams.put("token_type_hint", "refresh_token");
        }
        formParams.put("token", refreshToken);

        // Token Revocation must return 200
        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRevocationUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(200);


        String tokenRequestUrl = "/auth/oauth/token";
        formParams = new HashMap<>();
        formParams.put("grant_type", "refresh_token");
        formParams.put("client_id", clientId);
        formParams.put("client_secret", clientSecret);
        formParams.put("refresh_token", refreshToken);
        formParams.put("redirect_uri", "http://localhost:8085/myApplication/auth");

        answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(400);

    }

    @Test
    void invalidTokenNoErrorResponse() {
        // We send the server an invalid token, it must respond with 200 (according to the rfc)
        String tokenRevocationUrl = "/auth/oauth/revoke";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("token", "TotalInvalidToken");

       ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRevocationUrl).then().extract();
       answer.response().then().assertThat()
                .statusCode(200);
    }

    @Test
    void tokenRevocationOnAccessToken() {
        String tokenRevocationUrl = "/auth/oauth/revoke";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("token", accessToken);

        // Token Revocation must return 200
        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRevocationUrl).then().extract();
        answer.response().then().assertThat()
                .statusCode(200);

        // Step1: Create the scope that is used for the API we want to secure
        String scopeName = "AnyNewScope";
        String description = "Itzli butzli";
        String newScopeUrl = "/auth/admin/data/scopes";
        String createScopeJson = "{\n" +
                "    \"name\" : " + quote(scopeName) + ",\n" +
                "    \"description\" : "+ quote(description) +"\n" +
                "}";
        answer = given().log().all().header(auth(accessToken)).header(JSON).body(createScopeJson).post(newScopeUrl).then().extract();
        // this action must not be allowed due to token revocation
        answer.response().then().assertThat()
                .statusCode(401);

    }
}
