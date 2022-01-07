package org.remus.simpleoauthserver.integrationtest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.RestAssured;
import io.restassured.config.ObjectMapperConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.Header;
import io.restassured.path.json.mapper.factory.Jackson2ObjectMapperFactory;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.remus.simpleoauthserver.request.InitialApplicationRequest;
import org.springframework.boot.web.server.LocalServerPort;

import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

public abstract class BaseRest {

    public static final String BASE_URL = "http://localhost";

    public static final Header JSON = new Header("Content-Type", "application/json");

    public static final Header URI_LIST = new Header("Content-Type", "text/uri-list");

    public static final Header FORM_URLENCODED = new Header("Content-Type", "application/x-www-form-urlencoded");
    protected static String clientId;
    protected static String clientSecret;
    protected static PublicKey publicKey;
    protected static String accessToken;
    private static Path pubKey;
    @LocalServerPort
    private int port;

    @AfterAll
    public static void cleanup() {
        clientId = null;
        clientSecret = null;
    }

    @BeforeEach
    void createInitialApplicationAndDownloadPubKey(@TempDir Path tempDir) throws Exception {
        if (clientId == null || clientSecret == null) {
            configureRestAssured(port);
            String firstStartUrl = "/auth/firstStart/run";
            String downloadPubUrl = "/auth/firstStart/pub";

            InitialApplicationRequest request = new InitialApplicationRequest();
            request.setInitialAuthToken("testToken");

            ExtractableResponse<Response> answer = given().log().all().header(JSON).body(request).post(firstStartUrl).then().extract();

            answer.response().then().assertThat()
                    .statusCode(200);

            clientId = answer.path("client_id");
            clientSecret = answer.path("client_secret");

            answer = given().log().all().get(downloadPubUrl).then().extract();
            pubKey = tempDir.resolve("pubKey.pub");
            Files.write(pubKey, answer.asByteArray());
            acquireAccessToken();
            loadPublicKey();
        }
    }

    void acquireAccessToken() {
        String tokenRequestUrl = "/auth/oauth/token";

        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "client_credentials");
        formParams.put("client_id", clientId);
        formParams.put("client_secret", clientSecret);
        formParams.put("scope", "data.superadmin");

        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).formParams(formParams).post(tokenRequestUrl).then().extract();

        answer.response().then().assertThat()
                .statusCode(200);

        // Assert 1 check the response...
        answer.response().then().assertThat()
                .body("access_token", notNullValue())
                .body("token_type", equalTo("Bearer"))
                .body("expires_in", equalTo(604800));


        accessToken = answer.path("access_token");
    }

    public void loadPublicKey() throws Exception {
        if (publicKey == null) {
            byte[] bytes = Files.readAllBytes(pubKey);
            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(ks);
        }
    }

    protected Header auth(String token) {
        return new Header("Authorization", "Bearer " + token);
    }

    protected String getBaseUrl() {
        return RestAssured.baseURI + ":" + RestAssured.port;
    }

    protected void configureRestAssured(int port) {
        RestAssured.baseURI = BASE_URL;
        RestAssured.port = port;
        RestAssured.config = RestAssuredConfig.config().objectMapperConfig(new ObjectMapperConfig().jackson2ObjectMapperFactory(
                new Jackson2ObjectMapperFactory() {
                    @Override
                    public ObjectMapper create(Type type, String s) {
                        //FilterProvider filter = new SimpleFilterProvider().addFilter(...);
                        com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
                        //objectMapper.setFilters(filter);
                        return objectMapper;
                    }
                }
        ));
    }
}
