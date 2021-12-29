package org.remus.simpleoauthserver.systemtests;

import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.remus.simpleoauthserver.entity.User;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static io.restassured.RestAssured.given;
import static org.remus.simpleoauthserver.systemtests.BaseRest.JSON;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@TestPropertySource(
        locations = "classpath:application-integrationtest.properties")
public class ConfigurationTest extends BaseRest {

    @Test
    void createUser() {
        User user = new User();
        

        ExtractableResponse<Response> answer = given().log().all().header(JSON).header(auth(this.accessToken)).body(request).put(firstStartUrl).then().extract();


    }
}
