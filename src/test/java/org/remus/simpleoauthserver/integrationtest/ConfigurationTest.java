package org.remus.simpleoauthserver.integrationtest;

import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.remus.simpleoauthserver.entity.User;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
@TestPropertySource(
        locations = "classpath:application-integrationtest.properties")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ConfigurationTest extends BaseRest {

    @Test
    void createUser() {

        String newUserUrl = "/admin/data/users";
        String json = "{\n" +
                "    \"name\" : \"Hans Dampf\",\n" +
                "    \"email\" : \"test@example.org\",\n" +
                "    \"activated\": true\n" +
                "}";
        ExtractableResponse<Response> answer = given().log().all().header(auth(accessToken)).header(JSON).body(json).post(newUserUrl).then().extract();

        answer.response().then().assertThat()
                .statusCode(201);
        answer.response().then().assertThat()
                .body("id", greaterThan(0))
                .body("name", equalTo("Hans Dampf"))
                .body("email",equalTo("test@example.org"));


    }
}
