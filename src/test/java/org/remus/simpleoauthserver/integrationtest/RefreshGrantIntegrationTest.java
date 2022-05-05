/**
 * Copyright(c) 2022 Tom Seidel, Remus Software
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
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
