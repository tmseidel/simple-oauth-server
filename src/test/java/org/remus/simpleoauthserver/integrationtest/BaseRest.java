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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gargoylesoftware.htmlunit.BrowserVersion;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlPasswordInput;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;
import io.restassured.RestAssured;
import io.restassured.config.ObjectMapperConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.Header;
import io.restassured.path.json.mapper.factory.Jackson2ObjectMapperFactory;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.apache.http.client.utils.URLEncodedUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.remus.simpleoauthserver.TestUtils;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.remus.simpleoauthserver.request.InitialApplicationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.server.LocalServerPort;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.json.JSONObject.quote;

public abstract class BaseRest {

    @Value("${soas.keyservice.basepath}")
    private String basePath;

    public static final String BASE_URL = "http://localhost";

    public static final Header JSON = new Header("Content-Type", "application/json");

    public static final Header URI_LIST = new Header("Content-Type", "text/uri-list");

    public static final Header FORM_URLENCODED = new Header("Content-Type", "application/x-www-form-urlencoded");
    protected static String clientId;
    protected static String clientSecret;
    protected static PublicKey publicKey;
    protected static String accessToken;
    protected static String refreshToken;
    private static Path pubKey;
    @LocalServerPort
    private int port;

    @AfterAll
    public static void cleanup() {
        clientId = null;
        clientSecret = null;
        publicKey = null;
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

    private static Header basicAuthHeader() {
        String authStr = clientId + ":" + clientSecret;
        String base64Creds = Base64.getEncoder().encodeToString(authStr.getBytes());
        return new Header("Authorization","Basic " +base64Creds);
    }

    void acquireAccessToken() {
        String tokenRequestUrl = "/auth/oauth/token";

        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "client_credentials");
        formParams.put("scope", "data.superadmin");

        ExtractableResponse<Response> answer = given().log().all().header(FORM_URLENCODED).header(basicAuthHeader()).formParams(formParams).post(tokenRequestUrl).then().extract();

        answer.response().then().assertThat()
                .statusCode(200);

        // Assert 1 check the response...
        answer.response().then().assertThat()
                .body("access_token", notNullValue())
                .body("token_type", equalTo("Bearer"))
                .body("expires_in", equalTo(604800))
                .body("refresh_token",notNullValue());


        accessToken = answer.path("access_token");
        refreshToken = answer.path("refresh_token");
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

    protected int createNewScope(String scopeName, String description) {
        // Step1: Create the scope that is used for the API we want to secure
        String newScopeUrl = "/auth/admin/data/scopes";
        String createScopeJson = "{\n" +
                "    \"name\" : " + quote(scopeName) + ",\n" +
                "    \"description\" : "+ quote(description) +"\n" +
                "}";
        ExtractableResponse<Response> answer = given().log().all().header(auth(accessToken)).header(JSON).body(createScopeJson).post(newScopeUrl).then().extract();
        int scopeId = answer.path("id");
        return scopeId;
    }

    protected int registerNewApi(String clientId, String clientSecret, String name, ApplicationType type) {
        ExtractableResponse<Response> answer;
        // Step2: Registering the API
        String newApplicationUrl = "/auth/admin/data/applications";
        String createAppJson = "{\n" +
                "    \"name\": " + quote(name) + ",\n" +
                "    \"clientId\": " + quote(clientId) + ",\n" +
                "    \"clientSecret\": " + quote(clientSecret) + ",\n" +
                "    \"activated\": true," +
                "    \"applicationType\": " + quote(type.name()) + ",\n" +
                "    \"loginUrls\": [\n" +
                "         \"http://localhost:8085/myApplication/auth\"\n" +
                "    ]\n" +
                "}";
        answer = given().log().all().header(auth(accessToken)).header(JSON).body(createAppJson).post(newApplicationUrl).then().extract();
        int applicationId = answer.path("id");
        return applicationId;
    }

    protected void assignScopesToApi(int applicationId, int ...scopes) {
        ExtractableResponse<Response> answer;
        // Step3: Assigning the scope to the registered application:
        String assignScopeListUri = "/auth/admin/data/applications/" + applicationId + "/scopeList";
        String uriList = Arrays.stream(scopes).mapToObj(e -> getBaseUrl() + "/auth/admin/data/scopes/" + e).collect(Collectors.joining("\n"));
        answer = given().log().all().header(URI_LIST).header(auth(accessToken)).body(uriList).put(assignScopeListUri).then().extract();
    }

    protected void assignScopesToUser(int userId, int ...scopes) {
        ExtractableResponse<Response> answer;
        String assignScopeListUri = "/auth/admin/data/users/" + userId + "/scopeList";
        String uriList = Arrays.stream(scopes).mapToObj(e -> getBaseUrl() + "/auth/admin/data/scopes/" + e).collect(Collectors.joining("\n"));
        answer = given().log().all().header(URI_LIST).header(auth(accessToken)).body(uriList).put(assignScopeListUri).then().extract();
    }

    protected int createUser(String name, String email, String password) {
        String newUserUrl = "/auth/admin/data/users";
        String json = "{\n" +
                "    \"name\" : " + quote(name) + ",\n" +
                "    \"email\" : " + quote(email) + ",\n" +
                "    \"password\" : " + quote(password) + ",\n" +
                "    \"activated\": true\n" +
                "}";
        ExtractableResponse<Response> answer = given().log().all().header(auth(accessToken)).header(JSON).body(json).post(newUserUrl).then().extract();
        int newUserId = answer.path("id");
        return newUserId;
    }

    protected int createOrganization(String organizationName) {
        String newOrganizationUrl = "/auth/admin/data/organizations";
        String json = "{\n" +
                "    \"name\" : "+ quote(organizationName) +"\n" +
                "}";
        ExtractableResponse<Response> answer = given().log().all().header(auth(accessToken)).header(JSON).body(json).post(newOrganizationUrl).then().extract();
        int newOrgId = answer.path("id");
        return newOrgId;
    }

    protected void assignUserToOrganization(int myOrg, int ...user) {
        for (int i : user) {
            String assignUserListUri = "/auth/admin/data/users/" + i + "/organization";
            String uriList = getBaseUrl() + "/auth/admin/data/organizations/" + myOrg;
            ExtractableResponse<Response> response = given().log().all().header(URI_LIST).header(auth(accessToken)).body(uriList).put(assignUserListUri).then().extract();
            int i1 = response.statusCode();
        }

    }

    protected void assignApplicationsToUser(int user, int ...newApplication) {
        String assignApplicationsListUri = "/auth/admin/data/users/" + user + "/applications";
        String uriList = Arrays.stream(newApplication).mapToObj(e -> getBaseUrl() + "/auth/admin/data/applications/" + e).collect(Collectors.joining("\n"));
        given().log().all().header(URI_LIST).header(auth(accessToken)).body(uriList).put(assignApplicationsListUri).then().extract();
    }

    protected void setIpRestriction(int myOrg, String restriction) {
        String url = "auth/admin/data/organizations/" + myOrg;
        String json = "{\n" +
                "    \"ipRestriction\": "+quote(restriction) +"\n" +
        "}";
        given().log().all().header(auth(accessToken)).header(JSON).body(json).patch(url).then().extract();
    }

    /**
     * Loads and submits the login-form
     * @param user
     * @return if successful the auth-token is returned, otherwise the html of the loaded website
     */
    protected String loadAndSubmitLoginForm(TestUtils.TestUser user, boolean with2ndPage) {
        try (final WebClient webClient = new WebClient(BrowserVersion.BEST_SUPPORTED)) {
            webClient.getCache().setMaxSize(0);
            webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
            webClient.getOptions().setThrowExceptionOnScriptError(false);
            webClient.waitForBackgroundJavaScript(30000);
            webClient.waitForBackgroundJavaScriptStartingBefore(30000);
            webClient.getOptions().setCssEnabled(false);
            webClient.getOptions().setJavaScriptEnabled(true);
            webClient.getOptions().setRedirectEnabled(false);
            webClient.addRequestHeader("Accept-Language" , "en");

            // Get the first page
            HtmlPage page1 = webClient.getPage(buildLoginPage(user));


            webClient.waitForBackgroundJavaScript(60000);

            page1 = (HtmlPage) page1.getEnclosingWindow().getEnclosedPage();


            // Get the form that we are dealing with and within that form,
            // find the submit button and the field that we want to change.
            final HtmlForm form = page1.getForms().get(0);

            final DomElement button = page1.getElementsByTagName("button").get(0);
            final HtmlTextInput userName = form.getInputByName("userName");
            final HtmlPasswordInput pass = form.getInputByName("password");

            // Change the value of the text field
            userName.type(user.getUserName());
            pass.type(user.getPassWord());

            // Now submit the form by clicking the button and get back the second page.

            Page page2 = button.click();
            if (with2ndPage) {
                final DomElement acceptButton = ((HtmlPage)page2).getElementsByTagName("button").get(0);
                page2 = acceptButton.click();
            }
            Optional<String> first = page2.getWebResponse().getResponseHeaders().stream().filter(e -> "Location".equals(e.getName())).map(NameValuePair::getValue).findFirst();
            return first.map(e -> {
                List<org.apache.http.NameValuePair> parse = URLEncodedUtils.parse(e, StandardCharsets.UTF_8);
                return parse.get(0).getValue();
            }).orElse(page2.getWebResponse().getContentAsString());
        } catch (IOException e) {
            throw new IllegalStateException("Error while grabbing access token",e);
        }
    }

    protected String buildLoginPage(TestUtils.TestUser user) {
        String codeChallengeFragmet = "";
        if (user.getCodeChallenge() != null) {
            codeChallengeFragmet = "&code_challenge="+user.getCodeChallenge()+"&code_challenge_method=S256";
        }
        return getBaseUrl() + "/auth/oauth/authorize?response_type=code&client_id="+user.getClientId()+"" +
                "&scope="+ String.join(",",user.getScope()) + codeChallengeFragmet + "" +
                "&redirect_uri=http://localhost:8085/myApplication/auth&state=12345";
    }



}
