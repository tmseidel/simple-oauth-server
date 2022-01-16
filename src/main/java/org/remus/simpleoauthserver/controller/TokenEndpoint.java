package org.remus.simpleoauthserver.controller;

import org.remus.simpleoauthserver.grants.AuthorizationGrant;
import org.remus.simpleoauthserver.grants.ClientCredentialsGrant;
import org.remus.simpleoauthserver.grants.GrantController;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.response.ErrorResponse;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.OAuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class TokenEndpoint {

    private GrantController flowController;

    private ClientCredentialsGrant clientCredentialsGrant;

    private AuthorizationGrant authorizationGrant;

    public TokenEndpoint(GrantController flowController, ClientCredentialsGrant clientCredentialsGrant, AuthorizationGrant authorizationGrant) {
        this.flowController = flowController;
        this.clientCredentialsGrant = clientCredentialsGrant;
        this.authorizationGrant = authorizationGrant;
    }

    @PostMapping(path = "/auth/oauth/token",
            produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public AccessTokenResponse acquireAccessToken(
            @RequestBody MultiValueMap<String, String> body, HttpServletRequest request) {
        if (flowController.isClientCredentialGrant(body)) {
            return clientCredentialsGrant.execute(body,request.getHeader("Authorization"));
        } else if (flowController.isAuthorizationGrant(body)) {
            return authorizationGrant.execute(body);
        }
        return new AccessTokenResponse();

    }


    @ResponseBody
    @ExceptionHandler({OAuthException.class, ApplicationNotFoundException.class})
    public ResponseEntity<ErrorResponse> handleUnsupportedGrantTypeException(HttpServletRequest request, Throwable ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return new ResponseEntity<>(new ErrorResponse("invalid_client", ex.getMessage()), status);
    }

}
