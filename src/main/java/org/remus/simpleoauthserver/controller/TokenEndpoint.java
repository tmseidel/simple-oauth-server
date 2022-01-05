package org.remus.simpleoauthserver.controller;

import org.remus.simpleoauthserver.flows.AuthorizationFlow;
import org.remus.simpleoauthserver.flows.ClientCredentialsFlow;
import org.remus.simpleoauthserver.flows.FlowController;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.response.ErrorResponse;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.UnsupportedGrantTypeException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class TokenEndpoint {

    private FlowController flowController;

    private ClientCredentialsFlow clientCredentialsFlow;

    private AuthorizationFlow authorizationFlow;

    public TokenEndpoint(FlowController flowController, ClientCredentialsFlow clientCredentialsFlow, AuthorizationFlow authorizationFlow) {
        this.flowController = flowController;
        this.clientCredentialsFlow = clientCredentialsFlow;
        this.authorizationFlow = authorizationFlow;
    }

    @PostMapping(path = "/auth/oauth/token",
            produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public AccessTokenResponse acquireAccessToken(
            @RequestBody MultiValueMap<String, String> body) {
        if (flowController.isClientCredentialFlow(body)) {
            clientCredentialsFlow.validateInputs(body);
            return clientCredentialsFlow.execute(body);
        } else if (flowController.isAuthorizationFlow(body)) {

        }
        return new AccessTokenResponse();

    }

    @ResponseBody
    @ExceptionHandler(ApplicationNotFoundException.class)
    public ResponseEntity<?> handleApplicationNotFoundException(HttpServletRequest request, Throwable ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return new ResponseEntity<>(new ErrorResponse("invalid_client", ex.getMessage()), status);
    }

    @ResponseBody
    @ExceptionHandler(UnsupportedGrantTypeException.class)
    public ResponseEntity<?> handleUnsupportedGrantTypeException(HttpServletRequest request, Throwable ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return new ResponseEntity<>(new ErrorResponse("invalid_client", ex.getMessage()), status);
    }

}
