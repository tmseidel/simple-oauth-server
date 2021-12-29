package org.remus.simpleoauthserver.controller;

import org.remus.simpleoauthserver.flows.ClientCredentialsFlow;
import org.remus.simpleoauthserver.flows.FlowController;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
public class TokenEndpoint {

    private FlowController flowController;

    private ClientCredentialsFlow clientCredentialsFlow;

    public TokenEndpoint(FlowController flowController, ClientCredentialsFlow clientCredentialsFlow) {
        this.flowController = flowController;
        this.clientCredentialsFlow = clientCredentialsFlow;
    }

    @PostMapping(path = "/auth/oauth/token",
            produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public AccessTokenResponse acquireAccessToken(
            @RequestBody MultiValueMap<String, String> body, Errors errors) {
        if (flowController.isClientCredentialFlow(body)) {
            clientCredentialsFlow.validateInputs(body,errors);
            if (!errors.hasErrors()) {
                return clientCredentialsFlow.execute(body);
            } else {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Input validation failed");
            }


        }
        return new AccessTokenResponse();

    }

}
