package org.remus.simpleoauthserver.flows;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.response.TokenType;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.Errors;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Controller
public class ClientCredentialsFlow {

    private ApplicationRepository applicationRepository;

    private JwtTokenService jwtTokenService;

    @Value("${jwt.expiration}")
    private Long expiration;


    public ClientCredentialsFlow(ApplicationRepository applicationRepository, JwtTokenService jwtTokenService) {
        this.applicationRepository = applicationRepository;
        this.jwtTokenService = jwtTokenService;
    }

    /**
     * According to OAuth 2.0 RFC 6749, section 4.4.2 we check the request.
     * @param data
     */
    public void validateInputs(MultiValueMap<String, String> data, Errors errors) {


    }


    private Optional<String> extractValue(MultiValueMap<String,String> data, String key) {
        String value = data.getFirst(key);
        return value == null ? Optional.empty() : Optional.of(value);
    }

    public AccessTokenResponse execute(MultiValueMap<String, String> data) {
        String clientId = extractValue(data, "client_id").orElseThrow();
        String clientSecret = extractValue(data, "client_secret").orElseThrow();
        String[] scopes = extractValue(data, "scope").orElse("").split(",");

        Application application = applicationRepository.findApplicationByClientIdAndClientSecretAndActivated(clientId, clientSecret, true)
                .orElseThrow(() -> new ApplicationNotFoundException(String.format("The application with client_id %s was not found",clientId)));
        Set<String> scopesAsString = application.getScopeList().stream().map(Scope::getName).collect(Collectors.toSet());
        boolean requestedScopesAreValid = Arrays.stream(scopes).anyMatch(e -> scopesAsString.contains(e));

        AccessTokenResponse returnValue = new AccessTokenResponse();
        String accessToken = jwtTokenService.createAccessToken(application.getClientId(), application.getApplicationType(), scopes);

        returnValue.setAccessToken(accessToken);
        returnValue.setTokenType(TokenType.BEARER.getStringValue());
        returnValue.setExpiration(Math.toIntExact(expiration));

        return returnValue;

    }
}
