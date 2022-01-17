package org.remus.simpleoauthserver.grants;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.repository.ScopeRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.Map;

import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;

@Controller
public class ClientCredentialsGrant extends OAuthGrant {


    public ClientCredentialsGrant(ApplicationRepository applicationRepository, UserRepository userRepository, JwtTokenService jwtTokenService, PasswordEncoder passwordEncoder, ScopeRepository scopeRepository) {
        super(applicationRepository, userRepository, jwtTokenService, passwordEncoder,scopeRepository);
    }

    public AccessTokenResponse execute(MultiValueMap<String, String> data, String authorizationHeader) {
        String clientId = extractClientId(data, authorizationHeader);
        String clientSecret = extractClientSecret(data,authorizationHeader);
        String[] scopes = extractValue(data, "scope").orElse("").split(",");

        Application application = applicationRepository.findApplicationByClientIdAndClientSecretAndActivated(clientId, clientSecret, true)
                .orElseThrow(() -> new ApplicationNotFoundException(String.format("The application with client_id %s was not found",clientId)));
        checkScope(scopes, application);
        AccessTokenResponse returnValue = new AccessTokenResponse();
        Map<String,Object> claims = new HashMap<>();
        claims.put("type",application.getApplicationType().name());
        claims.put("scope",String.join(",",scopes));

        return createResponse(application.getClientId(), claims);

    }
}
