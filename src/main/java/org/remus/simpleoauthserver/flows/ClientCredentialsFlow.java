package org.remus.simpleoauthserver.flows;

import org.apache.commons.lang3.StringUtils;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.response.TokenType;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.InvalidGrandException;
import org.remus.simpleoauthserver.service.InvalidInputException;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.stream.Collectors;

import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;

@Controller
public class ClientCredentialsFlow extends OAuthFlow{

    @Value("${jwt.expiration}")
    private Long expiration;

    public ClientCredentialsFlow(ApplicationRepository applicationRepository, UserRepository userRepository, JwtTokenService jwtTokenService, PasswordEncoder passwordEncoder) {
        super(applicationRepository, userRepository, jwtTokenService, passwordEncoder);
    }


    private String extractClientId(MultiValueMap<String, String> data, String authorizationHeader) {
        String clientId = null;
        if (!StringUtils.isEmpty(authorizationHeader) && authorizationHeader.toLowerCase().startsWith("Basic ")) {
            String s = new String(Base64.getDecoder().decode(authorizationHeader.toLowerCase().replaceFirst("Basic ","")));
            if (!StringUtils.isEmpty(s)) {
                String[] split = s.split(":");
                if (split.length == 2) {
                    clientId = split[0];
                }
            }
        }
        if (clientId == null) {
            clientId = extractValue(data, "client_id").orElseThrow(() -> new InvalidInputException("No client_id present"));
        }
        return clientId;
    }

    private String extractClientSecret(MultiValueMap<String, String> data, String authorizationHeader) {
        String clientSecret = null;
        if (!StringUtils.isEmpty(authorizationHeader) && authorizationHeader.toLowerCase().startsWith("basic ")) {
            String s = new String(Base64.getDecoder().decode(authorizationHeader.toLowerCase().replaceFirst("Basic ","")));
            if (!StringUtils.isEmpty(s)) {
                String[] split = s.split(":");
                if (split.length == 2) {
                    clientSecret = split[1];
                }
            }
        }
        if (clientSecret == null) {
            clientSecret = extractValue(data, "client_secret").orElseThrow(() -> new InvalidInputException("No client_secret present"));
        }
        return clientSecret;
    }

    public AccessTokenResponse execute(MultiValueMap<String, String> data, String authorizationHeader) {
        String clientId = extractClientId(data, authorizationHeader);
        String clientSecret = extractClientSecret(data,authorizationHeader);
        String[] scopes = extractValue(data, "scope").orElse("").split(",");

        Application application = applicationRepository.findApplicationByClientIdAndClientSecretAndActivated(clientId, clientSecret, true)
                .orElseThrow(() -> new ApplicationNotFoundException(String.format("The application with client_id %s was not found",clientId)));
        checkScope(scopes, application);
        AccessTokenResponse returnValue = new AccessTokenResponse();
        String accessToken = jwtTokenService.createAccessToken(application.getClientId(), application.getApplicationType(), scopes);

        returnValue.setAccessToken(accessToken);
        returnValue.setTokenType(TokenType.BEARER.getStringValue());
        returnValue.setExpiration(Math.toIntExact(expiration));

        return returnValue;

    }


}
