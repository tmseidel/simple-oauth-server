package org.remus.simpleoauthserver.flows;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.InvalidInputException;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;

import java.util.Optional;

import static org.owasp.encoder.Encode.forJava;
import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;

@Service
public class AuthorizationFlow extends OAuthFlow {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected AuthorizationFlow(ApplicationRepository applicationRepository, UserRepository userRepository, JwtTokenService jwtTokenService, PasswordEncoder passwordEncoder) {
        super(applicationRepository, userRepository, jwtTokenService, passwordEncoder);
    }


    public void validateAuthorizationRequest(MultiValueMap<String, String> requestParams) {
        String requestParam = extractValue(requestParams, "response_type").orElseThrow(() -> new InvalidInputException("Request parameter response_type missing"));
        if (!"code".equals(requestParam)) {
            throw new InvalidInputException("response_type is not 'code'");
        }
        extractValue(requestParams,"client_id").orElseThrow(() -> new InvalidInputException("client_id is missing"));
        Optional<String> redirectUri = extractValue(requestParams, "redirect_uri");
        if(redirectUri.isPresent()) {
            boolean absoluteUrl = UrlUtils.isAbsoluteUrl(redirectUri.orElse(null));
            if (!absoluteUrl) {
                throw new InvalidInputException("redirect_uri is not an absolute URL.");
            }
        }

    }

    public void validateAccessTokenRequest(MultiValueMap<String, String> requestParams) {

    }

    public Application findApplication(MultiValueMap<String, String> requestParams) {
        String clientId = extractValue(requestParams,"client_id").orElseThrow();
        String redirectUrl = extractValue(requestParams,"redirect_uri").orElseThrow();
        if (logger.isDebugEnabled()) {
            logger.debug("Entering authentication with clientId {} and url {}", forJava(clientId), forJava(redirectUrl));
        }
        return getApplicationByClientIdAndRedirect(clientId, redirectUrl);

    }

    public Application getApplicationByClientIdAndRedirect(String clientId, String redirectUrl) {
        Optional<Application> result = applicationRepository.findOneByClientIdAndActivated(clientId, true);
        Application application = result.orElseThrow(() -> new ApplicationNotFoundException(String.format("Application with id %s not found", clientId)));
        if (application.getLoginUrls().contains(redirectUrl)) {
            return application;
        }
        throw new ApplicationNotFoundException(String.format("The application with the given redirect %s was not found", redirectUrl));
    }


    public User checkLogin(String userName, String password, String clientId, String remoteAddr, String[] scopes) {
        User checkedUser = checkUser(userName, password, clientId, remoteAddr);
        checkScope(checkedUser, scopes);
        return checkedUser;
    }

    public String createLoginToken(String userName) {
        return jwtTokenService.createAuthorizationToken(userName);
    }
}
