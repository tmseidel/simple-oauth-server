package org.remus.simpleoauthserver.flows;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static org.owasp.encoder.Encode.forJava;

@Service
public class AuthorizationFlow {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private ApplicationRepository applicationRepository;

    public AuthorizationFlow(ApplicationRepository applicationRepository) {
        this.applicationRepository = applicationRepository;
    }

    public void validateAuthorizationRequest(String responseType, String clientId, String redirectUri, String scope, String state, String responseMode) {
        // not yet implemented
    }

    public Application findApplication(String clientId, String redirectUrl) {
        if (logger.isDebugEnabled()) {
            logger.debug("Entering authentication with clientId {} and url {}", forJava(clientId), forJava(redirectUrl));
        }
        Optional<Application> result = applicationRepository.findOneByClientIdAndActivated(clientId, true);
        Application application = result.orElseThrow(() -> new ApplicationNotFoundException(String.format("Application with id %s not found", clientId)));
        if (application.getLoginUrls().contains(redirectUrl)) {
            return application;
        }
        throw new ApplicationNotFoundException(String.format("The application with the given redirect %s was not found", redirectUrl));

    }
}
