package org.remus.simpleoauthserver.service;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.text.MessageFormat;
import java.util.Optional;
import java.util.Set;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

@Service
public class LoginService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public ApplicationRepository applicationRepository;

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginService.class);

    public LoginService(ApplicationRepository applicationRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.applicationRepository = applicationRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public Application getApplicationByIdAndRedirect(String clientId, String redirectUrl) {
        LOGGER.debug("Entering authentication with clientId {} and url {}", clientId, redirectUrl);
        Optional<Application> result = applicationRepository.findOneByClientIdAndActivated(clientId, true);
        Application application = result.orElseThrow(() -> new ApplicationNotFoundException(String.format("Application with id %s not found", clientId)));
        if (application.getLoginUrls().contains(redirectUrl)) {
            return application;
        }
        throw new ApplicationNotFoundException(String.format("The application with the given redirect %s was not found", redirectUrl));

    }

    public void checkUser(String username, String password, String clientId, String ipAdress) {
        Optional<User> user = userRepository.findOneByEmail(username);
        User foundUser = user.orElseThrow(() -> new UserNotFoundException("Error checking user, Either passowrd, username or client-id does not match."));
        LOGGER.debug("checkUser() called with: username = [" + username + "], password = [" + password + "], clientId = [" + clientId + "], ipAdress = [" + ipAdress + "]");
        if (!StringUtils.isEmpty(foundUser.getOrganization().getIpRestriction())) {
            try {
                if (!ipAdress.matches(foundUser.getOrganization().getIpRestriction())) {
                    throw new InvalidIpException(MessageFormat.format("The ip {0} doesn't match the given ip-restriction {1}",ipAdress,foundUser.getOrganization().getIpRestriction()));
                }
            } catch (PatternSyntaxException e) {
                throw new InvalidIpException(MessageFormat.format("The pattern {1} doesn't compile for user {0}",foundUser.getId(),foundUser.getOrganization().getIpRestriction()));
            }
        }
        if (!foundUser.isActivated()) {
            throw new UserLockedException(MessageFormat.format("The user {0} is locked. Exiting", foundUser.getEmail()));
        }
        if (passwordEncoder.matches(password,foundUser.getPassword())) {
            Optional<Application> application = user.get().getApplications().stream().filter(e -> clientId.equals(e.getClientId()) && e.isActivated()).findAny();
            if (application.isPresent()) {
                return;
            }
        }

        throw new UserNotFoundException("Error checking user, Either password, username or client-id does not match.");

    }

    public void checkScope(String username, String[] scopes) {
        Optional<User> user = userRepository.findOneByEmail(username);
        User foundUser = user.orElseThrow(() -> new UserNotFoundException("Error checking user"));
        Set<String> stringSet = foundUser.getScopeList().stream().map(Scope::getName).collect(Collectors.toSet());
        for (String scope : scopes) {
            if (!stringSet.contains(scope)) {
                throw new ScopeNotFoundException("The requested scope " + scope+ " was not found for user " + username);
            }
        }
    }

    public String createLoginToken(String username) {
        return ""; //tokenService.generateShortLivingToken(username);
    }
}
