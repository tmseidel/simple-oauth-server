package org.remus.simpleoauthserver.service;

import org.apache.commons.lang3.StringUtils;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.MessageFormat;
import java.util.Optional;
import java.util.Set;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import static org.owasp.encoder.Encode.forJava;

@Service
public class LoginService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private JwtTokenService tokenService;

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginService.class);

    public LoginService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenService tokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
    }

    public void checkUser(String username, String password, String clientId, String ipAdress) {
        Optional<User> user = userRepository.findOneByEmail(username);
        User foundUser = user.orElseThrow(() -> new UserNotFoundException("Error checking user, Either passowrd, username or client-id does not match."));
        LOGGER.debug("checkUser() called with: username = [{}], clientId = [{}], ipAdress = [{}]", forJava(username), forJava(clientId), forJava(ipAdress));
        if (!StringUtils.isEmpty(foundUser.getOrganization().getIpRestriction())) {
            try {
                if (!ipAdress.matches(foundUser.getOrganization().getIpRestriction())) {
                    throw new InvalidIpException(MessageFormat.format("The ip {0} doesn''t match the given ip-restriction {1}", forJava(ipAdress), foundUser.getOrganization().getIpRestriction()));
                }
            } catch (PatternSyntaxException e) {
                throw new InvalidIpException(MessageFormat.format("The pattern {1} doesn''t compile for user {0}", foundUser.getId(), foundUser.getOrganization().getIpRestriction()));
            }
        }
        if (!foundUser.isActivated()) {
            throw new UserLockedException(MessageFormat.format("The user {0} is locked. Exiting", foundUser.getEmail()));
        }
        if (passwordEncoder.matches(password, foundUser.getPassword())) {
            Optional<Application> application = user.flatMap(f -> f.getApplications().stream().filter(e -> clientId.equals(e.getClientId()) && e.isActivated()).findAny());
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
                throw new ScopeNotFoundException("The requested scope " + scope + " was not found for user " + username);
            }
        }
    }

    public String createLoginToken(String username) {
        return tokenService.createAuthorizationToken(username);
    }
}
