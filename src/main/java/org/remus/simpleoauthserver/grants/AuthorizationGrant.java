package org.remus.simpleoauthserver.grants;

import io.jsonwebtoken.Claims;
import org.apache.commons.lang3.StringUtils;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.response.AccessTokenResponse;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.InvalidInputException;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.remus.simpleoauthserver.service.PkceService;
import org.remus.simpleoauthserver.service.TokenBinService;
import org.remus.simpleoauthserver.service.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;

import javax.persistence.EntityManager;
import javax.transaction.Transactional;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.owasp.encoder.Encode.forJava;
import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;

@Controller
public class AuthorizationGrant extends OAuthGrant {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final EntityManager entityManager;
    private final TokenBinService tokenBinService;
    private final PkceService pkceService;

    protected AuthorizationGrant(
            ApplicationRepository applicationRepository,
            UserRepository userRepository,
            JwtTokenService jwtTokenService,
            PasswordEncoder passwordEncoder,
            EntityManager entityManager,
            TokenBinService tokenBinService, PkceService pkceService) {
        super(applicationRepository, userRepository, jwtTokenService, passwordEncoder);
        this.entityManager = entityManager;
        this.tokenBinService = tokenBinService;
        this.pkceService = pkceService;
    }


    public void validateAuthorizationRequest(MultiValueMap<String, String> requestParams) {
        String requestParam = extractValue(requestParams, "response_type").orElseThrow(() -> new InvalidInputException("Request parameter response_type missing"));
        if (!CODE.equals(requestParam)) {
            throw new InvalidInputException("response_type is not 'code'");
        }
        String clientId = extractValue(requestParams, CLIENT_ID).orElseThrow(() -> new InvalidInputException("client_id is missing"));
        if (StringUtils.isEmpty(clientId)) {
            throw new InvalidInputException("client_id must not be empty.");
        }
        Optional<String> redirectUri = extractValue(requestParams, REDIRECT_URI);
        if (redirectUri.isPresent()) {
            boolean absoluteUrl = UrlUtils.isAbsoluteUrl(redirectUri.orElse(null));
            if (!absoluteUrl) {
                throw new InvalidInputException("redirect_uri is not an absolute URL.");
            }
        }
        Application application = findApplication(requestParams);
        if (application.getApplicationType() == ApplicationType.SPA) {
            String codeChallenge = extractValue(requestParams, CODE_CHALLENGE).orElseThrow(() -> new InvalidInputException("code_challenge is missing"));
            if (StringUtils.isEmpty(codeChallenge)) {
                throw new InvalidInputException("code_challenge is invalid");
            }
            String method = extractValue(requestParams, "code_challenge_method").orElseThrow(() -> new InvalidInputException("code_challenge_method is missing"));
            if (!"S256".equals(method)) {
                throw new InvalidInputException("The server only acceppts S256 pkce methods.");
            }
        }

    }


    public Application findApplication(MultiValueMap<String, String> requestParams) {
        String clientId = extractValue(requestParams, CLIENT_ID).orElseThrow();
        String redirectUrl = extractValue(requestParams, REDIRECT_URI).orElseThrow();
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

    public String createAuthorizationToken(String userName, Map<String, Object> data) {
        return jwtTokenService.createToken(userName, data, JwtTokenService.TokenType.AUTH);
    }

    @Transactional
    public AccessTokenResponse execute(MultiValueMap<String, String> body, String authorization) {
        String code = extractValue(body, CODE).orElseThrow(() -> new InvalidInputException("code is missing"));
        String clientId = extractClientId(body, authorization);
        String clientSecret = extractClientSecret(body, authorization);
        String redirectUrl = extractValue(body, REDIRECT_URI).orElseThrow();
        if (tokenBinService.isTokenInvalidated(code)) {
            throw new InvalidInputException("The token was already used.");
        }
        Application application = applicationRepository.findApplicationByClientIdAndClientSecretAndActivated(clientId, clientSecret, true)
                .orElseThrow(() -> new ApplicationNotFoundException("No application found"));
        checkCodeAndClientSecret(body, code, clientSecret, application);
        Claims claims = getClaims(code, clientId, redirectUrl);
        String userName = claims.getSubject();
        User user = userRepository.findOneByEmail(userName).orElseThrow(() -> new UserNotFoundException(String.format("User %s not found", userName)));
        Map<String, Object> tokenData = new HashMap<>();
        tokenData.put(SCOPE, claims.get(SCOPE));
        tokenData.put("organization_id", user.getOrganization().getId());
        tokenData.put("given_name", user.getName());
        tokenData.put("type", application.getApplicationType().name());
        tokenData.put(CLIENT_ID, clientId);

        AccessTokenResponse response = createResponse(userName, tokenData);
        tokenBinService.invalidateToken(code, claims.getExpiration());
        pkceService.invalidateToken(code);
        return response;
    }

    private Claims getClaims(String code, String clientId, String redirectUrl) {
        Claims claims = jwtTokenService.getAllClaimsFromToken(code, JwtTokenService.TokenType.AUTH);
        // Check if the client-id is the same as in the authorization-request.
        if (claims.get(CLIENT_ID, String.class) == null
                || !claims.get(CLIENT_ID, String.class).equals(clientId)) {
            throw new InvalidInputException("client_id not correct");
        }
        if (claims.get(REDIRECT_URI, String.class) == null
                || !claims.get(REDIRECT_URI, String.class).equals(redirectUrl)) {
            throw new InvalidInputException("redirect_uri not correct");
        }
        return claims;
    }

    private void checkCodeAndClientSecret(MultiValueMap<String, String> body, String code, String clientSecret, Application application) {
        // If the application is an SPA there is no client-secret and we have to check the verifier.
        if (application.getApplicationType() == ApplicationType.SPA) {
            String codeVerifier = extractValue(body, "code_verifier").orElseThrow(() -> new InvalidInputException("code-verifier is missing"));
            pkceService.checkVerifier(code, codeVerifier);
        } else {
            if (StringUtils.isEmpty(clientSecret) || !application.getClientSecret().equals(clientSecret)) {
                throw new InvalidInputException("No client secret found or client-secret invalid.");
            }
        }
    }

    @Transactional
    public void registerApplication(String clientId, String userName) {
        User oneByEmail = userRepository.findOneByEmail(userName).orElseThrow(() -> new InvalidInputException("username not found"));
        Application applicationByClientId = applicationRepository.findApplicationByClientId(clientId).orElseThrow(() -> new InvalidInputException("clientid not found"));
        if (!oneByEmail.getApplications().contains(applicationByClientId)) {
            oneByEmail.getApplications().add(applicationByClientId);
            entityManager.persist(oneByEmail);
        }
    }

    public void checkPkceEntry(String codeChallenge, String authorizationToken, String clientId, String redirectUri) {
        Application application = getApplicationByClientIdAndRedirect(clientId, redirectUri);
        if (application.getApplicationType() == ApplicationType.SPA) {
            pkceService.createEntry(authorizationToken, codeChallenge);
        }
    }
}
