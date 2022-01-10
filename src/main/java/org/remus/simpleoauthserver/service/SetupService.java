package org.remus.simpleoauthserver.service;

import org.apache.commons.lang3.RandomStringUtils;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.response.InitialApplicationResponse;
import org.remus.simpleoauthserver.security.ScopeRanking;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.transaction.Transactional;
import java.security.SecureRandom;
import java.util.Set;

@Service
public class SetupService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Value("${setup.secret}")
    private String setupSecret;

    private ApplicationRepository applicationRepository;

    private EntityManager entityManager;

    public SetupService(ApplicationRepository applicationRepository, EntityManager entityManager) {
        this.applicationRepository = applicationRepository;
        this.entityManager = entityManager;
    }

    /**
     * Checks if the application is able to create an initial super-admin.
     *
     * @return <code>true</code> if no super-admin data exists and the initial token matches, else <code>false</code>
     */
    public boolean canCreateInitialSuperAdmin(String initialToken) {
        return initialToken.equals(setupSecret) && !applicationRepository.findAllApplicationWithSuperAdminScope().iterator().hasNext();
    }

    @Transactional
    public InitialApplicationResponse createInitialApplication() {

        Scope scope = new Scope();
        scope.setName(ScopeRanking.SUPERADMIN_SCOPE);

        Application configuratorApp = new Application();
        configuratorApp.setScopeList(Set.of(scope));
        configuratorApp.setName("OAuth Server CLI Configurator");
        configuratorApp.setClientId(RandomStringUtils.random(32, 0, 0, true, true, null, new SecureRandom()));
        configuratorApp.setClientSecret(RandomStringUtils.random(64, 0, 0, true, true, null, new SecureRandom()));
        configuratorApp.setApplicationType(ApplicationType.M2M);
        configuratorApp.setActivated(true);

        entityManager.persist(scope);
        entityManager.persist(configuratorApp);

        InitialApplicationResponse response = new InitialApplicationResponse();
        response.setClientId(configuratorApp.getClientId());
        response.setClientSecret(configuratorApp.getClientSecret());

        logger.info("Created new configuratorApp {} with scope {}", configuratorApp, scope);

        return response;
    }


}
