package org.remus.simpleoauthserver.service;

import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.security.ScopeRanking;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.transaction.Transactional;
import java.util.Date;
import java.util.Set;

@Service
public class SetupService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Value("${setup.secret}")
    private String setupSecret;

    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;

    private EntityManager entityManager;

    public SetupService(UserRepository userRepository, PasswordEncoder passwordEncoder, EntityManager entityManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.entityManager = entityManager;
    }

    /**
     * Checks if the application is able to create an initial super-admin.
     *
     * @return <code>true</code> if no super-admin data exists and the initial token matches, else <code>false</code>
     */
    public boolean canCreateInitialSuperAdmin(String initialToken) {
        return initialToken.equals(setupSecret) && !userRepository.findAllSuperAdmins().iterator().hasNext();
    }

    @Transactional
    public void createInitialSuperAdmin(String superAdminUserName, String superAdminPassword, String superAdminName, String organizationName) {
        Scope scope = new Scope();
        scope.setName(ScopeRanking.SUPERADMIN_SCOPE);
        Organization organization = new Organization();
        organization.setName(organizationName);
        User user = new User();
        user.setEmail(superAdminUserName);
        user.setName(superAdminName);
        user.setOrganization(organization);
        user.setActivated(true);
        user.setCreated(new Date());

        user.setPassword(passwordEncoder.encode(superAdminPassword));
        user.setScopeList(Set.of(scope));
        entityManager.persist(organization);
        entityManager.persist(scope);
        entityManager.persist(user);
        logger.info("Created new user {} with organization {}", user, organization);
    }
}
