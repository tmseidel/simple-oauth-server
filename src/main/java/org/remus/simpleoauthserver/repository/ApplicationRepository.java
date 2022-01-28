package org.remus.simpleoauthserver.repository;

import org.remus.simpleoauthserver.entity.Application;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.util.Optional;

@CrossOrigin(origins = "*")
public interface ApplicationRepository extends CrudRepository<Application,Integer> {
    Optional<Application> findOneByClientIdAndActivated(String clientId, boolean activated);

    Optional<Application> findApplicationByClientIdAndClientSecretAndActivated(String clientId, String clientSecret, boolean activated);

    Optional<Application> findApplicationByClientId(String clientId);

    @Query("SELECT a FROM Application as a INNER JOIN a.scopeList s WHERE s.name = org.remus.simpleoauthserver.security.ScopeRanking.SUPERADMIN_SCOPE")
    Iterable<Application> findAllApplicationWithSuperAdminScope();

    @Override
    @PreAuthorize("hasPermission(#s, 'write')")
    <S extends Application> S save(S s);

    @Override
    @PreAuthorize("hasPermission(#iterable, 'write')")
    <S extends Application> Iterable<S> saveAll(Iterable<S> iterable);

    @Override
    @PostAuthorize("hasPermission(returnObject, 'read')")
    Optional<Application> findById(Integer integer);

    @Override
    boolean existsById(Integer integer);

    @Override
    @PostFilter("hasPermission(filterObject, 'read')")
    Iterable<Application> findAll();

    @Override
    @PostFilter("hasPermission(filterObject, 'read')")
    Iterable<Application> findAllById(Iterable<Integer> iterable);

    @Override
    long count();

    @Override
    @PreAuthorize("hasPermission(#integer,'User','delete')")
    void deleteById(Integer integer);

    @Override
    @PreAuthorize("hasPermission(#application, 'delete')")
    void delete(Application application);

    @Override
    @PreAuthorize("hasPermission(#iterable, 'delete')")
    void deleteAll(Iterable<? extends Application> iterable);

    @Override
    @PreAuthorize("hasPermission('Application','deleteAll')")
    void deleteAll();
}
