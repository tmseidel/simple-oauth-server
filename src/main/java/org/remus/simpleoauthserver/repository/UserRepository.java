package org.remus.simpleoauthserver.repository;

import org.remus.simpleoauthserver.entity.User;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.util.List;
import java.util.Optional;

@CrossOrigin(origins = "*")
public interface UserRepository extends CrudRepository<User, Integer> {

    Optional<User> findOneByEmail(String email);

    Optional<User> findOneByEmailAndActivated(String email, boolean activated);

    @Query("SELECT u FROM User as u INNER JOIN u.scopeList s WHERE s.name = org.remus.simpleoauthserver.security.ScopeRanking.SUPERADMIN_SCOPE")
    Iterable<User> findAllSuperAdmins();

    @Query("SELECT u FROM User u WHERE u.email = ?#{principal.username}")
    User findCurrentUser();

    @Query("SELECT u FROM User as u INNER JOIN u.scopeList s INNER JOIN u.applications o WHERE u.email = :email AND o.clientId = :clientId AND s.name IN :scopeList")
    User findByEmailAndScope(@Param("email") String email, @Param("clientId") String clientId, @Param("scopeList") List<String> scopes);

    @Override
    @PreAuthorize("hasPermission(#s, 'write')")
    <S extends User> S save(S s);

    @Override
    @PreAuthorize("hasPermission(#iterable, 'write')")
    <S extends User> Iterable<S> saveAll(Iterable<S> iterable);

    @Override
    @PostAuthorize("hasPermission(returnObject, 'read')")
    Optional<User> findById(Integer integer);

    @Override
    boolean existsById(Integer integer);

    @Override
    @PostFilter("hasPermission(filterObject, 'read')")
    Iterable<User> findAll();

    @Override
    @PostFilter("hasPermission(filterObject, 'read')")
    Iterable<User> findAllById(Iterable<Integer> iterable);

    @Override
    @PreAuthorize("hasPermission(#integer,'User','delete')")
    void deleteById(Integer integer);

    @Override
    @PreAuthorize("hasPermission(#user, 'delete')")
    void delete(User user);

    @Override
    @PreAuthorize("hasPermission(#iterable, 'delete')")
    void deleteAll(Iterable<? extends User> iterable);

    @Override
    @PreAuthorize("hasPermission('User','deleteAll')")
    void deleteAll();
}
