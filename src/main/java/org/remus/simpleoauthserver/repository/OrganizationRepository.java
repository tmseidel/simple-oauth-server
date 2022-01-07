package org.remus.simpleoauthserver.repository;

import org.remus.simpleoauthserver.entity.Organization;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.util.Optional;

@CrossOrigin(origins = "*")
public interface OrganizationRepository extends CrudRepository<Organization, Integer> {

    @Override
    @PreAuthorize("hasPermission(#s, 'write')")
    <S extends Organization> S save(S s);

    @Override
    @PreAuthorize("hasPermission(#iterable, 'write')")
    <S extends Organization> Iterable<S> saveAll(Iterable<S> iterable);

    @Override
    @PostAuthorize("hasPermission(returnObject, 'read')")
    Optional<Organization> findById(Integer integer);

    @Override
    boolean existsById(Integer integer);

    @Override
    @PostFilter("hasPermission(filterObject, 'read')")
    Iterable<Organization> findAll();

    @Override
    @PostFilter("hasPermission(filterObject, 'read')")
    Iterable<Organization> findAllById(Iterable<Integer> iterable);

    @Override
    @PreAuthorize("hasPermission(#integer,'Organization','delete')")
    void deleteById(Integer integer);

    @Override
    @PreAuthorize("hasPermission(#scope, 'delete')")
    void delete(Organization scope);

    @Override
    @PreAuthorize("hasPermission(#iterable, 'delete')")
    void deleteAll(Iterable<? extends Organization> iterable);

    @Override
    @PreAuthorize("hasPermission('Organization','deleteAll')")
    void deleteAll();
}
