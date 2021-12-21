package org.remus.simpleoauthserver.repository;

import org.remus.simpleoauthserver.entity.Scope;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.Optional;

public interface ScopeRepository extends CrudRepository<Scope, Integer> {

    Scope findScopeByName(String name);

    @Override
    @PreAuthorize("hasPermission(#s, 'write')")
    <S extends Scope> S save(S s);

    @Override
    @PreAuthorize("hasPermission(#iterable, 'write')")
    <S extends Scope> Iterable<S> saveAll(Iterable<S> iterable);

    @Override
    @PostAuthorize("hasPermission(returnObject, 'read')")
    Optional<Scope> findById(Integer integer);

    @Override
    boolean existsById(Integer integer);

    @Override
    @PostFilter("hasPermission(filterObject, 'read')")
    Iterable<Scope> findAll();

    @Override
    @PostFilter("hasPermission(filterObject, 'read')")
    Iterable<Scope> findAllById(Iterable<Integer> iterable);

    @Override
    @PreAuthorize("hasPermission(#integer,'Scope','delete')")
    void deleteById(Integer integer);

    @Override
    @PreAuthorize("hasPermission(#scope, 'delete')")
    void delete(Scope scope);

    @Override
    @PreAuthorize("hasPermission(#iterable, 'delete')")
    void deleteAll(Iterable<? extends Scope> iterable);

    @Override
    @PreAuthorize("hasPermission('Scope','deleteAll')")
    void deleteAll();
}
