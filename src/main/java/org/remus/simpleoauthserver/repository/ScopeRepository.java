/**
 * Copyright(c) 2022 Tom Seidel, Remus Software
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.remus.simpleoauthserver.repository;

import org.remus.simpleoauthserver.entity.Scope;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.util.List;
import java.util.Optional;

@CrossOrigin(origins = "*")
public interface ScopeRepository extends CrudRepository<Scope, Integer> {

    Scope findScopeByName(String name);

    Iterable<Scope> findScopesByNameIn(List<String> names);

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
