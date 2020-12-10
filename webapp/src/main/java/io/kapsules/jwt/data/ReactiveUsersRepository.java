// Copyright (c) 2020 covaxx.io. All rights reserved.
//
// Created by M. Massenzio, 2020-09-03

package io.kapsules.jwt.data;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface ReactiveUsersRepository extends ReactiveCrudRepository<User, String> {
  Mono<User> findByUsername(String username);

  Mono<User> removeByUsername(String username);

  Flux<User> findAllByRolesContains(User.RoleAuthority role);

}
