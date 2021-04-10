/*
 * Copyright (c) 2021 AlertAvert.com.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Marco Massenzio (marco@alertavert.com)
 */

package com.alertavert.opademo.api;

import com.alertavert.opademo.data.ReactiveUsersRepository;
import com.alertavert.opademo.data.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Collections;


@Slf4j
@RestController
@RequestMapping(
    path = "/users",
    produces = MimeTypeUtils.APPLICATION_JSON_VALUE
)
public class UserController {

  private static final String DEFAULT_ROLE = "USER";

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  ReactiveUsersRepository repository;

  private Mono<User> saveAndMaskPassword(User user) {
    if (user.getRoles().isEmpty()) {
      user.setRoles(Collections.singletonList(DEFAULT_ROLE));
    }

    User withEncodedPwd = User.withPassword(user,
        encoder.encode(user.getPassword()));

    return repository.save(withEncodedPwd)
        .map(u -> User.withPassword(u, null));
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public Mono<ResponseEntity<?>> create(@RequestBody User newUser) {
    if (newUser.getUserId() != null) {
      return Mono.just(
          ResponseEntity.badRequest()
              .body("User ID cannot be specified when creating a new user")
      );
    }

    return repository.findByUsername(newUser.getUsername())
        .hasElement()
        .flatMap(b -> b ?
            Mono.error(new ResponseStatusException(HttpStatus.CONFLICT,
                String.format("User %s already exists", newUser.getUsername()))) :
            saveAndMaskPassword(newUser)
                .map(u -> ResponseEntity.created(
                    URI.create(String.format("/users/%s", newUser.getUsername()))).body(u))
        );
  }

  @GetMapping(value = "/{username}", produces = MimeTypeUtils.APPLICATION_JSON_VALUE,
      consumes = MimeTypeUtils.ALL_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public Mono<ResponseEntity<User>> get(@PathVariable String username) {
    return repository.findByUsername(username)
        .map(u ->  User.withPassword(u, null))
        .doOnNext(u -> log.debug("Found User: {}", u))
        .map(ResponseEntity::ok)
        .switchIfEmpty(Mono.just(ResponseEntity.notFound().build()));
  }

  @GetMapping(consumes = MimeTypeUtils.ALL_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public Flux<User> getAll() {
    return repository.findAll()
        .map(u -> User.withPassword(u, "****"));
  }

  @PutMapping(path = "/{username}/role/{role}")
  @ResponseStatus(HttpStatus.OK)
  public Mono<ResponseEntity<User>> addRole(
      @PathVariable String username,
      @PathVariable String role
  ) {
       return repository.findByUsername(username)
                .map(u -> {
                  u.getRoles().add(role);
                  return u;
                })
                .flatMap(this::saveAndMaskPassword)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
  }

  @PutMapping(path = "/{username}/password/{password}")
  @ResponseStatus(HttpStatus.OK)
  public Mono<ResponseEntity<User>> changePassword(
      @PathVariable String username,
      @PathVariable String password
  ) {
    return repository.findByUsername(username)
        .map(u -> User.withPassword(u, password))
        .flatMap(this::saveAndMaskPassword)
        .map(ResponseEntity::ok)
        .defaultIfEmpty(ResponseEntity.notFound().build());
  }

  @PutMapping(path = "/{username}/username/{newUsername}")
  @ResponseStatus(HttpStatus.OK)
  public Mono<ResponseEntity<?>> changeUsername(
      @PathVariable String username,
      @PathVariable String newUsername
  ) {
    return repository.findByUsername(newUsername)
        .hasElement()
        .flatMap(b -> b ?
            Mono.just(ResponseEntity.status(HttpStatus.CONFLICT).body(
                Collections.singletonMap("message",
                    String.format("Username %s already in use", newUsername)))) :

            repository.findByUsername(username)
                .map(u -> User.withUsername(u, newUsername))
                .flatMap(this::saveAndMaskPassword)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build())
        );
  }
}
