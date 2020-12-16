// Copyright (c) 2020 covaxx.io. All rights reserved.
//
// Created by M. Massenzio, 2020-09-03

package io.kapsules.jwt.api;

import io.kapsules.jwt.data.ReactiveUsersRepository;
import io.kapsules.jwt.data.User;
import io.kapsules.jwt.RoleAuthority;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    produces = MimeTypeUtils.APPLICATION_JSON_VALUE,
    consumes = MimeTypeUtils.APPLICATION_JSON_VALUE)
public class UserController {

  @Autowired
  ReactiveUsersRepository repository;

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
            repository.save(newUser)
                .map(u -> ResponseEntity.created(
                    URI.create(String.format("/users/%s", newUser.getUsername()))).body(u))
        );
  }

  @GetMapping("/{username}")
  @ResponseStatus(HttpStatus.OK)
  public Mono<ResponseEntity<User>> get(@PathVariable String username) {
    return repository.findByUsername(username)
        .map(ResponseEntity::ok)
        .switchIfEmpty(Mono.just(ResponseEntity.notFound().build()));
  }

  @GetMapping
  @ResponseStatus(HttpStatus.OK)
  public Flux<User> getAll() {
      return repository.findAll();
  }

  @PutMapping(path = "/{username}/role/{role}")
  @ResponseStatus(HttpStatus.OK)
  public Mono<ResponseEntity<User>> addRole(
      @PathVariable String username,
      @PathVariable String role
  ) {
       return repository.findByUsername(username)
                .map(u -> {
                  u.getRoles().add(new RoleAuthority(role));
                  return u;
                })
                .flatMap(repository::save)
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
        .flatMap(repository::save)
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
                .flatMap(repository::save)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build())
        );
  }
}
