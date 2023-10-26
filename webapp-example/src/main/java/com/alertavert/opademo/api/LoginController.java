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

import com.alertavert.opa.jwt.JwtTokenProvider;
import com.alertavert.opademo.data.ReactiveUsersRepository;
import com.alertavert.opademo.data.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static com.alertavert.opa.Constants.BASIC_AUTH;
import static com.alertavert.opa.Constants.MAX_TOKEN_LEN_LOG;

/**
 * <h2>LoginController</h2>
 *
 * @author M. Massenzio, 2020-12-04
 */
@Slf4j
@RestController
@RequestMapping(
    path = "/login",
    produces = MimeTypeUtils.APPLICATION_JSON_VALUE,
    consumes = MimeTypeUtils.ALL_VALUE)
public class LoginController {

  private final JwtTokenProvider provider;
  private final ReactiveUsersRepository repository;

  public LoginController(JwtTokenProvider provider, ReactiveUsersRepository repository) {
    this.provider = provider;
    this.repository = repository;
  }


  @GetMapping
  Mono<JwtController.ApiToken> login(
      @RequestHeader("Authorization") String credentials
  ) {
    // Note here we do not even attempt to authenticate the user: because of the Spring Security
    // injection, we know that, if we got here, the user is authenticated and their credentials
    // are valid.
    return usernameFromHeader(credentials)
        .flatMap(repository::findByUsername)
        .map(u -> {
          log.debug("Creating API Token (JWT) for {}", u.getUsername());
          String token = provider.createToken(u.getUsername(), u.roles());
          return new JwtController.ApiToken(u.getUsername(), u.roles(), token);
        })
        .doOnNext(apiToken ->
            log.debug("User authenticated, user = {}, token = {}...",
                apiToken.username(), apiToken.apiToken().substring(0, MAX_TOKEN_LEN_LOG)));
  }

  @GetMapping("/reset/{username}")
  @ResponseStatus(HttpStatus.OK)
  Mono<ResponseEntity<User>> resetPassword(@PathVariable String username) {
    return repository.findByUsername(username)
        .map(u -> {
          log.info("Resetting password for user {}", u.getUsername());
          // FIXME: we should actually generate a unique URL and send it via email, for the user
          //  to pick a new password.
          String newPass = UUID.randomUUID().toString().substring(12);
          return User.withPassword(u, newPass);
        })
        .flatMap(repository::save)
        .map(ResponseEntity.ok()::body)
        .defaultIfEmpty(ResponseEntity.notFound().build());
  }

  /**
   * Parses the BASIC Authorization header (base-64 encoded) into a semicolon-separated pair, and
   * extracts the username from the pair.
   *
   * @param credentials a base-64 encoded {@literal username:password} pair, prefixed by
   * {@link com.alertavert.opa.Constants#BASIC_AUTH}.
   *
   * @return the decoded, plaintext username
   */
  public static Mono<String> usernameFromHeader(String credentials) {
    log.debug("Extracting username from Authorization header");
    if (credentials.startsWith(BASIC_AUTH)) {
      return Mono.just(credentials.substring(BASIC_AUTH.length() + 1))
          .map(enc -> Base64.getDecoder().decode(enc.getBytes(StandardCharsets.UTF_8)))
          .map(String::new)
          .map(creds -> {
            String[] userPass = creds.split(":");
            return userPass[0];
          })
          .doOnSuccess(userPass -> log.debug("Found user: {}", userPass));
    }
    return Mono.error(new IllegalStateException("Invalid Authorization header"));
  }

  public static Mono<String> credentialsToHeader(String credentials) {
    String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    return Mono.just(String.format("%s %s", BASIC_AUTH, encoded));
  }
}
