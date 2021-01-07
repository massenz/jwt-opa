/*
 * Copyright (c) 2020 kapsules.io.  All rights reserved.
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
 */

package io.kapsules.jwt.api;

import io.kapsules.jwt.data.ReactiveUsersRepository;
import io.kapsules.jwt.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Base64Utils;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

import static io.kapsules.jwt.Constants.BASIC_AUTH;

/**
 * <h3>LoginController</h3>
 *
 * @author M. Massenzio, 2020-12-04
 */
@Slf4j
@RestController
@RequestMapping(
    path = "/login",
    produces = MimeTypeUtils.APPLICATION_JSON_VALUE,
    consumes = MimeTypeUtils.APPLICATION_JSON_VALUE)
public class LoginController {

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  ReactiveUsersRepository repository;

  @Autowired
  PasswordEncoder encoder;

  @GetMapping
  Mono<JwtController.ApiToken> login(
      @RequestHeader("Authorization") String credentials
  ) {
    log.debug("Got credentials: {}", credentials);
    return credentialsFromHeader(credentials)
        .flatMap(creds -> repository.findByUsername(creds[0])
            .map(u -> {
              if (!encoder.matches(creds[1], u.getPassword())) {
                throw new IllegalStateException("Password does not match");
              }
              return u;
            }))
        .map(u -> {
          String token = provider.createToken(u.getUsername(), u.roles());
          return new JwtController.ApiToken(u.getUsername(), u.roles(), token);
        })
        .doOnSuccess(apiToken ->
            log.debug("User {} authenticated, API Token generated: {}",
                apiToken.getUsername(), apiToken.getApiToken()));
  }

  private Mono<String[]> credentialsFromHeader(String credentials) {
    log.debug("Extracting username from Authorization credentials: {}", credentials);
    if (credentials.startsWith(BASIC_AUTH)) {
      return Mono.just(credentials.substring(BASIC_AUTH.length() + 1))
          .map(enc -> Base64Utils.decode(enc.getBytes(StandardCharsets.UTF_8)))
          .map(String::new)
          .map(creds -> {
            String[] userPass = creds.split(":");
            // TODO: remove this logging of the password.
            log.debug("Basic auth - user: {}, pass: {}", userPass[0], userPass[1]);
            return userPass;
          })
          .doOnSuccess(userPass -> log.debug("Found user: {}", userPass[0]));
    }
    return Mono.error(new IllegalStateException("Invalid Authorization header"));
  }
}
