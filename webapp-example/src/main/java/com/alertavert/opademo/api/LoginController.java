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
import com.alertavert.opa.jwt.JwtTokenProvider;
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

import static com.alertavert.opa.Constants.BASIC_AUTH;

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
    consumes = MimeTypeUtils.ALL_VALUE)
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
            log.debug("User `{}` authenticated, API Token generated: {}",
                apiToken.getUsername(), apiToken.getApiToken()));
  }

  private Mono<String> usernameFromHeader(String credentials) {
    log.debug("Extracting username from Authorization header");
    if (credentials.startsWith(BASIC_AUTH)) {
      return Mono.just(credentials.substring(BASIC_AUTH.length() + 1))
          .map(enc -> Base64Utils.decode(enc.getBytes(StandardCharsets.UTF_8)))
          .map(String::new)
          .map(creds -> {
            String[] userPass = creds.split(":");
            return userPass[0];
          })
          .doOnSuccess(userPass -> log.debug("Found user: {}", userPass));
    }
    return Mono.error(new IllegalStateException("Invalid Authorization header"));
  }
}
