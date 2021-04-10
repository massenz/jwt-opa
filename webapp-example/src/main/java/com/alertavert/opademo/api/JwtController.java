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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.alertavert.opa.JwtTokenProvider;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.security.KeyPair;
import java.util.List;
import java.util.Objects;

import static com.alertavert.opa.Constants.BEARER_TOKEN;

@Slf4j
@RestController
public class JwtController {

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  ReactiveUsersRepository repository;

  @Autowired
  KeyPair keyPair;

  @Data
  @AllArgsConstructor
  static class ApiToken {
    String username;
    List<String> roles;
    @JsonProperty("api-token")
    String apiToken;
  }

  @GetMapping(path = "/token/{user}", produces = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<ApiToken>> getToken(@PathVariable String user) {
    log.debug("Refreshing API Token for `{}`", user);

    return repository.findByUsername(user)
        .map(u -> {
          String token = provider.createToken(u.getUsername(), u.roles());
          return new ApiToken(user, u.roles(), token);
        })
        .map(ResponseEntity::ok)
        .doOnSuccess(response -> log.debug("Returning API Token for user {}: {}", user,
            Objects.requireNonNull(response.getBody()).getApiToken()))
        .onErrorReturn(Exception.class, ResponseEntity.badRequest().build());
  }

  /**
   * Demo endpoint, accessible to all users, to authenticate themselves.
   *
   * @param user the user we wish to authenticate, MUST be the same as the one carried as a
   *             "subject" in the API Token
   * @return a simple 200 OK if the user is a valid user and the API Token matches
   */
  // TODO: create the Rego policy that verifies the user is authorized to access this API
  @GetMapping(path = "/auth/{user}", produces = MimeTypeUtils.TEXT_PLAIN_VALUE)
  public Mono<ResponseEntity<String>> authenticate(
      @PathVariable String user,
      @RequestHeader("Authorization") String apiToken
  ) {
    // Note that while we could conduct the authorization step here, by decoding the JWT (using
    // the JWTProvider) and comparing the "sub" field with the `user`, this is entirely
    // delegated, transparently, to the OPA Server, and the policies configured there.
    //
    // If Spring Security allowed us to get this far, we know we're good and can simply return a
    // 200 OK response.
    return Mono.just(ResponseEntity.ok(
        String.format("API Token [%s] is valid for user %s ",
            apiToken.substring(BEARER_TOKEN.length() + 1),
            user)));
  }

  /**
   * "Demo" endpoint only accessible to SYSTEM administrators.
   */
  // TODO: implement the Rego policy to only allow SYSTEM role to acces this API
  @GetMapping(path = "/keypair", produces = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<?>> getKeypair() {
    return Mono.just(ResponseEntity.ok(keyPair));
  }
}
