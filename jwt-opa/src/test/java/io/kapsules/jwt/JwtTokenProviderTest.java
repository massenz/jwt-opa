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

package io.kapsules.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.stream.Collectors;

import static io.kapsules.jwt.JwtTokenProvider.ROLES;
import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenProviderTest extends AbstractTestBase {

  @Autowired
  JwtTokenProvider provider;

  @Test
  public void createToken() {
    String token = provider.createToken("a-user", Lists.list("USER",
        "PAINTER", "POET"));

    JWT jwt = new JWT();
    DecodedJWT decoded = jwt.decodeJwt(token);
    assertThat(decoded).isNotNull();
    assertThat(decoded.getSubject()).isEqualTo("a-user");
    assertThat(decoded.getClaim(ROLES).asArray(String.class))
        .containsExactlyInAnyOrder("USER", "PAINTER", "POET");
  }

  @Test
  public void canVerifyCreated() {
    String token = provider.createToken("me", Lists.list("uno"));
    assertThat(provider.validateToken(token)).isTrue();
  }

  @Test
  public void verifyBogusFails() {
    String token = provider.createToken("attacker", Lists.list("CHEAT"));
    assertThat(provider.validateToken(
        token.replace("a", "A").replace("Y", "q"))).isFalse();
  }

  @Test
  public void getAuthentication() {
    String token = provider.createToken("alice", Lists.list("USER", "ADMIN"));

    Authentication auth = provider.getAuthentication(token);

    assertThat(auth).isNotNull();
    assertThat(auth.isAuthenticated()).isTrue();

    // This is needed, as the Authentication object does not know that its Principal is,
    // in fact, a User object
    User alice = (User) auth.getPrincipal();
    assertThat(alice.getUsername()).isEqualTo("alice");
    assertThat(auth.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.toList())
    ).containsExactlyInAnyOrder("USER", "ADMIN");
  }
}
