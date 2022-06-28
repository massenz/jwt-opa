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

package com.alertavert.opa;

import com.alertavert.opa.jwt.JwtTokenProvider;
import com.alertavert.opa.configuration.TokensProperties;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.sql.Date;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

import static com.auth0.jwt.impl.PublicClaims.EXPIRES_AT;
import static com.auth0.jwt.impl.PublicClaims.ISSUED_AT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertThrows;

class JwtTokenProviderTest extends AbstractTestBase {

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  TokensProperties properties;

  @Test
  public void createToken() {
    String token = provider.createToken("a-user", Lists.list("USER",
        "PAINTER", "POET"));

    JWT jwt = new JWT();
    DecodedJWT decoded = jwt.decodeJwt(token);

    assertThat(decoded).isNotNull();
    assertThat(decoded.getSubject()).isEqualTo("a-user");
    assertThat(decoded.getClaim(JwtTokenProvider.ROLES).asArray(String.class))
        .containsExactlyInAnyOrder("USER", "PAINTER", "POET");

    // Test time/expiry claims.
    assertThat(decoded.getClaim(ISSUED_AT).isNull()).isFalse();
    assertThat(decoded.getClaim(EXPIRES_AT).isNull()).isFalse();

    assertThat(decoded.getClaim(ISSUED_AT).asLong()).isLessThanOrEqualTo(
        Instant.now().getEpochSecond());

    long expiryAfter = properties.getExpiresAfterSec();
    assertThat(decoded.getClaim(EXPIRES_AT).asLong()).isEqualTo(
        decoded.getClaim(ISSUED_AT).asLong() + expiryAfter);
  }

  @Test
  public void createTokenThatNeverExpires() {
    boolean shouldExpire = properties.isShouldExpire();
    properties.setShouldExpire(false);
    String token = provider.createToken("alice", Lists.list("USER"));

    // Restore state for subsequent tests.
    properties.setShouldExpire(shouldExpire);

    // We specifically here avoid using TokenProvider's own methods.
    JWT jwt = new JWT();
    DecodedJWT decoded = jwt.decodeJwt(token);

    assertThat(decoded).isNotNull();
    assertThat(decoded.getClaim(EXPIRES_AT).isNull()).isTrue();
  }

  @Test
  public void createTokenWithExpiresAt() {
    Instant expires = Instant.now().plusSeconds(60);
    String token = provider.createToken("alice", Lists.list("USER"), expires);

    // We specifically here avoid using TokenProvider's own methods.
    JWT jwt = new JWT();
    DecodedJWT decoded = jwt.decodeJwt(token);

    assertThat(decoded).isNotNull();
    assertThat(decoded.getClaim(EXPIRES_AT).asLong()).isEqualTo(expires.getEpochSecond());
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

  @Test
  public void createTokenWithNotBefore() {
    long delay = properties.getNotBeforeDelaySec();
    properties.setNotBeforeDelaySec(60);
    String token = provider.createToken("charlie", List.of("USER"));

    // Restore state for subsequent tests.
    properties.setNotBeforeDelaySec(delay);

    assertThrows(InvalidClaimException.class, () -> provider.decode(token));
  }

  @Test
  public void invalidTokenFailsAuthentication() {
    assertThrows(AuthenticationException.class,
        () -> provider.getAuthentication("definitelynotatoken"));
  }

  @Test
  public void expiryDate() {
    Instant expiresAt = Instant.now().plusSeconds(60);
    String token = provider.createToken("alice", Lists.list("USER"), expiresAt);
    assertThat(provider.getExpiryDate(token)).isCloseTo(expiresAt, 999);
  }

  @Test
  public void expiryDateUnset() {
    boolean shouldExpire = properties.isShouldExpire();
    properties.setShouldExpire(false);

    String token = provider.createToken("alice", Lists.list("USER"));
    assertThat(provider.getExpiryDate(token)).isNull();

    // Restore state for subsequent tests.
    properties.setShouldExpire(shouldExpire);
  }
}
