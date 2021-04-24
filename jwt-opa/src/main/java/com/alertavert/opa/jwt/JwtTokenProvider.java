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

package com.alertavert.opa.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.alertavert.opa.configuration.KeyProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * <h3>JwtTokenProvider</h3>
 *
 * <p>Handles JWT tokens validation, creation and authentication.
 *
 * <p>Based on
 * <a href="https://github.com/hantsy/spring-reactive-jwt-sample/blob/master/src/main/java/com/example/demo/security/jwt/JwtTokenProvider.java">
 * this example code</a>
 *
 * <p><strong>This class is a temporary implementation and need a lot of refinement</strong></p>
 *
 * @author M. Massenzio, 2020-11-19
 */
@Component
@Slf4j
public class JwtTokenProvider {

  public static final String ROLES = "roles";

  @Autowired
  Algorithm hmac;

  @Autowired
  JWTVerifier verifier;

  @Autowired
  String issuer;

  @Autowired
  KeyProperties keyProperties;

  public String createToken(String user, List<String> roles) {
    Instant now = Instant.now();

    JWTCreator.Builder builder = JWT.create()
        .withIssuer(issuer)
        .withSubject(user)
        .withClaim(ROLES, roles)
        .withIssuedAt(Date.from(now));

    if (keyProperties.isShouldExpire()) {
      Instant expires = now.plusSeconds(keyProperties.getExpiresAfterSec());
      log.debug("JWT will expire at {}", expires);
      builder.withExpiresAt(Date.from(expires));
    }

    if (keyProperties.getNotBeforeDelaySec() > 0) {
      Instant notBefore = now.plusSeconds(keyProperties.getNotBeforeDelaySec());
      log.debug("JWT Not Valid Before {}", notBefore);
      builder.withNotBefore(Date.from(notBefore));
    }

    String token = builder.sign(hmac);
    log.debug("Issuing JWT: {}", token);
    return token;
  }

  public boolean validateToken(String token) {
    try {
      decode(token);
      return true;
    } catch (JWTVerificationException error) {
      log.error("Failed to verify token: {}", error.getMessage());
      return false;
    }
  }

  public DecodedJWT decode(String token) throws JWTVerificationException {
    return verifier.verify(token);
  }

  public Authentication getAuthentication(String token) {
    try {
      DecodedJWT decodedJWT = decode(token);
      String subject = decodedJWT.getSubject();

      List<? extends  GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(
          decodedJWT.getClaim(ROLES).asArray(String.class));

      // We do not store the password here, as we do not need it (by virtue of the API Token
      // having been successfully verified, we know the user is authenticated).
      // TODO: should we allow client applications to retrieve/inject it here?
      User principal = new User(subject, "", authorities);
      return new UsernamePasswordAuthenticationToken(principal, token, authorities);

    } catch (Exception error) {
      log.error("Could not authenticate Token: {}", error.getMessage());
    }
    return null;
  }
}
