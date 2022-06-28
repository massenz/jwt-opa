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
import com.alertavert.opa.configuration.TokensProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.BadCredentialsException;
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
 * <h2>JwtTokenProvider</h2>
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
  TokensProperties tokensProperties;

  /**
   * <p>Creates a JWT token for the given user, signed with the private key of the issuer.
   *
   * <p>The token contains the user's username and the user's roles.
   *
   * <p>The token is valid for {@link TokensProperties#getExpiresAfterSec()} seconds.
   *
   * <p>The token is valid from {@link TokensProperties#getNotBeforeDelaySec()} seconds in the
   * future, if this is configured; otherwise it will be valid from now.
   *
   * <p>The token is issued by {@link TokensProperties#getIssuer()}.
   *
   * @param user the user for which to create the token
   * @param roles the user's roles, which will be used for Authorization
   * @param expiresAt the expiration time of the token
   * @return the newly created JWT token
   */
  public String createToken(String user, List<String> roles, @Nullable Instant expiresAt) {
    Instant now = Instant.now();

    log.debug("Issuing JWT for user = {}, roles = {}", user, roles);
    JWTCreator.Builder builder = JWT.create()
        .withIssuer(issuer)
        .withSubject(user)
        .withIssuedAt(Date.from(now))
        .withArrayClaim(ROLES, roles.toArray(new String[0]));

    if (expiresAt != null) {
      builder.withExpiresAt(Date.from(expiresAt));
    }
    if (tokensProperties.getNotBeforeDelaySec() > 0) {
      builder.withNotBefore(Date.from(now.plusSeconds(tokensProperties.getNotBeforeDelaySec())));
    }
    return builder.sign(hmac);
  }

  /**
   * Creates a new JWT token for the given user.
   * <p>If configured to do so ({@literal tokens.shouldExpire}) it will expire after the
   * configured time, in seconds ({@literal tokens.expiresAfterSec}).
   *
   * @param user the username for the JWT (sub)
   * @param roles the roles for the user, used for Authorization
   * @return the newly created JWT token
   */
  public String createToken(String user, List<String> roles) {
    Instant expiresAt = null;
    if (tokensProperties.isShouldExpire()) {
      expiresAt = Instant.now().plusSeconds(tokensProperties.getExpiresAfterSec());
      log.debug("JWT will expire at {}", expiresAt);
    }
    return createToken(user, roles, expiresAt);
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

      log.debug("Token is valid: subject = `{}`, authorities = `{}`", subject, authorities);

      // We do not store the password here, as we do not need it (by virtue of the API Token
      // having been successfully verified, we know the user is authenticated).
      User principal = new User(subject, "", authorities);
      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    } catch (Exception error) {
      log.warn("Could not authenticate Token: {}", error.getMessage());
      throw new BadCredentialsException("JWT invalid", error);
    }
  }

  /**
   * Decodes the given token and returns the `expiry_at` claim, if it exists.
   *
   * @param token the JWT to decode
   * @return the expiry time of the token, or null if it does not exist
   */
  public Date getExpiryDate(String token) {
    return decode(token)
        .getExpiresAt();
  }
}
