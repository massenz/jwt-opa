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

import com.alertavert.opa.configuration.TokensProperties;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.extern.slf4j.Slf4j;
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
import java.util.Map;

/**
 * <h2>JwtTokenProvider</h2>
 *
 * <p>Handles JWT tokens validation, creation and authentication.
 *
 * @author M. Massenzio, 2020-11-19
 */
@Component
@Slf4j
public class JwtTokenProvider {
  public static final String ROLES = "roles";
  private static final String MASK = "****";
  private static final int MASKED_TOKEN_LEN = 12;

  private final Algorithm hmac;
  private final TokensProperties tokensProperties;

  public JwtTokenProvider(Algorithm hmac, TokensProperties tokensProperties) {
    this.hmac = hmac;
    this.tokensProperties = tokensProperties;
  }

  /**
   * This method takes an API Token and masks it by replacing the middle part with {@link #MASK},
   * and the first and last characters of the token, so that the total length is
   * {@link #MASKED_TOKEN_LEN}.
   *
   * @param token the API Token to mask
   * @return a masked version of the token
   */
  public static String maskToken(String token) {
    if (token == null) {
      return "";
    }
    var totLen = Math.min(token.length(), MASKED_TOKEN_LEN);
    if (totLen <= MASK.length()) {
      return MASK;
    }
    int prefixLen = Math.max(totLen - MASK.length() / 2, 1);
    return token.substring(0, prefixLen) + MASK
        + token.substring(token.length() - prefixLen);
  }

  public JWTVerifier verifier() {
    return JWT.require(hmac)
        .withIssuer(tokensProperties.getIssuer())
        .build();
  }

  /**
   * <p>Creates a JWT token for the given user, signed with the private key of the issuer.
   *
   * <p>The token is issued by the {@literal tokens.issuer} ({@literal "iss"} claim), and
   * contains the user's {@literal "username"} and {@literal "roles"}.
   *
   * <p>The token is valid for {@literal tokens.expires_after_sec} seconds from
   * {@literal  tokens.not_before_delay_sec} seconds in the
   * future, if this is configured; otherwise it will be valid from {@literal now}.
   *
   * @param user      the user for which to create the token
   * @param roles     the user's roles, which will be used for Authorization
   * @param expiresAt the expiration time of the token, if provided; otherwise it will be set based
   *                  on {@literal tokens.expires_after_sec}, if {@literal  tokens.should_expire()}
   *                  is true.
   * @param claims    a map of named claims to be added to the token; we currently support only
   *                  String, Integer and Boolean values. Can be null, in which case only the
   *                  default claims are set for the token.
   * @return the newly created JWT token
   * @see TokensProperties
   */
  public String createToken(String user, List<String> roles, @Nullable Instant expiresAt,
                            @Nullable Map<String, ?> claims) {
    Instant now = Instant.now();

    log.debug("Issuing JWT for user = {}, roles = {}", user, roles);
    JWTCreator.Builder builder = JWT.create()
        .withIssuer(tokensProperties.getIssuer())
        .withSubject(user)
        .withIssuedAt(Date.from(now))
        .withArrayClaim(ROLES, roles.toArray(new String[0]));

    if (expiresAt == null && tokensProperties.isShouldExpire()) {
      expiresAt = Instant.now().plusSeconds(tokensProperties.getExpiresAfterSec());
      log.debug("JWT will expire at {}", expiresAt);
    }
    if (expiresAt != null) {
      builder.withExpiresAt(Date.from(expiresAt));
    }
    if (tokensProperties.getNotBeforeDelaySec() > 0) {
      builder.withNotBefore(Date.from(now.plusSeconds(tokensProperties.getNotBeforeDelaySec())));
    }

    if (claims != null) {
      for (String claim : claims.keySet()) {
        Object value = claims.get(claim);
// TODO: once we upgrade to JDK 18 or greater use the Pattern Match in the switch and
//  allow for more types than String
//        switch (value) {
//          case String s -> builder.withClaim(claim, s);
//          case Boolean b -> builder.withClaim(claim, b);
//          case Integer n -> builder.withClaim(claim, n);
//          default -> throw new IllegalArgumentException("Supported types for claims are only "
//              + "string, boolean and integer, type " + value.getClass().getSimpleName() + " not "
//              + "supported");
//        }
        // This code compiles and works, but may cause unwanted (or surprising) results for
        // non-string types.
        if (!(value instanceof String)) {
          log.warn("Claim {} is not a string ({}) and adding it to the token may cause unexpected"
              + " results", claim, value.getClass().getSimpleName());
        }
        builder.withClaim(claim, value.toString());
      }

    }
    return builder.sign(hmac);
  }

  /**
   * Uses configuration to derive the Token expiration time.
   *
   * <p>If {@literal tokens.shouldExpire} is set to {@literal true} it will expire after
   * {@literal tokens.expiresAfterSec} seconds.
   *
   * <p>Simply calls {@link #createToken(String, List, Instant, Map)}.
   *
   * @param user  the username for the JWT (sub)
   * @param roles the roles for the user, used for Authorization
   * @return the newly created JWT token
   */
  public String createToken(String user, List<String> roles) {
    return createToken(user, roles, null, null);
  }

  /**
   * Creates a Token with a given expiration time, and default claims.
   *
   * <p>Simply calls {@link #createToken(String, List, Instant, Map)} with a null {@literal
   * claims} map.
   *
   * @param user  the username for the JWT (sub)
   * @param roles the roles for the user, used for Authorization
   * @param expiresAt the time when the JWT will expire
   * @return the newly created JWT token
   */
  public String createToken(String user, List<String> roles, Instant expiresAt) {
    return createToken(user, roles, expiresAt, null);
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
    return verifier().verify(token);
  }

  public Authentication getAuthentication(String token) {
    try {
      DecodedJWT decodedJWT = decode(token);
      String subject = decodedJWT.getSubject();

      List<? extends GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(
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
