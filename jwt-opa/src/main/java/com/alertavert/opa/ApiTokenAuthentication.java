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

import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.Collection;


/**
 * <h3>ApiTokenAuthentication</h3>
 * <p>
 * An {@link Authentication} implementation, based on an API Token (JWT) which is immutable and
 * validated at creation; the original {@literal token} can be obtained via the {@link
 * #getCredentials()} method.
 *
 * <p>To create API Token Authentication objects, use a {@link ApiTokenAuthenticationFactory
 * factory} (which in turn uses a {@link JwtTokenProvider provider} to validate the token).
 *
 * <p>The {@link #getPrincipal() principal} is the Token's {@literal "sub"} claim, while the
 * other "claims" carried in the token can be retrieved via the {@link #getDetails()} which will
 * return the {@link com.auth0.jwt.interfaces.DecodedJWT decoded JWT} which can be further
 * inspected.
 *
 * @author M. Massenzio, 2020-11-22
 * @see ApiTokenAuthenticationFactory
 * @see JwtTokenProvider
 */
@Slf4j
public class ApiTokenAuthentication extends AbstractAuthenticationToken {

  /**
   * The API Token's {@link #getPrincipal() principal}, as carried in the {@literal "sub"} claim.
   *
   * @see JwtPrincipal
   */
  private final Principal sub;

  private final String token;

  /**
   * Package private constructor, use the
   * {@link ApiTokenAuthenticationFactory#createAuthentication(String)}
   * factory method instead.
   *
   * <p>This <strong>always assumes the JWT to be valid</strong>, otherwise the factory method
   * would have failed, and none of the information would be available.
   *
   * <p><strong>DO NOT use directly</strong>, this constructor does not validate any of the
   * parameters.
   *
   * @param token       a Base-64 encoded representation of the JWT
   * @param sub         the Principal
   * @param authorities the Roles granted to the Principal
   * @param decodedJWT  the decoded API Token, from which other "claims" can be obtained; if
   *                    {@literal null}, it assumes the {@literal token} was invalid and could not
   *                    be decoded
   * @see ApiTokenAuthenticationFactory
   */
  ApiTokenAuthentication(
      String token, String sub,
      Collection<? extends GrantedAuthority> authorities,
      DecodedJWT decodedJWT
  ) {
    super(authorities);
    if (decodedJWT != null) {
      super.setAuthenticated(true);
      super.setDetails(decodedJWT);
      this.sub = new JwtPrincipal(sub);
    } else {
      this.sub = JwtPrincipal.NONE;
    }
    this.token = token;
  }

  /**
   * The API Token (JWT) that authenticates the request.
   *
   * @return the JWT as a String (Base64 encoded)
   */
  @Override
  public Object getCredentials() {
    return token;
  }

  /**
   * <p>The identity of the {@literal Principal} being authenticated is the
   * {@link "sub"} in the JWT body.
   *
   * @return the value of the {@literal "sub"} claim in the API Token.
   */
  @Override
  public Object getPrincipal() {
    return sub;
  }

  /**
   * This {@link Authentication} implementation is immutable, and whether the JWT is valid (hence
   * the {@link #getPrincipal() Principal} is authenticated) is set at creation time; any attempt to
   * change this will throw an {@link IllegalArgumentException}.
   *
   * @param isAuthenticated always ignored
   * @throws IllegalArgumentException always thrown by this method
   */
  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    throw new IllegalArgumentException("API Token must be validated at creation time");
  }

  /**
   * This {@link Authentication} implementation is immutable, and the JWT is set at creation time;
   * any attempt to change this will throw an {@link IllegalArgumentException}.
   *
   * @param details ignored
   * @throws IllegalArgumentException always thrown by this method
   */
  @Override
  public void setDetails(Object details) throws IllegalArgumentException {
    throw new IllegalArgumentException("API Token must be set at creation time");
  }

  /**
   * Implementation of the {@link Principal#implies(Subject)} abstract method.
   *
   * @param subject an authenticated Subject, which carries a list of Principals
   * @return wheter any of the Principals in Subject matches this {@link JwtPrincipal principal}
   */
  @Override
  public boolean implies(Subject subject) {
    return sub.implies(subject);
  }
}
