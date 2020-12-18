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

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

import static io.kapsules.jwt.JwtTokenProvider.ROLES;

/**
 * <h3>ApiTokenAuthenticationFactory</h3>
 *
 * <p>Insert class description here...
 *
 * @author M. Massenzio, 2020-12-15
 */
@Service
public class ApiTokenAuthenticationFactory {

  @Autowired
  JwtTokenProvider provider;

  public ApiTokenAuthentication createAuthentication(String token) {
    ApiTokenAuthentication auth;
    try {
      DecodedJWT jwt = provider.decode(token);
      List<? extends  GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(
          jwt.getClaim(ROLES).asArray(String.class));
      String subject = jwt.getSubject();

      auth = new ApiTokenAuthentication(token, subject, authorities, jwt);

    } catch (JWTVerificationException exception) {
      // We don't want to throw inside a factory method, so we partially construct
      // the authentication object, but we set its state to "unauthenticated".
      // We need to use here the superclass #setAuthenticated() because the method
      // in the ApiTokenAuth class has been disabled and throws if called.
      //
      auth = new ApiTokenAuthentication(token, "", Collections.emptyList(), null);
    }
    return auth;
  }
}
