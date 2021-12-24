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

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * <h2>ApiTokenAuthenticationFactory</h2>
 *
 * @author M. Massenzio, 2020-12-15
 */
@Service
public class ApiTokenAuthenticationFactory {

  @Autowired
  JwtTokenProvider provider;

  public Mono<Authentication> createAuthentication(String token) {
    try {
      DecodedJWT jwt = provider.decode(token);
      List<? extends  GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(
          jwt.getClaim(JwtTokenProvider.ROLES).asArray(String.class));
      String subject = jwt.getSubject();

      return Mono.just(new ApiTokenAuthentication(token, subject, authorities, jwt));

    } catch (JWTVerificationException exception) {
      return Mono.empty();
    }
  }
}
