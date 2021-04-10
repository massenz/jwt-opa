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

package com.alertavert.opa.security;

import com.alertavert.opa.JwtTokenProvider;
import com.alertavert.opa.configuration.RoutesConfiguration;
import com.alertavert.opa.configuration.JwtSecurityConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.stereotype.Component;

/**
 * <h3>OpaAuthorizationExchange</h3>
 *
 * <p>Opinionated authorization configuration class, defines a set of API endpoints and their
 * authentication/authorization policies.
 *
 * <p>Essentially, it configures a set of unauthenticated endpoint (such as {@literal /health});
 * those which are authenticated using the Spring Security
 * {@link org.springframework.security.core.userdetails.UserDetails UserDetails} mechanism
 * (e.g., a {@literal /login} endpoint to obtain a {@link com.auth0.jwt.JWT} Token);
 * and everything else that uses OPA to authorize access (the API Token is validated by the
 * {@link JwtTokenProvider} and provides the authentication part).
 *
 * <p>{@literal TODO} this may need revisiting, finding ways for applications using this library
 * to configure their own authentication/authorization policies per endpoint.
 *
 * @see JwtSecurityConfiguration
 * @author M. Massenzio, 2020-11-20
 */
@Component
@Slf4j
public class CustomAuthorizationExchange implements Customizer<AuthorizeExchangeSpec> {

  private final RoutesConfiguration configuration;
  private final JwtReactiveAuthorizationManager authorizationManager;

  public CustomAuthorizationExchange(
      RoutesConfiguration configuration,
      JwtReactiveAuthorizationManager authorizationManager
  ) {
    this.configuration = configuration;
    this.authorizationManager = authorizationManager;
  }

  @Override
  public void customize(AuthorizeExchangeSpec spec) {
    log.debug("Configuring Application Authorization using API Tokens (JWT)");
    spec
        // Allowed endpoints, which need to have unauthenticated access (such as heartbeat, and
        // other management ones).
        .pathMatchers(configuration.getProperties().getAllowed().toArray(String[]::new))
        .permitAll()

        // Endpoints which are accessible *without* an API Token, used to generate one, once
        // the user authenticates with username/password.
        .pathMatchers(configuration.getProperties().getAuthenticated().toArray(String[]::new))
        .authenticated()

        .and()
        .authorizeExchange()

        // Everything else is handled by validating the API Token and then passing it on to the
        // OPA Server for the authorization.
        .pathMatchers("/**")
        .access(authorizationManager);
  }
}
