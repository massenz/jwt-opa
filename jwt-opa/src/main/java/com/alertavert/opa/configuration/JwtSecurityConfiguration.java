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

package com.alertavert.opa.configuration;

import com.alertavert.opa.jwt.JwtAuthenticationWebFilter;
import com.alertavert.opa.security.OpaReactiveAuthorizationManager;
import com.alertavert.opa.security.PasswordAuthenticationManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * <h2>JwtSecurityConfiguration</h2>
 *
 * @author M. Massenzio, 2020-09-27
 */
@Configuration @Slf4j
@EnableWebFluxSecurity
public class JwtSecurityConfiguration {

  // TODO: use constructor arguments & final private fields instead of auto-wiring.
  @Autowired
  PasswordAuthenticationManager authenticationManager;

  @Autowired
  RoutesConfiguration configuration;

  @Autowired
  OpaReactiveAuthorizationManager authorizationManager;

  @Autowired
  JwtAuthenticationWebFilter jwtAuthenticationWebFilter;


  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

    log.debug("Setting up Security Web Filter Chain");
    log.debug("Password Authentication uses {}", authenticationManager.getClass().getName());

    return http
        // TODO: This is INSECURE, but makes testing using Postman easier
        // See: https://stackoverflow.com/questions/27182701/how-do-i-send-spring-csrf-token-from-postman-rest-client
        .csrf().disable()

        .addFilterAfter(jwtAuthenticationWebFilter, SecurityWebFiltersOrder.HTTP_BASIC)
        .authorizeExchange(authorizeExchangeSpec -> {
          authorizeExchangeSpec.pathMatchers("/**").access(authorizationManager);
        })

        .authenticationManager(authenticationManager)
        .httpBasic()
        .and()

        .authorizeExchange()
        .pathMatchers(configuration.getProperties().getAllowed().toArray(String[]::new))
        .permitAll()
        .anyExchange()
        .authenticated()
        .and()

        .build();
  }
}
