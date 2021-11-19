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

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


/**
 * <h3>PasswordAuthenticationManager</h3>
 *
 * <p>This class authenticates the user against the stored password in the database (hashed using
 * {@literal bcrypt}); it uses the {@link ReactiveUserDetailsService reactive repository} to
 * retrieve the {@link org.springframework.security.core.userdetails.UserDetails user details}
 * and validate them against the {@literal HTTP Basic} authorization header.
 *
 * @see ReactiveUserDetailsService
 * @see ReactiveAuthenticationManager
 *
 * @author M. Massenzio, 2020-11-21
 */
@Component
@Slf4j
public class PasswordAuthenticationManager implements
    ReactiveAuthenticationManager {

  private final ReactiveUserDetailsService userDetailsService;
  private final PasswordEncoder passwordEncoder;

  public PasswordAuthenticationManager(ReactiveUserDetailsService userDetailsService,
                                       PasswordEncoder passwordEncoder) {
    this.userDetailsService = userDetailsService;
    this.passwordEncoder = passwordEncoder;

    log.debug("Password Authentication Manager (basic auth) instantiated - Using password "
            + "encoder: {}", passwordEncoder.getClass().getName());
  }

  @Override
  public Mono<Authentication> authenticate(Authentication authentication) {
    String username = authentication.getPrincipal().toString();
    String password = authentication.getCredentials().toString();

    log.debug("Authenticating principal: {}", username);
    return userDetailsService.findByUsername(username)
        .flatMap(userDetails -> {
          if (passwordEncoder.matches(password, userDetails.getPassword())) {
            log.debug("`{}` principal authenticated", username);
            // Removing credentials here, so that they don't get passed around unnecessarily.
            // TODO: should we insert a freshly-minted API Token here?
            return Mono.just(new UsernamePasswordAuthenticationToken(username, null,
                userDetails.getAuthorities()));
          }
          log.warn("Invalid credentials for {}", username);
          return Mono.error(new BadCredentialsException("bad credentials"));
        });
  }
}
