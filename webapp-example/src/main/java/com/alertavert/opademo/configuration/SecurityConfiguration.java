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

package com.alertavert.opademo.configuration;

import com.alertavert.opademo.data.ReactiveUsersRepository;
import com.alertavert.opademo.data.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;

import static com.alertavert.opa.Constants.EMPTY_USERDETAILS;

/**
 * <h3>SecurityConfiguration</h3>
 *
 * @author M. Massenzio, 2020-09-27
 */
@Configuration
@EnableWebFluxSecurity
@Slf4j
public class SecurityConfiguration {


  @Bean
  public ReactiveUserDetailsService userDetailsService(ReactiveUsersRepository repository) {
    return username -> {
      log.debug("Retrieving user details for `{}`", username);
      return repository.findByUsername(username)
          .map(User::toUserDetails)
          .doOnSuccess(ud -> {
            if (ud != null) {
              log.debug("Found: {} [enabled={}]", ud.getUsername(), ud.isEnabled());
            } else {
              log.warn("No user {} found", username);
            }
          })
          // This is necessary to deal with the
          // "No provider found for class
          // org.springframework.security.authentication.UsernamePasswordAuthenticationToken"
          // error when simply returning an empty Mono, if the username does not exist.
          .defaultIfEmpty(EMPTY_USERDETAILS);
    };
  }
}
