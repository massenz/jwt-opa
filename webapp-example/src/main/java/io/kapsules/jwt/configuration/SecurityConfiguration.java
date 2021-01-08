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

package io.kapsules.jwt.configuration;

import io.kapsules.jwt.data.ReactiveUsersRepository;
import io.kapsules.jwt.data.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;

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
            }
          });
    };
  }
}
