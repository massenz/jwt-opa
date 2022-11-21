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
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;

import java.util.List;

import static com.alertavert.opa.Constants.EMPTY_USERDETAILS;

/**
 * <h2>SecurityConfiguration</h2>
 *
 * @author M. Massenzio, 2020-09-27
 */
@Configuration
@EnableWebFluxSecurity
@Slf4j
@EnableConfigurationProperties(
    {SecurityConfiguration.CorsProperties.class,
        SecurityConfiguration.KeyProperties.class})
public class SecurityConfiguration {

  /** CORS Configuration allows all routes ("*") */
  public static final String DEFAULT_ALL_ALLOWED = "*";

  private final CorsProperties properties;

  public SecurityConfiguration(CorsProperties properties) {
    this.properties = properties;
  }

  @Data
  @ConfigurationProperties(prefix = "cors")
  public static class CorsProperties {
    List<String> allowed = List.of(DEFAULT_ALL_ALLOWED);
    List<String> methods = List.of(DEFAULT_ALL_ALLOWED);
    List<String> headers = List.of(DEFAULT_ALL_ALLOWED);
  }

  @Data
  @ConfigurationProperties(prefix = "keys")
  public static class KeyProperties {
    String algorithm;
    String priv;
    String pub;
  }


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

  /**
   * An example as to how to configure CORS for a web app using jwt-opa.
   *
   * @return a CORS Configuration which will respect all the allowed origins; by default this
   *    bean allows all origins/methods/headers.
   */
  @Bean
  public CorsConfigurationSource corsConfiguration() {
    log.debug("CORS Configuration");
    return exchange -> {
      log.debug("Allowing Origins: {}", properties.allowed);
      CorsConfiguration conf = new CorsConfiguration();
      conf.setAllowedOriginPatterns(properties.allowed);
      conf.setAllowedMethods(properties.methods);
      conf.setAllowedHeaders(properties.headers);
      return conf;
    };
  }
}
