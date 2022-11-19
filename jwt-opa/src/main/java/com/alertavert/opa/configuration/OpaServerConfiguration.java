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

import com.alertavert.opa.security.OpaReactiveAuthorizationManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

/**
 * <h2>OpaServerConfiguration</h2>
 *
 * @author M. Massenzio, 2020-11-22
 */
@Configuration
@EnableConfigurationProperties(OpaServerProperties.class)
@Slf4j
public class OpaServerConfiguration {

  private final OpaServerProperties opaServerProperties;
  private final RoutesConfiguration configuration;

  public OpaServerConfiguration(
      OpaServerProperties opaServerProperties,
      RoutesConfiguration configuration) {
    this.opaServerProperties = opaServerProperties;
    this.configuration = configuration;
  }

  /**
   * Implementations will use this method to configure the client's endpoint, most likely derived
   * from configuration properties.
   *
   * @return the full URL of the OPA server API endpoint.
   */
  @Bean
  public String authorizationEndpoint() {
    return opaServerProperties.authorization();
  }

  @Bean
  public String policyEndpoint() {
    return opaServerProperties.policyEndpoint();
  }

  @Bean
  public WebClient client() {
    log.info("OPA Server base URL: {}", authorizationEndpoint());
    return WebClient.builder()
        .baseUrl(authorizationEndpoint())
        .defaultHeader("Accept", MediaType.APPLICATION_JSON_VALUE)
        .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
        .build();
  }

  @Bean
  public List<String> requiredHeaders() {
    return opaServerProperties.getHeaders();
  }

  @Bean
  public OpaReactiveAuthorizationManager authorizationManager() {
    return new OpaReactiveAuthorizationManager(client(), configuration,
        opaServerProperties.getHeaders());
  }
}
