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

import io.kapsules.jwt.security.OpaReactiveAuthorizationManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * <h3>OpaServerConfiguration</h3>
 *
 * @author M. Massenzio, 2020-11-22
 */
@Configuration
@EnableConfigurationProperties(OpaServerProperties.class)
@Slf4j
public class OpaServerConfiguration {

  private final OpaServerProperties opaServerProperties;

  public OpaServerConfiguration(OpaServerProperties opaServerProperties) {
    this.opaServerProperties = opaServerProperties;
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
  public OpaReactiveAuthorizationManager authorizationManager(WebClient client) {
    return new OpaReactiveAuthorizationManager(client);
  }
}
