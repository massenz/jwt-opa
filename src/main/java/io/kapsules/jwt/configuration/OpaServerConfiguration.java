package io.kapsules.jwt.configuration;

import io.kapsules.jwt.security.OpaReactiveAuthorizationManager;
import org.springframework.beans.factory.annotation.Autowired;
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
public class OpaServerConfiguration {

  @Autowired
  OpaServerProperties opaProperties;

  @Bean
  public WebClient client() {
    return WebClient.builder()
        .baseUrl(opaProperties.endpoint())
        .defaultHeader("Accept", MediaType.APPLICATION_JSON_VALUE)
        .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
        .build();
  }

  @Bean
  OpaReactiveAuthorizationManager authorizationManager() {
    return new OpaReactiveAuthorizationManager(client());
  }
}
