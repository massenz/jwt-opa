package io.kapsules.jwt.configuration;

import io.kapsules.jwt.security.OpaReactiveAuthorizationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * <h3>OpaServerConfiguration</h3>
 *
 * @author M. Massenzio, 2020-11-22
 */
@Configuration
@EnableWebFluxSecurity
public abstract class OpaServerConfiguration {

  /**
   * Implementations will use this method to configure the client's endpoint, most likely derived
   * from configuration properties.
   *
   * @return the full URL of the OPA server API endpoint.
   */
  protected abstract String endpoint();

  @Bean
  public WebClient client() {
    return WebClient.builder()
        .baseUrl(endpoint())
        .defaultHeader("Accept", MediaType.APPLICATION_JSON_VALUE)
        .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
        .build();
  }


  @Bean
  OpaReactiveAuthorizationManager authorizationManager(WebClient client) {
    return new OpaReactiveAuthorizationManager(client);
  }
}
