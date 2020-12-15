package io.kapsules.jwt.configuration;

import io.kapsules.jwt.security.OpaReactiveAuthorizationManager;
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
  public String authorizationEndpoint() {
    return opaServerProperties.authorization();
  }

  @Bean
  public WebClient client() {
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
