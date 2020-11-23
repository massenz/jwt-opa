package io.kapsules.jwt.configuration;

import io.kapsules.jwt.security.OpaReactiveAuthorizationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * <h3>OpaServerConfiguration</h3>
 *
 * <p>Insert class description here...
 *
 * @author M. Massenzio, 2020-11-22
 */
@Configuration
public class OpaServerConfiguration {

  @Autowired
  OpaServerProperties opaProperties;

  @Bean
  public WebClient.Builder clientBuilder() {
    return WebClient.builder();
  }

  @Bean
  OpaReactiveAuthorizationManager authorizationManager() {
    return new OpaReactiveAuthorizationManager(clientBuilder(), opaProperties.endpoint());
  }
}
