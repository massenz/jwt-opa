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
public class PolicyServerConfiguration extends OpaServerConfiguration {

  @Autowired
  OpaServerProperties opaProperties;

  @Override
  protected String endpoint() {
    return opaProperties.endpoint();
  }
}
