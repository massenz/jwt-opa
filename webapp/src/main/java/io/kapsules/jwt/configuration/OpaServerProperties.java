package io.kapsules.jwt.configuration;

import io.kapsules.jwt.Constants;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * <h3>OpaServerProperties</h3>
 *
 * <p>Insert class description here...
 *
 * @author M. Massenzio, 2020-11-22
 */
@Data
@Component
@ConfigurationProperties(prefix = "opa")
public class OpaServerProperties {

  String server;
  String policy;
  String rule;

  public String endpoint() {
    return server + Constants.OPA_DATA_API + policy + "/" + rule;
  }
}
