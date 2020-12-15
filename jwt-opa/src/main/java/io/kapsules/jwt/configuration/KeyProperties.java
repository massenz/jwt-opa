package io.kapsules.jwt.configuration;

import lombok.Data;
import lombok.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * <h3>KeyPropertiers</h3>
 *
 * @author M. Massenzio, 2020-12-14
 */
@Data
@ConfigurationProperties(prefix = "secrets")
public class KeyProperties {

  @Data
  public static class Pair {
    String priv;
    String pub;
  }

  private String algorithm;
  private String issuer;
  private Pair keypair;
  private String secret;
}
