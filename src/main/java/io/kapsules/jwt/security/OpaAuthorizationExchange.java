package io.kapsules.jwt.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;

/**
 * <h3>OpaAuthorizationExchange</h3>
 *
 * <p>Insert class description here...
 *
 * @author M. Massenzio, 2020-11-20
 */
@Slf4j
public class OpaAuthorizationExchange implements Customizer<AuthorizeExchangeSpec> {
  @Override
  public void customize(AuthorizeExchangeSpec spec) {
    log.debug("OpaAuthEx called with spec");
  }
}
