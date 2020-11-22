package io.kapsules.jwt.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.stereotype.Component;

/**
 * <h3>OpaAuthorizationExchange</h3>
 *
 * @author M. Massenzio, 2020-11-20
 */
@Component
@Slf4j
public class OpaAuthorizationExchange implements Customizer<AuthorizeExchangeSpec> {

  @Autowired
  OpaReactiveAuthorizationManager opaAccessManager;

  @Override
  public void customize(AuthorizeExchangeSpec spec) {
    log.debug("Configuring Application Authorization via the OPA Server");
    spec.anyExchange().access(opaAccessManager);
  }
}
