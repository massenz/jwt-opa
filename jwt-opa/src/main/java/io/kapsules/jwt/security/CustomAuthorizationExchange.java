package io.kapsules.jwt.security;

import io.kapsules.jwt.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.stereotype.Component;

/**
 * <h3>OpaAuthorizationExchange</h3>
 *
 * <p>Opinionated authorization configuration class, defines a set of API endpoints and their
 * authentication/authorization policies.
 *
 * <p>Essentially, it provides a heartbeat unauthenticated endpoint ({@literal /health}) a single
 * (authenticated) {@literal /login} endpoint to obtain an API Token ({@link com.auth0.jwt.JWT})
 * and everything else uses OPA to authorize access (the API Token is validated by the
 * {@link JwtTokenProvider verifies} and provides the authentication phase).
 *
 * <p>{@literal TODO} this may need revisiting, finding ways for applications using this library
 * to configure their own authentication/authorization policies per endpoint.
 *
 * @see io.kapsules.jwt.configuration.JwtSecurityConfiguration
 * @author M. Massenzio, 2020-11-20
 */
@Component
@Slf4j
public class CustomAuthorizationExchange implements Customizer<AuthorizeExchangeSpec> {

  @Autowired
  JwtReactiveAuthorizationManager authorizationManager;

  @Override
  public void customize(AuthorizeExchangeSpec spec) {
    log.debug("Configuring Application Authorization using API Tokens (JWT)");
    spec
        // Heartbeat endpoint, needs to have unauthenticated access.
        .pathMatchers("/health")
        .permitAll()

        // Only endpoint which is accessible *without* an API Token, used to generate one, once
        // the user authenticates with username/password.
        .pathMatchers("/login")
        .authenticated()

        .and()
        .authorizeExchange()

        // Everything else is handled by validating the API Token and then passing it on to the
        // OPA Server for the authorization.
        .pathMatchers("/**")
        .access(authorizationManager);
  }
}
