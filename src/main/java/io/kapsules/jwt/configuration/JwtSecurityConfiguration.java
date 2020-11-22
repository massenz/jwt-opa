package io.kapsules.jwt.configuration;

import io.kapsules.jwt.security.OpaAuthorizationExchange;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * <h3>JwtSecurityConfiguration</h3>
 *
 * <p>Insert class description here...
 *
 * @author M. Massenzio, 2020-09-27
 */
@Configuration
@EnableWebFluxSecurity
@Slf4j
public class JwtSecurityConfiguration {

  @Autowired
  OpaAuthorizationExchange authorizationExchange;

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    // OPA Authorization will be done inside the authorizeExchange "custom authorization" logic
    return http.authorizeExchange(authorizationExchange).build();
  }
}
