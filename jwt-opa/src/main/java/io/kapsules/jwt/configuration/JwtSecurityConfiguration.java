package io.kapsules.jwt.configuration;

import io.kapsules.jwt.security.CustomAuthorizationExchange;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * <h3>JwtSecurityConfiguration</h3>
 *
 * @author M. Massenzio, 2020-09-27
 */
@Configuration
public class JwtSecurityConfiguration {

  @Autowired
  CustomAuthorizationExchange authorizationExchange;

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    // OPA Authorization will be done inside the authorizeExchange "custom authorization" logic
    return http
        // TODO: This is INSECURE, but makes testing using Postman easier
        // See: https://stackoverflow.com/questions/27182701/how-do-i-send-spring-csrf-token-from-postman-rest-client
        .csrf().disable()
        .httpBasic()
      .and()
        .authorizeExchange(authorizationExchange).build();
  }
}
