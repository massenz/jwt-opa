package io.kapsules.jwt.configuration;

import io.kapsules.jwt.data.ReactiveUsersRepository;
import io.kapsules.jwt.data.User;
import io.kapsules.jwt.security.CustomAuthorizationExchange;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
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

  @Bean
  public ReactiveUserDetailsService userDetailsService(ReactiveUsersRepository repository) {
    log.debug("Getting ReactiveUserDetailsService");
    return new ReactiveUserDetailsService() {
      @Override
      public Mono<UserDetails> findByUsername(String username) {
        log.debug("Authenticating {}", username);
        return repository.findByUsername(username)
            .map(User::toUserDetails);
      }
    };
  }
}
