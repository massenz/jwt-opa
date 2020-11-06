package io.kapsules.jwt.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
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

  static class MyReactiveUserDetailsService implements ReactiveUserDetailsService {

    @Override
    public Mono<UserDetails> findByUsername(String username) {
      log.debug("Looking up user details for: {}", username);
      return Mono.just(
          User.withDefaultPasswordEncoder()
              .username(username)
              .password("password")
              .disabled(false)
              .roles("USER")
              .build()
      );
    }
  }

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    return http.authorizeExchange()
        .anyExchange().authenticated()
        .and().httpBasic()
        .and().build();
  }

  @Bean
  public ReactiveUserDetailsService userDetailsService() {
    log.info("Creating a ReactiveUserDetailsService bean");
    return new MyReactiveUserDetailsService();
  }
}
