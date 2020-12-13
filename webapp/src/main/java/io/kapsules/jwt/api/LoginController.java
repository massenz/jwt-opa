package io.kapsules.jwt.api;

import io.kapsules.jwt.data.ReactiveUsersRepository;
import io.kapsules.jwt.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Base64Utils;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

import static io.kapsules.jwt.Constants.BASIC_AUTH;

/**
 * <h3>LoginController</h3>
 *
 * @author M. Massenzio, 2020-12-04
 */
@Slf4j
@RestController
@RequestMapping(
    path = "/login",
    produces = MimeTypeUtils.APPLICATION_JSON_VALUE,
    consumes = MimeTypeUtils.APPLICATION_JSON_VALUE)
public class LoginController {

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  ReactiveUsersRepository repository;

  @GetMapping
  Mono<JwtController.ApiToken> login(
      @RequestHeader("Authorization") String credentials
  ) {
    log.debug("Got credentials: {}", credentials);
    return fromCredentials(credentials)
        .flatMap(repository::findByUsername)
        .map(u -> {
          String token = provider.createToken(u.getUsername(), u.roles());
          return new JwtController.ApiToken(u.getUsername(), u.roles(), token);
        })
        .doOnSuccess(apiToken ->
            log.debug("User {} authenticated, API Token generated: {}",
                apiToken.getUsername(), apiToken.getApiToken()));
  }

  private Mono<String> fromCredentials(String credentials) {
    log.debug("Extracting username from Authorization credentials: {}", credentials);
    if (credentials.startsWith(BASIC_AUTH)) {
      return Mono.just(credentials.substring(BASIC_AUTH.length() + 1))
          .map(enc -> Base64Utils.decode(enc.getBytes(StandardCharsets.UTF_8)))
          .map(String::new)
          .map(creds -> creds.split(":")[0])
          .doOnSuccess(user -> log.debug("Found user: {}", user));
    }
    return Mono.error(new IllegalStateException("Invalid Authorization header"));
  }
}
