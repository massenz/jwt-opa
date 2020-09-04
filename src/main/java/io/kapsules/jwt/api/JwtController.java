package io.kapsules.jwt.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.kapsules.jwt.KeyPair;
import io.kapsules.jwt.configuration.VaultConfiguration;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;

@Slf4j
@RestController
public class JwtController {

  @Autowired
  Algorithm hmac;

  @Autowired
  JWTVerifier verifier;

  @Autowired
  PrivateKey privateKey;

  @Autowired
  PublicKey publicKey;

  @Data
  @AllArgsConstructor
  static class ApiToken {
    String username;
    @JsonProperty("api-token")
    String apiToken;
  }


  @GetMapping(path = "/token/{user}", produces = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<ApiToken>> getToken(@PathVariable String user) {
    return Mono.just(
        JWT.create()
            .withIssuer(VaultConfiguration.ISSUER)
            .withSubject(user)
            .sign(hmac)
        )
        .map(jwt -> new ApiToken(user, jwt))
        .map(ResponseEntity::ok)
        .doOnSuccess(x -> log.debug("Creating API Token for user {}", user));
  }

  @GetMapping(path = "/auth/{user}", produces = MimeTypeUtils.APPLICATION_JSON_VALUE,
      consumes = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<?>> authenticate(
      @RequestHeader("Authorization") String apiToken,
      @PathVariable String user
  ) {
    return Mono.just(apiToken)
        .map(verifier::verify)
        .map(jwt -> {
          if (user.equals(jwt.getSubject())) {
            log.debug("Authenticating user with API Token for {}", jwt.getSubject());
            return ResponseEntity.ok(
                Collections.singletonMap("authenticated", true)
            );
          }
          log.warn("User {} cannot be authenticated [{}]", user, jwt.getSubject());
          return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

        })
        .doOnError(e -> log.error("Could not verify API Token: {}", e.getMessage()))
        .onErrorResume(ex -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
  }

  @GetMapping(path = "/keypair", produces = MimeTypeUtils.APPLICATION_JSON_VALUE,
      consumes = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<?>> getKeypair(
      @RequestHeader("Authorization") String apiToken
  ) {
    return Mono.just(apiToken)
        .map(verifier::verify)
        .map(jwt -> {
          if ("admin".equals(jwt.getSubject())) {
            log.debug("Authenticating user with API Token for {}", jwt.getSubject());
            return ResponseEntity.ok(KeyPair.build(privateKey, publicKey));
          }
          log.warn("User {} is not an Admin user", jwt.getSubject());
          return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        })
        .doOnError(e -> log.error("An error ({}) occurred: {}",
            e.getClass().getSimpleName(), e.getMessage()))
        .onErrorResume(ex -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
  }

  @PostMapping(path = "/keypair", produces = MimeTypeUtils.APPLICATION_JSON_VALUE,
      consumes = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<?>> postKeypair(
      @RequestHeader("Authorization") String apiToken,
      @RequestBody KeyPair pair
  ) {
    return Mono.just(apiToken)
        .map(verifier::verify)
        .map(jwt -> {
          if ("admin".equals(jwt.getSubject())) {
            log.debug("Updating Key material from user {}", jwt.getSubject());
            privateKey = pair.getPrivateKey();
            publicKey = pair.getPublicKey();
            return ResponseEntity.created(URI.create("/pair")).body(
                Collections.singletonMap("message", "KeyPair updated")
            );
          }
          log.warn("User {} is not an Admin user", jwt.getSubject());
          return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        })
        .doOnError(e -> log.error("An error ({}) occurred: {}",
            e.getClass().getSimpleName(), e.getMessage()))
        .onErrorResume(JWTVerificationException.class,
            ex -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()))
        .onErrorResume(ex -> Mono.just(ResponseEntity.badRequest().body(
            Collections.singletonMap("message", ex.getMessage())
        )));
  }
}
