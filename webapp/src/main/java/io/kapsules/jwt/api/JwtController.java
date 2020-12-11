package io.kapsules.jwt.api;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.kapsules.jwt.KeyPair;
import io.kapsules.jwt.JwtTokenProvider;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Objects;

@Slf4j
@RestController
public class JwtController {


  @Autowired
  JWTVerifier verifier;

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  PrivateKey privateKey;

  @Autowired
  PublicKey publicKey;

  @Data
  @AllArgsConstructor
  static class ApiToken {
    String username;
    String role;
    @JsonProperty("api-token")
    String apiToken;
  }


  // TODO: change this endpoint to `/login` with the `username` being carried in the Authorization
  //  header; the `role` is extracted from the User DB.
  @GetMapping(path = "/token/{user}", produces = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<ApiToken>> getToken(
      @PathVariable String user,
      @RequestParam(required = true, name = "role") final String role
  ) {
    if (StringUtils.isEmpty(role)) {
      log.error("Missing role when requesting API Token for {}", user);
      return Mono.error(
          new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing Role"));
    }
    log.debug("Creating API Token for `{}` with role [{}]", user, role);
    return Mono.just(provider.createToken(user, role))
        .map(jwt -> new ApiToken(user, role, jwt))
        .map(ResponseEntity::ok)
        .doOnSuccess(response -> log.debug("Returning API Token for user {}: {}", user,
            Objects.requireNonNull(response.getBody()).getApiToken()))
        .onErrorReturn(Exception.class, ResponseEntity.badRequest().build());
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
