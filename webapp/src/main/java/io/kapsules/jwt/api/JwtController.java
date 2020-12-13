package io.kapsules.jwt.api;

import com.auth0.jwt.JWTVerifier;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.kapsules.jwt.JwtTokenProvider;
import io.kapsules.jwt.KeyPair;
import io.kapsules.jwt.data.ReactiveUsersRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.List;
import java.util.Objects;

import static io.kapsules.jwt.security.JwtReactiveAuthorizationManager.BEARER_TOKEN;

@Slf4j
@RestController
public class JwtController {

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  ReactiveUsersRepository repository;

  @Autowired
  KeyPair keyPair;

  @Data
  @AllArgsConstructor
  static class ApiToken {
    String username;
    List<String> roles;
    @JsonProperty("api-token")
    String apiToken;
  }

  @GetMapping(path = "/token/{user}", produces = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<ApiToken>> getToken(@PathVariable String user) {
    log.debug("Refreshing API Token for `{}`", user);

    return repository.findByUsername(user)
        .map(u -> {
          String token = provider.createToken(u.getUsername(), u.roles());
          return new ApiToken(user, u.roles(), token);
        })
        .map(ResponseEntity::ok)
        .doOnSuccess(response -> log.debug("Returning API Token for user {}: {}", user,
            Objects.requireNonNull(response.getBody()).getApiToken()))
        .onErrorReturn(Exception.class, ResponseEntity.badRequest().build());
  }

  /**
   * Demo endpoint, accessible to all users, to authenticate themselves.
   *
   * @param user the user we wish to authenticate, MUST be the same as the one carried as a
   *             "subject" in the API Token
   * @return a simple 200 OK if the user is a valid user and the API Token matches
   */
  // TODO: create the Rego policy that verifies the user is authorized to access this API
  @GetMapping(path = "/auth/{user}", produces = MimeTypeUtils.TEXT_PLAIN_VALUE)
  public Mono<ResponseEntity<String>> authenticate(
      @PathVariable String user,
      @RequestHeader("Authorization") String apiToken
  ) {
    // Note that while we could conduct the authorization step here, by decoding the JWT (using
    // the JWTProvider) and comparing the "sub" field with the `user`, this is entirely
    // delegated, transparently, to the OPA Server, and the policies configured there.
    //
    // If Spring Security allowed us to get this far, we know we're good and can simply return a
    // 200 OK response.
    return Mono.just(ResponseEntity.ok(
        String.format("API Token [%s] is valid for user %s ",
            apiToken.substring(BEARER_TOKEN.length() + 1),
            user)));
  }

  /**
   * "Demo" endpoint only accessible to SYSTEM administrators.
   */
  // TODO: implement the Rego policy to only allow SYSTEM role to acces this API
  @GetMapping(path = "/keypair", produces = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<?>> getKeypair() {
    return Mono.just(ResponseEntity.ok(keyPair));
  }

  /**
   * Just a "demo" endpoint which is accessible exclusively by the SYSTEM role.
   *
   * <p>Updates the Key Pair used by the server; upon restart, the server however will pick up
   * again the configured files: the POSTed key material does not get persisted.</p>
   *
   * @param pair a JSON object that carries the key material, Base-64 encoded
   * @see KeyPair
   */
  // TODO: implement the Rego policy to only allow SYSTEM role to acces this API
  @PostMapping(path = "/keypair", produces = MimeTypeUtils.APPLICATION_JSON_VALUE,
      consumes = MimeTypeUtils.APPLICATION_JSON_VALUE)
  public Mono<ResponseEntity<?>> postKeypair(@RequestBody KeyPair pair) {
    log.warn("Updating Key material");
    // In a real-life application, we should verify here that the contents of the request body
    // match the expected format of a JSON KeyPair (see KeyPair#build()) and that these are a valid
    // private/public key pair.
    // Then again, in a real application, we would NEVER allow an API to upload key material.
    keyPair = pair;
    return Mono.just(ResponseEntity.created(URI.create("/keypair")).body(
        Collections.singletonMap("message", "KeyPair updated")
    ));
  }
}
