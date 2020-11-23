package io.kapsules.jwt.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Objects;

/**
 * <h3>OpaReactiveAuthorizationManager</h3>
 *
 * <p>We execute the authorization request against an OPA server, which is reachable via the
 * {@link #apiEndpoint}, using the
 * <a href="https://www.openpolicyagent.org/docs/latest/rest-api/#data-api">Data REST API</a>.
 *
 * <p>In this example implementation, we simply validate the user/roles contained in the JWT
 * against the API endpoint and method that are in the request; however, via the
 * {@link ServerHttpRequest request} object we would have access to the entire request
 * attributes, headers, etc. and those could be packaged into the JSON
 * {@link TokenBasedAuthorizationRequestBody body} of the request POSTed to the OPA server.
 *
 * @author M. Massenzio, 2020-11-22
 */
@Slf4j
@RequiredArgsConstructor
public class OpaReactiveAuthorizationManager implements ReactiveAuthorizationManager<ServerHttpRequest> {

  private final WebClient.Builder clientBuilder;
  private final String apiEndpoint;

  /**
   * Determines if access is granted for a specific authentication and request.
   *
   * @param authentication  an {@link ApiTokenAuthentication} object, contains the JWT in the
   *                        {@literal credentials} attribute; `authenticated` will be {@literal true}
   *                        if the JWT has been validated
   * @param request         the API endpoint and method (amongst other attributes) which we are
   *                        authorizing access to (or denying, depending on the OPA Policy
   *                        validation)
   * @return a decision or empty Mono if no decision could be made.
   * @see ApiTokenAuthentication
   * @see JwtTokenProvider
   */
  @Override
  public Mono<AuthorizationDecision> check(Mono<Authentication> authentication,
                                           ServerHttpRequest request) {

    return authentication.flatMap(
            auth -> {
              // We expect to receive a valid API Token (JWT) as the user's credentials.
              if (!auth.isAuthenticated()) {
                throw new IllegalStateException("Credentials have not been authenticated");
              }
              TokenBasedAuthorizationRequestBody.RequestBody body =
                  makeRequestBody(auth.getCredentials().toString(), request);
              // TODO: it would be probably beneficial here to emit the full JSON instead.
              log.debug("OPA Authorization request with {}", body);
              return clientBuilder.build().post()
                  .uri(apiEndpoint)
                  .accept(MediaType.APPLICATION_JSON)
                  .contentType(MediaType.APPLICATION_JSON)
                  .bodyValue(body)
                  .exchange();
            }
        )
        .flatMap(response -> {
          return response.bodyToMono(Map.class)
              .map(res -> res.get("result").toString())
              .map(Boolean::parseBoolean)
              .map(AuthorizationDecision::new);
        });
  }

  private TokenBasedAuthorizationRequestBody.RequestBody makeRequestBody(String token, ServerHttpRequest request) {
    return TokenBasedAuthorizationRequestBody.build(token, request.getPath().toString(),
        Objects.requireNonNull(request.getMethod()).toString());
  }
}