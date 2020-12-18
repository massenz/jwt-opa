/*
 * Copyright (c) 2020 kapsules.io.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.kapsules.jwt.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kapsules.jwt.ApiTokenAuthentication;
import io.kapsules.jwt.JwtTokenProvider;
import io.kapsules.jwt.configuration.OpaServerProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;

/**
 * <h3>OpaReactiveAuthorizationManager</h3>
 *
 * <p>We execute the authorization request against an OPA server, which is reachable via the
 * {@link OpaServerProperties#authorization() authorization endpoint}, using the
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
@Component
@Slf4j
@RequiredArgsConstructor
public class OpaReactiveAuthorizationManager implements ReactiveAuthorizationManager<ServerHttpRequest> {

  private final WebClient client;

  private final ObjectMapper mapper = new ObjectMapper();

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
              try {
                log.debug("POSTing OPA Authorization request: {}",
                    mapper.writeValueAsString(body));
              } catch (JsonProcessingException e) {
                e.printStackTrace();
              }
              return client.post()
                  .accept(MediaType.APPLICATION_JSON)
                  .contentType(MediaType.APPLICATION_JSON)
                  .bodyValue(body)
                  .exchange();
            }
        )
        .flatMap(response -> response.bodyToMono(Map.class)
            .map(res -> {
              log.debug("OPA Server returned: {}", res);
              Object result = res.get("result");
              if (StringUtils.isEmpty(result)) {
                return Mono.error(unauthorized());
              }
              return result.toString();
            })
            .map(o -> Boolean.parseBoolean(o.toString()))
            .map(AuthorizationDecision::new));
  }

  private TokenBasedAuthorizationRequestBody.RequestBody makeRequestBody(
      String token,
      ServerHttpRequest request
  ) {
    return TokenBasedAuthorizationRequestBody.build(token, request.getPath().toString(),
        Objects.requireNonNull(request.getMethod()).toString());
  }

  private WebClientResponseException unauthorized() {
    return WebClientResponseException.create(
        HttpStatus.UNAUTHORIZED.value(),
        "OPA Server did not return a valid result",
        null,
        null,
        StandardCharsets.UTF_8
    );
  }
}
