/*
 * Copyright (c) 2021 AlertAvert.com.  All rights reserved.
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
 *
 * Author: Marco Massenzio (marco@alertavert.com)
 */

package com.alertavert.opa.security;

import com.alertavert.opa.Constants;
import com.alertavert.opa.configuration.OpaServerProperties;
import com.alertavert.opa.configuration.RoutesConfiguration;
import com.alertavert.opa.jwt.ApiTokenAuthentication;
import com.alertavert.opa.jwt.JwtTokenProvider;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.alertavert.opa.Constants.CANNOT_PARSE_AUTHORIZATION_REQUEST;
import static com.alertavert.opa.Constants.UNEXPECTED_AUTHENTICATION_CLASS;
import static com.alertavert.opa.Constants.USER_NOT_AUTHORIZED;

/**
 * <h2>OpaReactiveAuthorizationManager</h2>
 *
 * <p>We execute the authorization request against an OPA server, which is reachable via the
 * {@link OpaServerProperties#authorization() authorization endpoint}, using the
 * <a href="https://www.openpolicyagent.org/docs/latest/rest-api/#data-api">Data REST API</a>.
 *
 * <p>In this example implementation, we simply validate the user/roles contained in the JWT
 * against the API endpoint and method that are in the request; however, via the {@link
 * ServerHttpRequest request} object we would have access to the entire request attributes, headers,
 * etc. and those could be packaged into the JSON {@link TokenBasedAuthorizationRequestBody body} of
 * the request POSTed to the OPA server.
 *
 * @author M. Massenzio, 2020-11-22
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class OpaReactiveAuthorizationManager
    implements ReactiveAuthorizationManager<AuthorizationContext> {

  private final WebClient client;
  private final RoutesConfiguration configuration;
  private final ObjectMapper mapper = new ObjectMapper();
  private final AntPathMatcher pathMatcher = new AntPathMatcher();

  /**
   * Determines if access is granted for a specific request, given a user's credentials (API
   * token).
   *
   * @param authentication an {@link ApiTokenAuthentication} object, contains the JWT in the
   *                       {@literal credentials} attribute; `authenticated` will be {@literal true}
   *                       if the JWT has been validated
   * @param context        the {@link AuthorizationContext context} for the authorization decision,
   *                       we will use it to extract the HTTP request, which will be sent to the OPA
   *                       server (alongside the user's {@link ApiTokenAuthentication credentials},
   *                       i.e., the JWT) for the authorization policies to be evaluated.
   * @return a decision or empty Mono if no decision could be made.
   * @see ApiTokenAuthentication
   * @see JwtTokenProvider
   */
  @Override
  public Mono<AuthorizationDecision> check(
      Mono<Authentication> authentication,
      AuthorizationContext context
  ) {
    final List<String> authRoutes = configuration.getProperties().getAuthenticated();
    ServerHttpRequest request = context.getExchange().getRequest();
    log.debug("Authorizing access: method = `{}`, path = `{}`",
        request.getMethod(), request.getPath());

    String path = request.getPath().toString();
    for (String pattern : authRoutes) {
      if (pathMatcher.match(pattern, path)) {
        log.debug("Route is allowed to bypass authorization");
        return Mono.just(new AuthorizationDecision(true));
      }
    }

    return authentication
        .flatMap(auth -> {
          log.debug("Authorizing user = `{}`", auth.getPrincipal());
          // If authentication failed, there is no point in even trying to authorize the request.
          if (!auth.isAuthenticated() || !(auth instanceof ApiTokenAuthentication)) {
            log.debug(UNEXPECTED_AUTHENTICATION_CLASS, auth.getClass().getSimpleName());
            return Mono.empty();
          }
          return Mono.just(makeRequestBody(auth.getCredentials(), request));
        })
        .doOnNext(body -> {
            log.debug("POST Authorization request:\n{}", body.prettyPrint());
        })
        .flatMap(body -> client.post()
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(body)
            .exchange())
        .flatMap(response -> response.bodyToMono(Map.class))
        .map(res -> {
          log.debug("OPA Server returned: {}", res);
          Object result = res.get("result");
          boolean authorized = false;
          if (!StringUtils.isEmpty(result)) {
            authorized = Boolean.parseBoolean(result.toString());
          }
          return new AuthorizationDecision(authorized);
        });
  }

  private TokenBasedAuthorizationRequestBody.RequestBody makeRequestBody(
      Object credentials,
      ServerHttpRequest request
  ) {
    Objects.requireNonNull(credentials);
    String token = credentials.toString();
    return TokenBasedAuthorizationRequestBody.build(token, request.getPath().toString(),
        Objects.requireNonNull(request.getMethod()).toString());
  }

  private WebClientResponseException unauthorized() {
    return WebClientResponseException.create(
        HttpStatus.UNAUTHORIZED.value(),
        HttpStatus.UNAUTHORIZED.getReasonPhrase(),
        null,
        USER_NOT_AUTHORIZED.getBytes(StandardCharsets.UTF_8),
        StandardCharsets.UTF_8
    );
  }
}
