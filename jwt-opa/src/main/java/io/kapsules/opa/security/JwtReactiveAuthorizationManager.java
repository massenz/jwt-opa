/*
 * Copyright (c) 2021 kapsules.io.  All rights reserved.
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

package io.kapsules.opa.security;

import io.kapsules.opa.ApiTokenAuthenticationFactory;
import io.kapsules.opa.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import static io.kapsules.opa.Constants.BEARER_TOKEN;
import static io.kapsules.opa.Constants.TOKEN_MISSING_OR_INVALID;
import static io.kapsules.opa.Constants.UNEXPECTED_AUTHENTICATION_OBJECT;


/**
 * <h3>OpaReactiveAuthorizationManager</h3>
 *
 * <p>This class runs the authorization of the user against the request: it first checks for an
 * Authorization header with a Bearer token; if the API Token (a JWT) is valid (i.e., the signature
 * verifies against the secret key) the request context, along with the retrieved user details, are
 * passed on to an OPA server for validation against the stored policies.
 *
 * @author M. Massenzio, 2020-11-21
 */
@Component
@Slf4j
public class JwtReactiveAuthorizationManager implements
    ReactiveAuthorizationManager<AuthorizationContext> {

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  OpaReactiveAuthorizationManager authorizationManager;

  @Autowired
  ApiTokenAuthenticationFactory factory;

  private Mono<String> resolveToken(ServerHttpRequest request) {
    String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_TOKEN)) {
      return Mono.just(bearerToken.substring(BEARER_TOKEN.length() + 1));
    }
    log.warn(TOKEN_MISSING_OR_INVALID);
    return Mono.empty();
  }

  /**
   * This validates a signed JWT against the application's secret, without making any assertion
   * about the user and/or the roles carried by the token; in other words, the only question this
   * answers (delegating it to the {@link JwtTokenProvider}) is: "Do we recognize this API Token,
   * and by extension, its contents, as one we emitted previously."
   *
   * @param request the request, inside whose Authorization header the API token is carried
   *                ({@literal Bearer} token)
   * @return a non-empty Mono if the token is validated, with the API token inside
   */
  private Mono<String> validate(ServerHttpRequest request) {
    return resolveToken(request)
        .flatMap(token -> {
          log.debug("Validating token [{}] from Authorization Header", token);
          if (StringUtils.hasText(token) && provider.validateToken(token)) {
            log.debug("Found valid API Token");
            return Mono.just(token);
          }
          log.warn(TOKEN_MISSING_OR_INVALID);
          return Mono.empty();
        });
  }

  /**
   * Determines if access is granted for a specific authentication and object.
   *
   * @param authentication the Authentication to check
   * @param context        the object to check
   * @return a decision or empty Mono if no decision could be made.
   */
  @Override
  public Mono<AuthorizationDecision> check(Mono<Authentication> authentication,
                                           AuthorizationContext context) {
    ServerHttpRequest request = context.getExchange().getRequest();
    log.debug("Authorizing access to `{}`", request.getPath());

    // We expect the `authentication` Mono to always be empty, as Spring does not authenticate
    // the user in this configuration.
    return authentication
        .hasElement()
        .flatMap(b -> b ?
            Mono.error(new IllegalStateException(UNEXPECTED_AUTHENTICATION_OBJECT)) :
            validate(request)
                .flatMap(token ->
                    authorizationManager.check(
                        Mono.just(factory.createAuthentication(token)), request))
                .doOnSuccess(decision -> {
                  if (decision != null) {
                    log.debug("Access was {}granted", decision.isGranted() ? "" : "not ");
                  } else {
                    log.warn(TOKEN_MISSING_OR_INVALID);
                  }
                })
        );
  }
}
