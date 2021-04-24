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

package com.alertavert.opa.jwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.WebFilterChainServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.security.Principal;

/**
 * <h3>JwtAuthenticationWebFilter</h3>
 *
 * <p>This is a Spring Security filter that authenticates the request using API Tokens carried in
 * the {@literal Authorization} header using a
 * ({@link com.alertavert.opa.Constants#BEARER_TOKEN Bearer} token).
 *
 * @author M. Massenzio, 2021-04-15
 */
@Slf4j
@Component
public class JwtAuthenticationWebFilter implements WebFilter {

  private final ServerAuthenticationSuccessHandler authenticationSuccessHandler =
      new WebFilterChainServerAuthenticationSuccessHandler();
  private final TokenAuthenticationFailureHandler failureHandler =
      new TokenAuthenticationFailureHandler();
  private final ServerTokenAuthenticationConverter authenticationConverter;

  public JwtAuthenticationWebFilter(ServerTokenAuthenticationConverter authenticationConverter) {
    this.authenticationConverter = authenticationConverter;
  }


  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

    log.debug("JWT Auth Web Filter :: {} {}",
        exchange.getRequest().getMethod(),
        exchange.getRequest().getPath());
    return
        // First, try and extract HTTP Basic credentials
        this.authenticationConverter.convert(exchange)
            .doOnNext(authentication -> {
              Principal principal = (Principal) authentication.getPrincipal();
              log.debug("Validated API Token for Principal: `{}`", principal.getName());
            })
            .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))

            // If successful, save the Authentication object in the Security Context
            .flatMap(authentication -> onAuthenticationSuccess(
                authentication, new WebFilterExchange(exchange, chain)))

            // If authentication failed, register the failure and continue with the chain,
            // as there may be other filters which are able to successfully authenticate the user.
            .onErrorResume(AuthenticationException.class, e -> this.failureHandler
                .onAuthenticationFailure(new WebFilterExchange(exchange, chain), e));
  }

  private Mono<Void> onAuthenticationSuccess(Authentication authentication,
                                             WebFilterExchange filterExchange) {
    log.debug("Auth Success :: {}", authentication == null ? "null" :
        authentication.getCredentials());

    SecurityContextImpl securityContext = new SecurityContextImpl();
    securityContext.setAuthentication(authentication);

    return authenticationSuccessHandler
        .onAuthenticationSuccess(filterExchange, authentication)
        .subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
  }
}
