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

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import reactor.core.publisher.Mono;

/**
 * <h3>TokenAuthenticationFailureHandler</h3>
 *
 * <p>Helper class to handle authentication failures, modeled over Spring's
 * {@link org.springframework.security.web.server.authentication.AuthenticationWebFilter}.
 *
 * @see AuthenticationWebFilter
 * @author M. Massenzio, 2021-04-15
 */
public class TokenAuthenticationFailureHandler
    implements ServerAuthenticationFailureHandler {

  @Override
  public Mono<Void> onAuthenticationFailure(WebFilterExchange exchange,
                                            AuthenticationException exception) {
    return Mono.fromRunnable(() -> {
      ServerHttpResponse response = exchange.getExchange().getResponse();
      response.setStatusCode(HttpStatus.UNAUTHORIZED);
    });
  }
}
