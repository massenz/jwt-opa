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

import com.alertavert.opa.Constants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static com.alertavert.opa.Constants.BEARER_TOKEN;

/**
 * <h2>ServerTokenAuthenticationConverter</h2>
 *
 * <p>Given a {@link ServerHttpRequest request} it extracts the API Token and creates an
 * {@link Authentication} object from it; in the process of creating it, the
 * {@link ApiTokenAuthenticationFactory factory} will also validate it, so that the
 * authentication process can progress.
 *
 * @author M. Massenzio, 2021-04-15
 */
@Slf4j
@Component
public class ServerTokenAuthenticationConverter implements ServerAuthenticationConverter {

  @Autowired
  ApiTokenAuthenticationFactory factory;

  private Mono<String> resolveToken(ServerHttpRequest request) {
    String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_TOKEN)
        && bearerToken.length() > BEARER_TOKEN.length()) {
      return Mono.just(bearerToken.substring(BEARER_TOKEN.length() + 1));
    }
    log.warn(Constants.TOKEN_MISSING_OR_INVALID);
    return Mono.empty();
  }

  @Override
  public Mono<Authentication> convert(ServerWebExchange exchange) {
    return resolveToken(exchange.getRequest())
        .flatMap(factory::createAuthentication);
  }
}
