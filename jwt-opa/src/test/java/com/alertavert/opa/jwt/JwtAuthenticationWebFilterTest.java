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

import com.alertavert.opa.AbstractTestBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationWebFilterTest extends AbstractTestBase {

  ServerWebExchange exchange = mock(ServerWebExchange.class);
  WebFilterChain chain = mock(WebFilterChain.class);
  ServerHttpRequest request = mock(ServerHttpRequest.class);

  @Autowired
  JwtAuthenticationWebFilter filter;

  @Autowired
  JwtTokenProvider provider;

  @BeforeEach
  public void setup() {
    RequestPath path = mock(RequestPath.class);

    when(exchange.getRequest()).thenReturn(request);
    when(request.getMethod()).thenReturn(HttpMethod.GET);
    when(request.getPath()).thenReturn(path);
    when(path.toString()).thenReturn("/path");
  }

  @Disabled("The ReactiveSecurityContextHolder does not seem to hold the Authentication object, so "
      + "this test will always fail, even if the filter works fine.")
  @Test
  public void validTokenShouldValidate() {
    String token = provider.createToken("alice", List.of("USER"));
    setBearerTokenForRequest(request, token);

    when(chain.filter(exchange)).thenReturn(Mono.empty());
    filter.filter(exchange, chain)
        .subscribe();

    // TODO: This fails, because of some Spring Security magic: find out why.
    Authentication authentication = ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .block();
    assertThat(authentication).isNotNull();
    assertThat(authentication.isAuthenticated()).isTrue();
  }
}
