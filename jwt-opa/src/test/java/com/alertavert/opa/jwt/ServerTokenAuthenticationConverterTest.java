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
import com.alertavert.opa.Constants;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.server.ServerWebExchange;

import java.security.Principal;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ServerTokenAuthenticationConverterTest extends AbstractTestBase {

  @Autowired
  JwtTokenProvider tokenProvider;

  @Autowired
  ServerTokenAuthenticationConverter converter;

  ServerWebExchange exchange = mock(ServerWebExchange.class);
  ServerHttpRequest request = mock(ServerHttpRequest.class);


  @BeforeEach
  public void setup() {
    when(exchange.getRequest()).thenReturn(request);
  }

  @Test
  public void validTokenShouldReturnAuthentication() {
    String token = tokenProvider.createToken("bob", Lists.list("USER", "TESTER"));
    setBearerTokenForRequest(request, token);
    Authentication authentication = converter.convert(exchange).block();
    assertThat(authentication).isNotNull();
    assertThat(authentication.isAuthenticated()).isTrue();
    assertThat(authentication.getCredentials().toString()).isEqualTo(token);

    assertThat(authentication.getPrincipal()).isInstanceOf(Principal.class);
    assertThat(((Principal)authentication.getPrincipal()).getName()).isEqualTo("bob");

    assertThat(authentication.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.toList())).containsExactlyInAnyOrder("USER", "TESTER");
  }

  @Test
  public void invalidTokenShouldFail() {
    setBearerTokenForRequest(request, "definitelynotatoken");
    Authentication authentication = converter.convert(exchange).block();
    assertThat(authentication).isNull();
  }

  @Test
  public void missingAuthorizationHeaderShouldBeHandledGracefully() {
    HttpHeaders headers = mock(HttpHeaders.class);
    when(request.getHeaders()).thenReturn(headers);
    when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn(null);

    Authentication authentication = converter.convert(exchange).block();
    assertThat(authentication).isNull();

    // An empty token should also not cause a panic.
    when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn(Constants.BEARER_TOKEN);
    authentication = converter.convert(exchange).block();
    assertThat(authentication).isNull();
  }

  @Test
  public void basicAuthorizationHeaderShouldBeHandledGracefully() {
    HttpHeaders headers = mock(HttpHeaders.class);
    when(request.getHeaders()).thenReturn(headers);
    when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn(
        String.format("%s %s", Constants.BASIC_AUTH, "deadbeff")
    );

    Authentication authentication = converter.convert(exchange).block();
    assertThat(authentication).isNull();
  }
}
