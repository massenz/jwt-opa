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

import com.alertavert.opa.AbstractTestBase;
import com.alertavert.opa.Constants;
import com.alertavert.opa.JwtTokenProvider;
import com.alertavert.opa.ApiTokenAuthenticationFactory;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtReactiveAuthorizationManagerTest extends AbstractTestBase {

  @Autowired
  JwtReactiveAuthorizationManager manager;

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  ApiTokenAuthenticationFactory factory;


  @MockBean(name = "authorizationManager")
  OpaReactiveAuthorizationManager opaAuthorizationManager;

  AuthorizationContext context = mock(AuthorizationContext.class);
  ServerHttpRequest mockRequest = mock(ServerHttpRequest.class);
  ServerWebExchange mockExchange = mock(ServerWebExchange.class);
  HttpHeaders mockHeaders = mock(HttpHeaders.class);

  private void mockWithOpaResult(boolean granted) {
    when(opaAuthorizationManager.check(any(), eq(mockRequest)))
        .thenReturn(Mono.just(new AuthorizationDecision(granted)));
  }

  private void mockWithValidToken() {
    String token = provider.createToken("test-user", Lists.list("USER"));
    when(mockHeaders.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn(
        String.format("%s %s", Constants.BEARER_TOKEN, token));
  }

  private void mockWithInvalidToken() {
    when(mockHeaders.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn(
        String.format("%s %s", Constants.BEARER_TOKEN, "not a token"));
  }

  @BeforeEach
  void initMocks() {
    when(context.getExchange()).thenReturn(mockExchange);
    when(mockExchange.getRequest()).thenReturn(mockRequest);
    when(mockRequest.getHeaders()).thenReturn(mockHeaders);
    when(mockRequest.getPath()).thenReturn(
        RequestPath.parse(URI.create("/some/crazy/test/path"), null));
  }

  @Test
  void checkSucceeds() {
    mockWithValidToken();

    // Happy path: the OPA server returned an "allow" result.
    mockWithOpaResult(true);

    assertThat(manager.check(Mono.empty(), context)
        .map(AuthorizationDecision::isGranted).block()
    ).isTrue();

    verify(opaAuthorizationManager).check(any(), eq(mockRequest));
  }

  @Test
  void checkFailsIfNoToken() {
    assertThat(manager.check(Mono.empty(), context)
        .map(AuthorizationDecision::isGranted).block()
    ).isNull();

    // We never even got so far as to calling the OPA Server
    verify(opaAuthorizationManager, never()).check(any(), any());
  }

  @Test
  void checkFailsIfInvalidToken() {
    mockWithInvalidToken();

    assertThat(manager.check(Mono.empty(), context)
        .map(AuthorizationDecision::isGranted).block()
    ).isNull();

    // We never even got so far as to calling the OPA Server
    verify(opaAuthorizationManager, never()).check(any(), any());
  }

  @Test
  void checkFailsIfOpaCheckFails() {
    mockWithValidToken();
    mockWithOpaResult(false);

    assertThat(manager.check(Mono.empty(), context)
        .map(AuthorizationDecision::isGranted).block()
    ).isFalse();

    verify(opaAuthorizationManager).check(any(), eq(mockRequest));
  }
}
