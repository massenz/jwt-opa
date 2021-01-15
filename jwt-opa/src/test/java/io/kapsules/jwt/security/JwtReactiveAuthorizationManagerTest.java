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

package io.kapsules.jwt.security;

import io.kapsules.jwt.AbstractTestBaseWithOpaContainer;
import io.kapsules.jwt.ApiTokenAuthenticationFactory;
import io.kapsules.jwt.JwtTokenProvider;
import org.assertj.core.util.Lists;
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

import static io.kapsules.jwt.Constants.BEARER_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtReactiveAuthorizationManagerTest extends AbstractTestBaseWithOpaContainer {

  @Autowired
  JwtReactiveAuthorizationManager manager;

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  ApiTokenAuthenticationFactory factory;


  @MockBean(name = "authorizationManager")
  OpaReactiveAuthorizationManager authorizationManager;

  @Test
  void check() {
    AuthorizationContext context = mock(AuthorizationContext.class);
    ServerHttpRequest mockRequest = mock(ServerHttpRequest.class);
    ServerWebExchange mockExchange = mock(ServerWebExchange.class);
    HttpHeaders mockHeaders = mock(HttpHeaders.class);

    String token = provider.createToken("test-user", Lists.list("USER"));

    when(context.getExchange()).thenReturn(mockExchange);
    when(mockExchange.getRequest()).thenReturn(mockRequest);

    when(mockRequest.getHeaders()).thenReturn(mockHeaders);
    when(mockHeaders.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn(
        String.format("%s %s", BEARER_TOKEN, token));

    when(mockRequest.getPath()).thenReturn(
        RequestPath.parse(URI.create("/some/crazy/test/path"), null));

    // Happy path: the OPA server returned an "allow" result.
    when(authorizationManager.check(any(), eq(mockRequest)))
        .thenReturn(Mono.just(new AuthorizationDecision(true)));

    assertThat(manager.check(Mono.empty(), context)
      .map(AuthorizationDecision::isGranted).block()
    ).isTrue();

    verify(authorizationManager).check(any(), eq(mockRequest));
  }
}
