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

import io.kapsules.jwt.AbstractTestBase;
import io.kapsules.jwt.ApiTokenAuthenticationFactory;
import io.kapsules.jwt.JwtTokenProvider;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OpaReactiveAuthorizationManagerTest extends AbstractTestBase {

  @Autowired
  OpaReactiveAuthorizationManager opaReactiveAuthorizationManager;

  @Autowired
  ApiTokenAuthenticationFactory factory;

  @Autowired
  JwtTokenProvider provider;

  @Test
  void isInjected() {
    assertThat(opaReactiveAuthorizationManager).isNotNull();
  }

  @Test
  void check() {
    Authentication auth = factory.createAuthentication(
      provider.createToken("test-user", Lists.list("USER"))
    );
    assertThat(auth.isAuthenticated()).isTrue();

    ServerHttpRequest request = mock(ServerHttpRequest.class);
    RequestPath path = mock(RequestPath.class);

    when(request.getMethod()).thenReturn(HttpMethod.GET);
    when(request.getPath()).thenReturn(path);
    when(path.toString()).thenReturn("/users/test-user");

    AuthorizationDecision decision = opaReactiveAuthorizationManager.check(
        Mono.just(auth), request
    ).block();
    assertThat(decision).isNotNull();
    assertThat(decision.isGranted()).isTrue();
  }
}
