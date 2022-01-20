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

import com.alertavert.opa.AbstractTestBaseWithOpaContainer;
import com.alertavert.opa.jwt.ApiTokenAuthenticationFactory;
import com.alertavert.opa.jwt.JwtTokenProvider;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OpaReactiveAuthorizationManagerTest extends AbstractTestBaseWithOpaContainer {

  @Autowired
  OpaReactiveAuthorizationManager opaReactiveAuthorizationManager;

  @Autowired
  ApiTokenAuthenticationFactory factory;

  @Autowired
  JwtTokenProvider provider;

  @Autowired
  WebClient client;

  @Autowired
  String policyEndpoint;

  @Value("classpath:jwt_auth.rego")
  private Resource resource;

  @BeforeEach
  void postPolicy() throws IOException {
    Reader reader = new InputStreamReader(resource.getInputStream(), UTF_8);
    String policy = FileCopyUtils.copyToString(reader);

    ClientResponse response = client.put()
        .uri(policyEndpoint)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.TEXT_PLAIN)
        .bodyValue(policy)
        .exchange()
        .block();
    assertThat(response).isNotNull();
    assertThat(response.statusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void check() {
    Mono<Authentication> auth = factory.createAuthentication(
      provider.createToken("test-user", Lists.list("USER"))
    );

    AuthorizationContext context = getAuthorizationContext(HttpMethod.GET, "/users/test-user");
    opaReactiveAuthorizationManager.check(auth, context)
        .doOnNext(decision -> {
          assertThat(decision).isNotNull();
          assertThat(decision.isGranted()).isTrue();
        }).subscribe();
  }

  @Test
  public void checkUnauthorizedFails() {
    Authentication auth = factory.createAuthentication(
        provider.createToken("alice", Lists.list("USER"))
    ).block();
    assertThat(auth).isNotNull();
    assertThat(auth.isAuthenticated()).isTrue();
    AuthorizationContext context = getAuthorizationContext(HttpMethod.POST, "/users");

    AuthorizationDecision decision = opaReactiveAuthorizationManager.check(
        Mono.just(auth), context).block();
    assertThat(decision).isNotNull();
    assertThat(decision.isGranted()).isFalse();
  }

  @Test
  public void checkUnauthenticatedFails() {
    Authentication auth = new UsernamePasswordAuthenticationToken("bob", "pass");
    AuthorizationContext context = getAuthorizationContext(HttpMethod.GET, "/whocares");

    opaReactiveAuthorizationManager.check(Mono.just(auth), context)
        .doOnNext(decision -> assertThat(decision.isGranted()).isFalse())
        .block();
  }

  private AuthorizationContext getAuthorizationContext(
      HttpMethod method, String path
  ) {
    ServerHttpRequest request = mock(ServerHttpRequest.class);
    RequestPath requestPath = mock(RequestPath.class);

    when(request.getMethod()).thenReturn(method);
    when(request.getPath()).thenReturn(requestPath);
    when(requestPath.toString()).thenReturn(path);

    ServerWebExchange exchange = mock(ServerWebExchange.class);
    when(exchange.getRequest()).thenReturn(request);

    AuthorizationContext context = mock(AuthorizationContext.class);
    when(context.getExchange()).thenReturn(exchange);
    return context;
  }

  @Test
  public void authenticatedEndpointBypassesOpa() {
    AuthorizationContext context = getAuthorizationContext(HttpMethod.GET, "/testauth");
    opaReactiveAuthorizationManager.check(
        factory.createAuthentication(
            provider.createToken("alice", Lists.list("USER"))
        ), context)
        .map(AuthorizationDecision::isGranted)
        .doOnNext(b -> assertThat(b).isTrue())
        .subscribe();
  }

  @Test
  public void authenticatedEndpointMatches() {
    // In the test configuration (application-test.yaml) we have configured the following
    // path matchers: ["/match/*/this", "/match/any/**"].
    // Here we test that an authenticated user gains access to them without needing authorization.

    AuthorizationContext context = getAuthorizationContext(HttpMethod.GET, "/match/one/this");
    opaReactiveAuthorizationManager.check(
        factory.createAuthentication(
            provider.createToken("alice", Lists.list("USER"))
        ), context)
        .map(AuthorizationDecision::isGranted)
        .doOnNext(b -> assertThat(b).isTrue())
        .subscribe();

    // This should NOT match
    context = getAuthorizationContext(HttpMethod.GET, "/match/one/two/this.html");
    opaReactiveAuthorizationManager.check(
        factory.createAuthentication(
            provider.createToken("alice", Lists.list("USER"))
        ), context)
        .map(AuthorizationDecision::isGranted)
        .doOnNext(b -> assertThat(b).isFalse())
        .subscribe();

    context = getAuthorizationContext(HttpMethod.GET, "/match/any/this/that.html");
    opaReactiveAuthorizationManager.check(
        factory.createAuthentication(
            provider.createToken("alice", Lists.list("USER"))
        ), context)
        .map(AuthorizationDecision::isGranted)
        .doOnNext(b -> assertThat(b).isTrue())
        .subscribe();
  }
}
