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
import org.springframework.http.HttpHeaders;
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
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
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

  @Value("classpath:test_policy.rego")
  private Resource resource;

  @BeforeEach
  void postPolicy() throws IOException {
    Reader reader = new InputStreamReader(resource.getInputStream(), UTF_8);
    String policy = FileCopyUtils.copyToString(reader);

    client.put()
        .uri(policyEndpoint)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.TEXT_PLAIN)
        .bodyValue(policy)
        .exchangeToMono(response -> {
          assertThat(response).isNotNull();
          assertThat(response.statusCode()).isEqualTo(HttpStatus.OK);
          return response.bodyToMono(String.class);
        })
        .block();
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

    assertThat(opaReactiveAuthorizationManager.check(
        Mono.just(auth), context)
        .map(AuthorizationDecision::isGranted)
        .block()).isFalse();
  }

  @Test
  public void checkUnauthenticatedFails() {
    Authentication auth = new UsernamePasswordAuthenticationToken("bob", "pass");

    // As this endpoint is not mapped in `routes` (application-test.yaml) it expects by default
    // a JWT Authorization Bearer token; finding a Username/Password credentials will deny access.
    AuthorizationContext context = getAuthorizationContext(HttpMethod.GET, "/whocares");
    assertThat(opaReactiveAuthorizationManager.check(Mono.just(auth), context).block()).isNull();
  }

  private AuthorizationContext getAuthorizationContext(
      HttpMethod method, String path
  ) {
    return getAuthorizationContextWithHeaders(method, path, Map.of());
  }

  private AuthorizationContext getAuthorizationContextWithHeaders(
      HttpMethod method, String path, Map<String, String> headers
  ) {
    ServerHttpRequest request = mock(ServerHttpRequest.class);
    RequestPath requestPath = mock(RequestPath.class);

    when(request.getMethodValue()).thenReturn(method.name());
    when(request.getPath()).thenReturn(requestPath);
    when(requestPath.toString()).thenReturn(path);

    HttpHeaders mockHeaders = new HttpHeaders();
    headers.forEach((k,v) -> mockHeaders.put(k, List.of(v)));
    when(request.getHeaders()).thenReturn(mockHeaders);

    ServerWebExchange exchange = mock(ServerWebExchange.class);
    when(exchange.getRequest()).thenReturn(request);

    AuthorizationContext context = mock(AuthorizationContext.class);
    when(context.getExchange()).thenReturn(exchange);
    return context;
  }

  @Test
  public void authenticatedEndpointBypassesOpa() {
    AuthorizationContext context = getAuthorizationContext(HttpMethod.GET, "/testauth");
    assertThat(opaReactiveAuthorizationManager.check(
            factory.createAuthentication(
                provider.createToken("alice", Lists.list("USER"))
            ), context)
        .map(AuthorizationDecision::isGranted)
        .block()).isTrue();
  }

  @Test
  public void authenticatedEndpointMatches() {
    // In the test configuration (application-test.yaml) we have configured the following
    // path matchers: ["/match/*/this", "/match/any/**"].
    // Here we test that an authenticated user gains access to them without needing authorization.

    AuthorizationContext context = getAuthorizationContext(HttpMethod.GET, "/match/one/this");
    assertThat(opaReactiveAuthorizationManager.check(
            factory.createAuthentication(
                provider.createToken("alice", Lists.list("USER"))
            ), context)
        .map(AuthorizationDecision::isGranted)
        .block()).isTrue();

    // This should NOT match
    context = getAuthorizationContext(HttpMethod.GET, "/match/one/two/this.html");
    assertThat(opaReactiveAuthorizationManager.check(
            factory.createAuthentication(
                provider.createToken("alice", Lists.list("USER"))
            ), context)
        .map(AuthorizationDecision::isGranted)
        .block()).isFalse();

    context = getAuthorizationContext(HttpMethod.GET, "/match/any/this/that.html");
    assertThat(opaReactiveAuthorizationManager.check(
            factory.createAuthentication(
                provider.createToken("alice", Lists.list("USER"))
            ), context)
        .map(AuthorizationDecision::isGranted)
        .block()).isTrue();
  }

  @Test
  public void testHeaders() {
    AuthorizationContext context = getAuthorizationContextWithHeaders(HttpMethod.GET, "/whatever",
        Map.of("x-test-header", "test-value", HttpHeaders.USER_AGENT, "TestAgent"));
    assertThat(opaReactiveAuthorizationManager.check(
        factory.createAuthentication(
            provider.createToken("alice", List.of("USER"))), context
        )
        .map(AuthorizationDecision::isGranted)
        .block()).isTrue();

    context = getAuthorizationContextWithHeaders(HttpMethod.GET, "/whatever",
        Map.of("x-test-header", "wrong-value", HttpHeaders.USER_AGENT, "TestAgent"));
    assertThat(opaReactiveAuthorizationManager.check(
        factory.createAuthentication(
            provider.createToken("alice", List.of("USER"))), context
        )
        .map(AuthorizationDecision::isGranted)
        .block()).isFalse();
  }
}
