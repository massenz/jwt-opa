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
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.testcontainers.containers.FixedHostPortGenericContainer;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Testcontainers
class OpaReactiveAuthorizationManagerTest extends AbstractTestBase {

  @Autowired
  OpaReactiveAuthorizationManager opaReactiveAuthorizationManager;

  @Autowired
  ApiTokenAuthenticationFactory factory;

  @Autowired
  JwtTokenProvider provider;

  // TODO: Use @ContextConfiguration(initializers) to use the dynamically generated port.
  @Container
  public GenericContainer<?> opaServer = new FixedHostPortGenericContainer<>(
      "openpolicyagent/opa:0.25.2")
      .withExposedPorts(8181)
      .withFixedExposedPort(8181, 8181)
      .withCommand("run --server --addr :8181")
      .waitingFor(Wait.forHttp("/health"));

  @Autowired
  WebClient client;

  @Autowired
  String policyEndpoint;

  @Value("classpath:jwt_auth.rego")
  private Resource resource;

  @BeforeEach
  void postPolicy() throws IOException {
    System.out.println(">>>> " + policyEndpoint);

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
  void isReady() {
    assertThat(opaReactiveAuthorizationManager).isNotNull();

    assertThat(opaServer).isNotNull();
    assertThat(opaServer.getHost()).isEqualTo("localhost");
    assertThat(opaServer.getFirstMappedPort()).isEqualTo(8181);
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
        Mono.just(auth), request).block();
    assertThat(decision).isNotNull();
    assertThat(decision.isGranted()).isTrue();
  }
}
