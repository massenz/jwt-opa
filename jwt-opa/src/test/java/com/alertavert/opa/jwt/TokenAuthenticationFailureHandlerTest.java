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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.web.server.ServerWebExchange;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TokenAuthenticationFailureHandlerTest {

  ServerAuthenticationFailureHandler handler = new TokenAuthenticationFailureHandler();

  WebFilterExchange exchange = mock(WebFilterExchange.class);
  ServerHttpResponse response = mock(ServerHttpResponse.class);

  @BeforeEach
  public void init() {
    ServerWebExchange webExchange = mock(ServerWebExchange.class);
    when(webExchange.getResponse()).thenReturn(response);
    when(exchange.getExchange()).thenReturn(webExchange);
  }

  @Test
  public void testAuthFailure() {
    handler.onAuthenticationFailure(exchange, new BadCredentialsException("bad bad bad"))
        .subscribe();

    verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
  }

}
