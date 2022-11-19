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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.alertavert.opa.security.TokenBasedAuthorizationRequest.AuthRequestBody;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.alertavert.opa.Constants.MAPPER;
import static com.jayway.jsonpath.matchers.JsonPathMatchers.hasJsonPath;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class TokenBasedAuthorizationRequestTest {

  @Test
  void serialize() throws Exception {
    TokenBasedAuthorizationRequest request = TokenBasedAuthorizationRequest.builder()
        .input(new AuthRequestBody("tokenAAjwtDEF123456.anothertoken.yetanothertoken",
            new TokenBasedAuthorizationRequest.Resource("POST", "/foo/bar", Map.of()))
        )
        .build();
    String json = MAPPER.writeValueAsString(request);

    assertThat(json, hasJsonPath("$.input"));
    assertThat(json, hasJsonPath("$.input.api_token", equalTo("tokenAAjwtDEF123456.anothertoken.yetanothertoken")));
    assertThat(json, hasJsonPath("$.input.resource.method", equalTo("POST")));
    assertThat(json, hasJsonPath("$.input.resource.path", equalTo("/foo/bar")));
  }

  @Test
  void obfuscatesJwt() {
    TokenBasedAuthorizationRequest request = TokenBasedAuthorizationRequest.builder()
        .input(new AuthRequestBody("tokenAAjwtDEF123456.anothertoken.yetanothertoken",
            new TokenBasedAuthorizationRequest.Resource("POST", "/foo/bar", Map.of()))
        )
        .build();
    String json = request.toString();

    assertThat(json, hasJsonPath("$.input"));
    assertThat(json, hasJsonPath("$.input.api_token", equalTo("tokenA****rtoken")));
    assertThat(json, hasJsonPath("$.input.resource.method", equalTo("POST")));
    assertThat(json, hasJsonPath("$.input.resource.path", equalTo("/foo/bar")));
  }
}
