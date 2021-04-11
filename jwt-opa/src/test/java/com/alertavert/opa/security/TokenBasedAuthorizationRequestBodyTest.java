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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.alertavert.opa.security.TokenBasedAuthorizationRequestBody.RequestBody;
import org.junit.jupiter.api.Test;

import static com.jayway.jsonpath.matchers.JsonPathMatchers.hasJsonPath;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class TokenBasedAuthorizationRequestBodyTest {

  ObjectMapper mapper = new ObjectMapper();

  @Test
  void build() throws JsonProcessingException {
    RequestBody requestBody = TokenBasedAuthorizationRequestBody.build(
        "token", "/foo/bar", "POST"
    );
    String json = mapper.writeValueAsString(requestBody);

    assertThat(json, hasJsonPath("$.input"));
    assertThat(json, hasJsonPath("$.input.api_token", equalTo("token")));
    assertThat(json, hasJsonPath("$.input.resource.method", equalTo("POST")));
    assertThat(json, hasJsonPath("$.input.resource.path", equalTo("/foo/bar")));
  }
}
