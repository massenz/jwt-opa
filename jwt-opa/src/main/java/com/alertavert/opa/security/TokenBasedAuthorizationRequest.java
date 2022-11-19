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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

import java.util.Map;

import static com.alertavert.opa.Constants.MAPPER;
import static com.alertavert.opa.Constants.MAX_TOKEN_LEN_LOG;


/**
 * <h2>TokenBasedAuthorizationRequest</h2>
 *
 * <p>Encapsulates a request body to the OPA server, structured in a way that conforms to the
 * policy's Rego code's expectations:
 *
 * <p>The OPA server requires every POST body to the Data API to be wrapped inside an {@literal
 * "input"} object, we use this class to simplify the construction of the JSON body.
 *
 // {{ formatter:off }}
    <pre>
      {
        "input": {
            "api_token": ".... API Token Base-64 encoded ...",
            "resource": {
                "method": "POST",
                "path": "/path/to/resource"
           }
        }
      }
    </pre>
 // {{ formatter:on }}
 *
 * <p>When serializing to String (e.g., in debug logs output) the API Token (JWT) is obfuscated
 * (and the request is rendered in pretty-printed JSON).
 *
 * @author M. Massenzio, 2020-11-22
 * @see OpaReactiveAuthorizationManager
 */
@Value
@Builder
@Jacksonized
public class TokenBasedAuthorizationRequest {

  public record Resource(String method, String path, Map<String, ?> headers) {
  }

  public record AuthRequestBody(@JsonProperty("api_token") String token, Resource resource) {
  }

  AuthRequestBody input;

  @Override
  public String toString() {
    try {
      String token = "";
      if (input.token.length() > 2 * MAX_TOKEN_LEN_LOG) {
        token = input.token.substring(0, MAX_TOKEN_LEN_LOG) + "****" +
            input.token.substring(input.token.length() - MAX_TOKEN_LEN_LOG);
      }
      TokenBasedAuthorizationRequest copy = TokenBasedAuthorizationRequest.builder()
          .input(new AuthRequestBody(token, input.resource))
          .build();
      return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(copy);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }
}
