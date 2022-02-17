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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.ToString;
import lombok.Value;
import org.springframework.util.StringUtils;

import static com.alertavert.opa.Constants.MAX_TOKEN_LEN_LOG;

/**
 * <h2>TokenBasedAuthorizationRequestBody</h2>
 *
 * <p>Encapsulates a request body to the OPA server, structured in a way that conforms to the
 * policy's Rego code's expectations:
 *
 * <code>
 * { "input": { "api_token": ".... API Token Base-64 encoded ...", "resource": { "path":
 * "/path/to/resource", "method": "POST" } } }
 * </code>
 *
 * @author M. Massenzio, 2020-11-22
 * @see OpaReactiveAuthorizationManager
 */
@Value
public class TokenBasedAuthorizationRequestBody {


  /**
   * The OPA server requires every POST body to the Data API to be wrapped inside an {@literal
   * "input"} object, we use this class to simplify the construction of the JSON body.
   */
  @Value
  public static class RequestBody {
    @JsonIgnore
    ObjectMapper mapper = new ObjectMapper();
    TokenBasedAuthorizationRequestBody input;

    /**
     * Pretty-formatted JSON content of this RequestBody, with the API Token (JWT) masked.
     *
     * @return a printable String, suitable for logging
     */
    public String prettyPrint() {
      RequestBody body = build(input.token.substring(0, MAX_TOKEN_LEN_LOG) + "...",
          input.resource.path, input.resource.method);
      try {
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
      } catch (JsonProcessingException e) {
        throw new RuntimeException(e);
      }
    }
  }

  @Value
  public static class Resource {
    String path;
    String method;
  }

  @JsonProperty("api_token")
  @ToString.Exclude
  String token;
  Resource resource;

  public static RequestBody build(String token, String path, String method) {
    return new RequestBody(new TokenBasedAuthorizationRequestBody(token,
        new Resource(path, method)));
  }
}
