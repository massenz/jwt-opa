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
import lombok.Value;

/**
 * <h3>TokenBasedAuthorizationRequestBody</h3>
 *
 * <p>Encapsulates a request body to the OPA server, structured in a way that conforms to the
 * policy's Rego code's expectations:
 *
 <code>
 {
    "input": {
        "api_token": ".... API Token Base-64 encoded ...",
        "resource": {
            "path": "/path/to/resource",
            "method": "POST"
        }
    }
 }
 </code>
 *
 * @see OpaReactiveAuthorizationManager
 * @author M. Massenzio, 2020-11-22
 */
@Value
public class TokenBasedAuthorizationRequestBody {

  /**
   * The OPA server requires every POST body to the Data API to be wrapped inside an {@literal
   * "input"} object, we use this class to simplify the construction of the JSON body.
   */
  @Value
  public static class RequestBody {
    TokenBasedAuthorizationRequestBody input;
  }

  @Value
  public static class Resource {
    String path;
    String method;
  }

  @JsonProperty("api_token")
  String token;
  Resource resource;

  public static RequestBody build(String token, String path, String method) {
    return new RequestBody(new TokenBasedAuthorizationRequestBody(token,
        new Resource(path, method)));
  }
}
