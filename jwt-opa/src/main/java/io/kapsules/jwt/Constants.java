/*
 * Copyright (c) 2021 kapsules.io.  All rights reserved.
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

package io.kapsules.jwt;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Constants {
  // Authorization header types.
  public static final String BASIC_AUTH = "Basic";
  public static final String BEARER_TOKEN = "Bearer";

  // Secrets options
  public static final String ELLIPTIC_CURVE = "EC";
  public static final String PASSPHRASE = "SECRET";

  // OPA Server API constants.
  public static final String OPA_VERSION = "v1";
  public static final String OPA_DATA_API = "data";
  public static final String OPA_POLICIES_API = "policies";

  // Error Messages
  public static final String FILE_NOT_EXISTS = "The file '%s' doesn't exist.";
  public static final String INVALID_RESULT = "OPA Server did not return a valid result";
  public static final String UNEXPECTED_AUTHENTICATION_OBJECT = "Unexpected Authentication object";
  public static final String TOKEN_MISSING_OR_INVALID = "API Token was missing or invalid";
  public static final String AUTHORIZATION_HEADER_MISSING =
      "No Authorization header, rejecting request";
}
