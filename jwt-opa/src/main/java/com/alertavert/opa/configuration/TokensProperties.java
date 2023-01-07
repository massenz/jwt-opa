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

package com.alertavert.opa.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * <h2>TokensPropertiers</h2>
 *
 * @author M. Massenzio, 2020-12-14
 */
@Data
@ConfigurationProperties(prefix = "tokens")
public class TokensProperties {

  /**
   * Corresponds to the {@literal "iss"} claim; the authority that has issued the token
   */
  private String issuer;

  /**
   * Passphrase-based signature uses this secret.
   *
   * <strong>NOT recommended</strong> as this is insecure, prefer the use of private/public key
   * pairs.
   *
   * @see com.alertavert.opa.security.crypto.KeypairReader
   */
  private String secret;

  /**
   * {@literal true} by default, used in conjunction with {@link #expiresAfterSec} to determine
   * whether the token should expire and, if so, how long after it has been created (the
   * {@literal "iat"}, "issued-at" claim).
   */
  boolean shouldExpire = true;

  /**
   * How long this token is valid; this value is added to the creation time ({@literal "iat"}
   * claim} and set in the {@literal "exp"} (expires) claim.
   */
  long expiresAfterSec = 86400L;

  /**
   * To set the {@literal "nbf"} (not-before) claim, this value is added to the token's creation
   * time ({@literal "iat"} (issued-at) time.
   *
   * By default this value is 0, i.e., the token is immediately available for use.
   */
  long notBeforeDelaySec = 0L;
}
