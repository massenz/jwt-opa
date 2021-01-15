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

package io.kapsules.jwt.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * <h3>KeyPropertiers</h3>
 *
 * @author M. Massenzio, 2020-12-14
 */
@Data
@ConfigurationProperties(prefix = "secrets")
public class KeyProperties {

  @Data
  public static class Pair {
    String priv;
    String pub;
  }

  private String algorithm;
  private String issuer;
  private Pair keypair;
  private String secret;
}
