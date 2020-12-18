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

package io.kapsules.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.kapsules.jwt.thirdparty.PemUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.Value;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * <h3>KeyPair</h3>
 *
 * <p>A JSON-friendly representation of an immutable Private/Public asymmetric key pair.
 *
 * @author M. Massenzio, 2020-09-04
 */
// TODO: this class is just a stopgap measure; we should use instead already-available others.

@Value
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class KeyPair {

  @JsonProperty("private")
  Map<String, String> privateKeyProperties = new HashMap<>();

  @JsonProperty("public")
  Map<String, String> publicKeyProperties = new HashMap<>();

  public PrivateKey getPrivateKey() {
    if (privateKeyProperties.containsKey("key")) {
      return PemUtils.getPrivateKey(
          Base64.getUrlDecoder().decode(privateKeyProperties.get("key").getBytes()),
          privateKeyProperties.get("algorithm")
      );
    }
    throw new IllegalStateException("Key pair does not contain key material");
  }

  public PublicKey getPublicKey() {
    if (publicKeyProperties.containsKey("key")) {
      return PemUtils.getPublicKey(
          Base64.getUrlDecoder().decode(publicKeyProperties.get("key").getBytes()),
          publicKeyProperties.get("algorithm")
      );
    }
    throw new IllegalStateException("Key pair does not contain key material");
  }

  public static KeyPair build(PrivateKey privateKey, PublicKey publicKey) {
    KeyPair pair = new KeyPair();

    pair.privateKeyProperties.put("algorithm", privateKey.getAlgorithm());
    pair.privateKeyProperties.put("format", privateKey.getFormat());
    pair.privateKeyProperties.put("key",
        new String(Base64.getUrlEncoder().encode(privateKey.getEncoded())));


    pair.publicKeyProperties.put("algorithm", publicKey.getAlgorithm());
    pair.publicKeyProperties.put("format", publicKey.getFormat());
    pair.publicKeyProperties.put("key",
        new String(Base64.getUrlEncoder().encode(publicKey.getEncoded())));

    return pair;
  }
}
