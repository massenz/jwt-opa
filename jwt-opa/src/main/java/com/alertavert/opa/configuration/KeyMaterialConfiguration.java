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

import com.alertavert.opa.security.crypto.KeypairFileReader;
import com.alertavert.opa.security.crypto.KeypairReader;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static com.alertavert.opa.Constants.ELLIPTIC_CURVE;
import static com.alertavert.opa.Constants.PASSPHRASE;
import static com.alertavert.opa.Constants.UNDEFINED_KEYPAIR;

@Slf4j
@Configuration
@EnableConfigurationProperties(TokensProperties.class)
public class KeyMaterialConfiguration {

  private final TokensProperties tokensProperties;

  public KeyMaterialConfiguration(TokensProperties properties) {
    this.tokensProperties = properties;
  }

  @Bean
  public String issuer() {
    return tokensProperties.getIssuer();
  }

  @Bean
  Algorithm hmac(KeypairReader reader) {
    switch (reader.algorithm()) {
      case PASSPHRASE:
        return Algorithm.HMAC256(tokensProperties.getSecret());
      case ELLIPTIC_CURVE:
        KeyPair keyPair = reader.loadKeys();
        return Algorithm.ECDSA256((ECPublicKey) keyPair.getPublic(),
            (ECPrivateKey) keyPair.getPrivate());
      default:
        throw new IllegalArgumentException(String.format("Algorithm [%s] not supported",
          reader.algorithm()));
    }
  }

  @Bean
  JWTVerifier verifier(Algorithm algorithm) throws IOException {
    return JWT.require(algorithm)
        .withIssuer(issuer())
        .build();
  }
}
