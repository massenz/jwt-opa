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
@EnableConfigurationProperties(KeyProperties.class)
public class KeyMaterialConfiguration {

  private final KeyProperties keyProperties;

  public KeyMaterialConfiguration(KeyProperties properties) {
    this.keyProperties = properties;
    if (properties.getSignature().getKeypair() == null) {
      throw new IllegalStateException(UNDEFINED_KEYPAIR);
    }
  }

  @Bean
  public String issuer() {
    return keyProperties.getIssuer();
  }

  @Bean
  Algorithm hmac(KeyPair keyPair) {
    KeyProperties.SignatureProperties properties = keyProperties.getSignature();

    switch (properties.getAlgorithm()) {
      case PASSPHRASE:
        return Algorithm.HMAC256(properties.getSecret());
      case ELLIPTIC_CURVE:
        return Algorithm.ECDSA256((ECPublicKey) keyPair.getPublic(),
          (ECPrivateKey) keyPair.getPrivate());
      default:
        throw new IllegalArgumentException(String.format("Algorithm [%s] not supported",
          properties.getAlgorithm()));
    }
  }

  @Bean
  JWTVerifier verifier(KeypairReader reader) throws IOException {
    return JWT.require(hmac(keyPair(reader)))
        .withIssuer(issuer())
        .build();
  }

  @Bean
  public KeyPair keyPair(KeypairReader reader) throws IOException {
    return reader.loadKeys();
  }

  /**
   * Default key pair reader from the file system; to load a key pair from a different storage
   * (e.g., Vault) implement your custom {@link KeypairReader} and inject it as a {@literal
   * reader} bean.
   *
   * <p>This reader will interpret the {@literal keypair.priv,pub} properties as paths.
   *
   * <p>To use your custom {@link KeypairReader} implementation, define your bean as primary:
   *
   <pre>
       &#64;Bean &#64;Primary
       public KeypairReader reader() {
         return new KeypairReader() {
           &#64;Override
           public KeyPair loadKeys() throws KeyLoadException {
              // do something here
              return someKeypair;
           }
         };
   </pre>
   *
   * @return      a reader which will try and load the key pair from the filesystem.
   */
  @Bean
  public KeypairReader filereader() {
    KeyProperties.SignatureProperties props = keyProperties.getSignature();
    return new KeypairFileReader(
        props.getAlgorithm(),
        Paths.get(props.getKeypair().getPriv()),
        Paths.get(props.getKeypair().getPub()));
  }
}
