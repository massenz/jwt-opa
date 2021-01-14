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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import io.kapsules.jwt.thirdparty.PemUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

@Slf4j
@Configuration
@EnableConfigurationProperties(KeyProperties.class)
public class KeyMaterialConfiguration {

  public static final String ELLIPTIC_CURVE = "EC";
  public static final String PASSPHRASE = "SECRET";

  private final KeyProperties secrets;

  public KeyMaterialConfiguration(KeyProperties secrets) {
    this.secrets = secrets;
  }

  @Bean
  public String issuer() {
    return secrets.getIssuer();
  }

  @Bean
  Algorithm hmac(KeyPair keyPair) {
    switch (secrets.getAlgorithm()) {
      case PASSPHRASE:
        return Algorithm.HMAC256(secrets.getSecret());
      case ELLIPTIC_CURVE:
        return Algorithm.ECDSA256((ECPublicKey) keyPair.getPublic(),
          (ECPrivateKey) keyPair.getPrivate());
      default:
        throw new IllegalArgumentException(String.format("Algorithm [%s] not supported",
          secrets.getAlgorithm()));
    }
  }

  @Bean
  JWTVerifier verifier() throws IOException {
    return JWT.require(hmac(keyPair()))
        .withIssuer(issuer())
        .build();
  }

  @Bean
  public KeyPair keyPair() throws IOException {
    return new KeyPair(loadPublicKey(), loadPrivateKey());
  }

  private PrivateKey loadPrivateKey() throws IOException {
    Path p = Paths.get(secrets.getKeypair().getPriv());
    log.info("Reading private key from file {}", p.toAbsolutePath());

    PrivateKey pk = PemUtils.readPrivateKeyFromFile(p.toString(), secrets.getAlgorithm());
    if (pk == null) {
      log.error("Could not read Public key");
      throw new IllegalStateException(
          String.format("Not a valid EC Private key file %s", p.toAbsolutePath()));
    }
    log.info("Read private key, format: {}", pk.getFormat());
    return pk;
  }

  private PublicKey loadPublicKey() throws IOException {
    Path p = Paths.get(secrets.getKeypair().getPub());
    log.info("Reading public key from file {}", p.toAbsolutePath());

    PublicKey pk = PemUtils.readPublicKeyFromFile(p.toString(), secrets.getAlgorithm());
    if (pk == null) {
      log.error("Could not read Public key");
      throw new IllegalStateException(
          String.format("Not a valid EC Public key file %s", p.toAbsolutePath()));
    }
    log.info("Read public key, format: {}", pk.getFormat());
    return pk;
  }
}
