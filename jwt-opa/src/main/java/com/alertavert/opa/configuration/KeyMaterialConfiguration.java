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

import com.alertavert.opa.security.EnvSecretResolver;
import com.alertavert.opa.security.FileSecretResolver;
import com.alertavert.opa.security.NoopKeypairReader;
import com.alertavert.opa.security.NoopSecretResolver;
import com.alertavert.opa.security.SecretsResolver;
import com.alertavert.opa.security.aws.AwsSecretsKeypairReader;
import com.alertavert.opa.security.aws.AwsSecretsManagerResolver;
import com.alertavert.opa.security.crypto.KeyLoadException;
import com.alertavert.opa.security.crypto.KeypairFileReader;
import com.alertavert.opa.security.crypto.KeypairReader;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

import javax.annotation.PostConstruct;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static com.alertavert.opa.Constants.PEM_EXT;
import static com.alertavert.opa.Constants.PUB_EXT;

@Slf4j
@Configuration
@EnableConfigurationProperties({
    KeysProperties.class,
    TokensProperties.class
})
@RequiredArgsConstructor
public class KeyMaterialConfiguration {

  private final KeysProperties keyProperties;

  /**
   * AWS SecretsManager client, will only be configured by the
   * {@link com.alertavert.opa.security.aws.AwsClientConfiguration AWS Configuration} if the
   * {@literal aws} profile is active.
   */
  @Autowired(required = false)
  SecretsManagerClient secretsManagerClient;

  @PostConstruct
  private void log() {
    log.info("Configuring key material, algorithm = {}, location = {}",
        keyProperties.algorithm, keyProperties.location);
  }

  @Bean
  SecretsResolver secretsResolver() {
    return switch (keyProperties.getLocation()) {
      case env -> new EnvSecretResolver();
      case file -> new FileSecretResolver();
      case keypair -> new NoopSecretResolver();
      case awsSecret -> new AwsSecretsManagerResolver(secretsManagerClient);
      case vaultPath -> throw new UnsupportedOperationException("Support for Vault not "
          + "implemented yet");
    };
  }

  @Bean
  KeypairReader keypairReader() {
    return switch (keyProperties.getLocation()) {
      case env, file -> new NoopKeypairReader();
      case keypair -> new KeypairFileReader(keyProperties.algorithm.name(),
          Path.of(keyProperties.name + PEM_EXT), Path.of(keyProperties.name + PUB_EXT));
      case awsSecret -> new AwsSecretsKeypairReader(secretsResolver(), keyProperties.name);
      case vaultPath -> throw new UnsupportedOperationException("Support for Vault not "
          + "implemented yet");
    };
  }


  @Bean
  Algorithm hmac(SecretsResolver resolver, KeypairReader reader) {
    return switch (keyProperties.getAlgorithm()) {
      case PASSPHRASE -> {
        log.warn("Using insecure passphrase signing secret, name = {}", keyProperties.name);
        String passphrase = resolver.getSecret(keyProperties.getName()).block();
        if (passphrase == null) {
          log.error("Could not resolve secret {}, with SecretsResolver {}",
              keyProperties.name, resolver.getClass().getSimpleName());
          throw new IllegalArgumentException("Signing secret cannot be resolved");
        }
        yield  Algorithm.HMAC256(passphrase);
      }
      case EC -> {
        KeyPair keyPair = reader.loadKeys().block();
        if (keyPair == null) {
          throw new KeyLoadException("Cannot load keypair " + keyProperties.name);
        }
        yield Algorithm.ECDSA256((ECPublicKey) keyPair.getPublic(),
            (ECPrivateKey) keyPair.getPrivate());
      }
    };
  }
}
