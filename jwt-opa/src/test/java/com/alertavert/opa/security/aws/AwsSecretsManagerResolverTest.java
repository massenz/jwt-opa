/*
 * Copyright (c) 2022 AlertAvert.com.  All rights reserved.
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

package com.alertavert.opa.security.aws;

import com.alertavert.opa.JwtOpa;
import com.alertavert.opa.configuration.JwtSecurityConfiguration;
import com.alertavert.opa.configuration.KeyMaterialConfiguration;
import com.alertavert.opa.configuration.OpaServerConfiguration;
import com.alertavert.opa.security.crypto.KeyLoadException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.lang.NonNull;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.containers.wait.strategy.WaitStrategy;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * <H2>AwsSecretsManagerResolverTest</H2>
 *
 * @author M. Massenzio, 2022-10-26
 */
@SpringBootTest(classes = {
    AwsClientConfiguration.class,
})
@ActiveProfiles(profiles = {"test", "aws"})
@ContextConfiguration(initializers = {AwsSecretsManagerResolverTest.Initializer.class})
class AwsSecretsManagerResolverTest {

  @Autowired
  SecretsManagerClient client;

  @Autowired
  String keypairSecretName;

  AwsSecretsManagerResolver resolver;

  public static class Initializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    @Container
    public static LocalStackContainer AWS_LOCAL =
        new LocalStackContainer(DockerImageName.parse("localstack/localstack:1.2"))
            .withServices(LocalStackContainer.Service.SECRETSMANAGER);

    @Override
    public void initialize(@NonNull ConfigurableApplicationContext context) {
      AWS_LOCAL.start();
      TestPropertyValues.of(
              "aws.region:" + AWS_LOCAL.getRegion(),
              "aws.profile:default",
              "aws.endpoint:" + AWS_LOCAL.getEndpointOverride(LocalStackContainer.Service.SECRETSMANAGER),
              "aws.keypair.secret_name:test-secret"
          )
          .applyTo(context.getEnvironment());
    }
  }

  @BeforeEach
  public void setup() {
    resolver = new AwsSecretsManagerResolver(client);
    assertThat(resolver).isNotNull();
  }

  @Test
  void getSecret() {
    client.createSecret(CreateSecretRequest.builder()
            .name(keypairSecretName)
        .secretString("test-secret-value")
        .build());

    String secret = resolver.getSecret(keypairSecretName).block();
    assertThat(secret).isNotNull();
    assertThat(secret).isEqualTo("test-secret-value");
  }

  @Test
  void getSecretNotFound() {
    assertThrows(KeyLoadException.class, () -> resolver.getSecret("not-found").block());
  }
}
