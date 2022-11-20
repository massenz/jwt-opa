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

import com.alertavert.opa.configuration.KeyMaterialConfiguration;
import com.alertavert.opa.security.SecretsResolver;
import com.alertavert.opa.security.crypto.KeyLoadException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.lang.NonNull;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.ResourceExistsException;

import java.net.URI;

import static com.alertavert.opa.configuration.KeysProperties.AlgorithmType.EC;
import static com.alertavert.opa.configuration.KeysProperties.AlgorithmType.PASSPHRASE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * <H2>AwsSecretsManagerResolverTest</H2>
 *
 * @author M. Massenzio, 2022-10-26
 */
@SpringBootTest(classes = {
    AwsClientConfiguration.class,
    KeyMaterialConfiguration.class
})
@ActiveProfiles(profiles = {"test", "aws"})
@ContextConfiguration(initializers = {AwsSecretsManagerResolverTest.Initializer.class})
class AwsSecretsManagerResolverTest {

  @Autowired
  SecretsResolver resolver;
  @Value("${keys.name}")
  String secretName;

  public static class Initializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    @Container
    public static LocalStackContainer AWS_LOCAL =
        new LocalStackContainer(DockerImageName.parse("localstack/localstack:1.2"))
            .withServices(LocalStackContainer.Service.SECRETSMANAGER);

    @Override
    public void initialize(@NonNull ConfigurableApplicationContext context) {
      AWS_LOCAL.start();
      URI endpoint = AWS_LOCAL.getEndpointOverride(LocalStackContainer.Service.SECRETSMANAGER);
      TestPropertyValues.of("aws.endpoint:" + endpoint)
          .applyTo(context.getEnvironment());

      SecretsManagerClient client = SecretsManagerClient.builder()
          .region(Region.US_WEST_2)
          .credentialsProvider(ProfileCredentialsProvider.create())
          .endpointOverride(endpoint)
          .build();
      try {
        var response = client.createSecret(CreateSecretRequest.builder()
            .name("test-secret")
            .secretString("test-secret-value")
            .build());
      } catch (ResourceExistsException ex) {
        // ignore
      }
    }
  }

  @BeforeEach
  public void setup() {
    assertThat(resolver).isNotNull();
  }

  @Test
  void getSecret() {
    String secret = resolver.getSecret(secretName).block();
    assertThat(secret).isNotNull();
    assertThat(secret).isEqualTo("test-secret-value");
  }

  @Test
  void getSecretNotFound() {
    assertThrows(KeyLoadException.class, () -> resolver.getSecret("fake-name").block());
  }
}
