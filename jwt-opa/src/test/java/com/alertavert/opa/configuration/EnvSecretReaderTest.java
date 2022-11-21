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

package com.alertavert.opa.configuration;

import com.alertavert.opa.security.EnvSecretResolver;
import com.alertavert.opa.security.SecretsResolver;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import javax.annotation.Resource;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <H2>AwsSecretsKeypairReaderTest</H2>
 *
 * <p>It is incredibly difficult (and, as of JDK 17, virtually impossible) to set an
 * arbitrary env var, even for testing purposes; all the various hacks that used to
 * work (usually via Reflection) have been essentially closed off.
 *
 * <p>We use here the {@literal HOME} env var just because it is pretty much guaranteed
 * to be defined in every environment, but it definitely makes this test flakier than we'd like
 * to.
 *
 * @author M. Massenzio, 2022-10-28
 */
@SpringBootTest(classes = {
    KeyMaterialConfiguration.class,
})
@ActiveProfiles(profiles = {"test"})
@TestPropertySource(properties = {
    "keys.algorithm = passphrase",
    "keys.location = env",
    "keys.name = HOME"
})
class EnvSecretReaderTest {

  @Resource
  KeyMaterialConfiguration configuration;
  @Resource
  Algorithm hmac;


  @Test
  public void getSecret() {
    assertThat(configuration).isNotNull();
    assertThat(hmac).isNotNull();

    SecretsResolver resolver = configuration.secretsResolver();
    assertThat(resolver.getClass()).isEqualTo(EnvSecretResolver.class);
    assertThat(resolver.getSecret("HOME").block(Duration.ofMillis(5))).isEqualTo(
        System.getenv("HOME"));
  }
}
