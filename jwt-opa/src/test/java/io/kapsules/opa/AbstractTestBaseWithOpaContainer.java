/*
 * Copyright (c) 2021 kapsules.io.  All rights reserved.
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

package io.kapsules.opa;

import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@ContextConfiguration(initializers = {AbstractTestBaseWithOpaContainer.Initializer.class})
public abstract class AbstractTestBaseWithOpaContainer extends AbstractTestBase {

  public static final Integer opaServerExposedPort = 8181;

  @Container
  protected static GenericContainer<?> opaServer = new GenericContainer<>(
      "openpolicyagent/opa:0.25.2")
      .withExposedPorts(opaServerExposedPort)
      .withCommand(String.format("run --server --addr :%d", opaServerExposedPort))
      .waitingFor(Wait.forHttp("/health"));

  public static class Initializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    public void initialize(ConfigurableApplicationContext configurableApplicationContext) {
      opaServer.start();
      TestPropertyValues.of(
          String.format("opa.server=%s:%d", opaServer.getHost(), opaServer.getFirstMappedPort())
      ).applyTo(configurableApplicationContext.getEnvironment());
    }
  }
}
