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

package io.kapsules.jwt;

import org.testcontainers.containers.FixedHostPortGenericContainer;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public abstract class AbstractTestBaseWithOpaContainer extends AbstractTestBase {

  // TODO: Use @ContextConfiguration(initializers) to use the dynamically generated port.
  @Container
  protected static GenericContainer<?> opaServer = new FixedHostPortGenericContainer<>(
      "openpolicyagent/opa:0.25.2")
      .withExposedPorts(8181)
      .withFixedExposedPort(8181, 8181)
      .withCommand("run --server --addr :8181")
      .waitingFor(Wait.forHttp("/health"));
}
