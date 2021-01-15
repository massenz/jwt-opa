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
