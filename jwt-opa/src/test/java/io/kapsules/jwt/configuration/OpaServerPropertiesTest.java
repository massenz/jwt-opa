package io.kapsules.jwt.configuration;

import io.kapsules.jwt.AbstractTestBase;
import io.kapsules.jwt.JwtOpa;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

class OpaServerPropertiesTest extends AbstractTestBase {

  @Autowired
  OpaServerProperties opaServerProperties;

  @Test
  public void endpoint() {
    String ep = opaServerProperties.endpoint("foo");
    assertThat(ep).isEqualTo("http://opa-test.kapsules.io/v1/foo/test-policy");
  }

  @Test
  public void policy() {
    assertThat(opaServerProperties.policyEndpoint())
        .isEqualTo("http://opa-test.kapsules.io/v1/policies/test-policy");
  }

  @Test
  public void data() {
    assertThat(opaServerProperties.dataEndpoint())
        .isEqualTo("http://opa-test.kapsules.io/v1/data/test-policy");
  }

  @Test
  public void authorizationEndpoint() {
    assertThat(opaServerProperties.authorization())
        .isEqualTo("http://opa-test.kapsules.io/v1/data/test-policy/allow");
  }
}
