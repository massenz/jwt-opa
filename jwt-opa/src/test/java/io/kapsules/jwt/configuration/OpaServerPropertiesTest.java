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
    assertThat(ep).isEqualTo("http://localhost:8181/v1/foo/kapsules");
  }

  @Test
  public void policy() {
    assertThat(opaServerProperties.policyEndpoint())
        .isEqualTo("http://localhost:8181/v1/policies/kapsules");
  }

  @Test
  public void data() {
    assertThat(opaServerProperties.dataEndpoint())
        .isEqualTo("http://localhost:8181/v1/data/kapsules");
  }

  @Test
  public void authorizationEndpoint() {
    assertThat(opaServerProperties.authorization())
        .isEqualTo("http://localhost:8181/v1/data/kapsules/allow");
  }
}
