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

import com.alertavert.opa.AbstractTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;

import static org.assertj.core.api.Assertions.assertThat;

class OpaServerPropertiesTest extends AbstractTestBase {

  @Autowired
  OpaServerProperties opaServerProperties;

  @Value("${opa.policy}")
  String policy;
  @Value("${opa.rule}")
  String rule;

  @Test
  public void endpoint() {
    String api = "foo";
    assertThat(opaServerProperties.endpoint(api))
        .isEqualTo(String.format("http://localhost:8181/v1/%s/%s", api, policy));
  }

  @Test
  public void policy() {
    assertThat(opaServerProperties.policyEndpoint())
        .isEqualTo(String.format("http://localhost:8181/v1/policies/%s", policy));
  }

  @Test
  public void data() {
    assertThat(opaServerProperties.dataEndpoint())
        .isEqualTo(String.format("http://localhost:8181/v1/data/%s", policy));
  }

  @Test
  public void authorizationEndpoint() {
    assertThat(opaServerProperties.authorization())
        .isEqualTo(String.format("http://localhost:8181/v1/data/%s/%s",policy, rule));
  }

  @Test
  public void testHeaders() {
    assertThat(opaServerProperties.getHeaders()).containsExactlyInAnyOrder(
        HttpHeaders.HOST, HttpHeaders.USER_AGENT, "x-test-header"
    );
  }
}
