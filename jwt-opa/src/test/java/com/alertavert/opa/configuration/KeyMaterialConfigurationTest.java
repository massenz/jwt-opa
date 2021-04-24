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
import com.alertavert.opa.Constants;
import com.alertavert.opa.jwt.JwtTokenProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;
import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;

class KeyMaterialConfigurationTest extends AbstractTestBase {

  @Autowired
  KeyMaterialConfiguration configuration;

  @Value("${tokens.issuer}")
  private String issuer;

  @Test
  void issuer() {
    assertThat(configuration.issuer()).isEqualTo(issuer);
  }

  @Test
  void hmac() throws IOException {
    KeyPair pair = configuration.keyPair();
    assertThat(pair).isNotNull();
    Algorithm hmac = configuration.hmac(pair);
    assertThat(hmac).isNotNull();
    assertThat(hmac.getName()).isEqualTo("ES256");
  }

  @Test
  void verifier() throws IOException {
    JWTVerifier verifier = configuration.verifier();
    assertThat(verifier).isNotNull();
  }

  @Test
  void keyPair() throws IOException {
    KeyPair pair = configuration.keyPair();
    assertThat(pair).isNotNull();
    assertThat(pair.getPrivate().getFormat()).isEqualTo("PKCS#8");
    assertThat(pair.getPrivate().getAlgorithm()).isEqualTo(Constants.ELLIPTIC_CURVE);
  }

  @Test
  void signVerify() throws IOException {
    KeyPair pair = configuration.keyPair();
    Algorithm hmac = configuration.hmac(pair);

    String token = JWT.create()
        .withIssuer(issuer)
        .withSubject("test-user")
        .withClaim(JwtTokenProvider.ROLES, Lists.list("TEST"))
        .sign(hmac);

    JWTVerifier verifier = configuration.verifier();
    assertThat(verifier.verify(token)).isNotNull();
  }
}
