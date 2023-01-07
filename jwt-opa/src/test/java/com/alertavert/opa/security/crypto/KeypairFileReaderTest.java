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

package com.alertavert.opa.security.crypto;

import com.alertavert.opa.AbstractTestBase;
import com.alertavert.opa.configuration.TokensProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.nio.file.Paths;
import java.security.KeyPair;

import static com.alertavert.opa.configuration.KeysProperties.AlgorithmType.EC;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * <H2>KeypairFileReaderTest</H2>
 *
 * @author M. Massenzio, 2022-01-24
 */
class KeypairFileReaderTest extends AbstractTestBase {

  KeypairFileReader reader;

  @Autowired
  TokensProperties properties;

  @BeforeEach
  public void setup() {
    reader = new KeypairFileReader(EC.name(),
        Paths.get("testdata/test.pem"), Paths.get("testdata/test-pub.pem"));
  }

  @Test
  void loadKeys() {
    KeyPair pair = reader.loadKeys().block();
    assertThat(pair).isNotNull();
    assertThat(pair.getPrivate()).isNotNull();
    assertThat(pair.getPublic()).isNotNull();

    assertThat(pair.getPublic().getAlgorithm()).isEqualTo(EC.name());
  }

  @Test
  void nonExistKeysThrows() {
    KeypairReader reader = new KeypairFileReader(EC.name(),
        Paths.get("/etc/bogus/none.pub"), Paths.get("/etc/bogus/none.pem"));
    assertThrows(KeyLoadException.class, reader::loadKeys);
  }
}
