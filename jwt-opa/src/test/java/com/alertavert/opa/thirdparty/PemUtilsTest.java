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

package com.alertavert.opa.thirdparty;

import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.alertavert.opa.configuration.KeysProperties.AlgorithmType.EC;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PemUtilsTest {

  @Test
  public void readKeys() throws IOException {
    PrivateKey pk = PemUtils.readPrivateKeyFromFile("testdata/test.pem", EC.name());
    PublicKey pubk = PemUtils.readPublicKeyFromFile("testdata/test-pub.pem", EC.name());
    assertThat(pk).isNotNull();
    assertThat(pubk).isNotNull();
  }

  @Test
  public void readKeysThrowsNotFound() throws IOException {
    assertThrows(FileNotFoundException.class, () ->
      PemUtils.readPublicKeyFromFile("bogus.pem", EC.name()));
  }

  @Test
  public void nonExistAlgoReturnsNull() throws IOException {
    PrivateKey pk = PemUtils.readPrivateKeyFromFile("testdata/test.pem", "foo-algo");
    assertThat(pk).isNull();
    PublicKey pubk = PemUtils.readPublicKeyFromFile("testdata/test-pub.pem", "foo-algo");
    assertThat(pubk).isNull();
  }

}
