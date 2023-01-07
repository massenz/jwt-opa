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

package com.alertavert.opa.security.aws;

import com.alertavert.opa.security.crypto.KeypairReader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;

import java.security.KeyPair;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * <H2>AwsSecretsKeypairReaderTest</H2>
 *
 * @author M. Massenzio, 2022-10-28
 */
@SpringBootTest(classes = {
    AwsClientConfiguration.class,
})
@ActiveProfiles(profiles = {"test", "aws"})
@ContextConfiguration(initializers = {AwsSecretsManagerResolverTest.Initializer.class})
class AwsSecretsKeypairReaderTest {

  @Autowired
  SecretsManagerClient secretsManagerClient;

  String keypairName = "test-keypair";
  String secret = """
    {
      "priv": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYEIUVkTtwBilNcNoEzsP3jdslIlOtXQ5pByuzxhLJTChRANCAAS+gitL0EgxyFCvdT6rJ39DbCrLLwLReTA5OXahcIEeCBygfyh35H8T9r9uHszSOCpAk1QQMuhqURzyWEaKjk92",
      "pub": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvoIrS9BIMchQr3U+qyd/Q2wqyy8C0XkwOTl2oXCBHggcoH8od+R/E/a/bh7M0jgqQJNUEDLoalEc8lhGio5Pdg=="
    }
  """;
  String priv = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYEIUVkTtwBilNcNoEzsP3jdslIlO"
      + "tXQ5pByuzxhLJTChRANCAAS+gitL0EgxyFCvdT6rJ39DbCrLLwLReTA5OXahcIEeCBygfyh35H8T9r9uHs"
      + "zSOCpAk1QQMuhqURzyWEaKjk92";


  @BeforeEach
  void setUp() {
    secretsManagerClient.createSecret(CreateSecretRequest.builder()
        .name(keypairName)
        .secretString(secret)
        .build());
  }

  @Test
  public void getSecret() {
    KeypairReader reader = new AwsSecretsKeypairReader(
        new AwsSecretsManagerResolver(secretsManagerClient), keypairName);
    KeyPair keyPair = reader.loadKeys().block();
    assertNotNull(keyPair);
    assertThat(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()))
        .isEqualTo(priv);
  }
}
