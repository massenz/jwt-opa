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

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * <h2>KeysPropertiers</h2>
 *
 * @author M. Massenzio, 202-11-19
 */
@Data
@ConfigurationProperties(prefix = "keys")
public class KeysProperties {

  /**
   * <h3>Location for the signing secret</h3>
   *
   * <p>Possible values are:
   *
   * <li>{@literal env}: only available for PASSPHRASE, env var name which contains
   * the signing secret</li>
   * <li>{@literal file}: only valid if algorithm is PASSPHRASE, the file is simply read</li>
   * <li>{@literal keypair}: the filename without extension, to which `.pem` and `.pub`
   * will be added</li>
   * <li>{@literal aws_secret}: name of AWS SecretsManager secret</li>
   * <li>{@literal vault_path}: path in HashiCorp Vault</li>
   *
   * <p>File paths can be absolute or relative.
   *
   * <p>For a {@link AlgorithmType#PASSPHRASE passphrase}, the secret is simply read from
   * SecretsManager/Vault, the {@link AlgorithmType#EC keypair} keypair is
   * stored as a JSON-formatted secret, with two keys: "priv" and "pub" (see
   * {@link com.alertavert.opa.security.aws.AwsSecretsKeypairReader.SecretKeys}).
   */
  enum KeyLocation {
    env, file, keypair, awsSecret, vaultPath
  }

  public enum AlgorithmType {
    /** Plaintext secret */
    PASSPHRASE,
    /** Elliptic Curve cryptography */
    EC
  }

  AlgorithmType algorithm;
  KeyLocation location;
  String name;
}
