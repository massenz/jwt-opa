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

import com.alertavert.opa.thirdparty.PemUtils;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.helpers.MessageFormatter;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.alertavert.opa.Constants.ERROR_CANNOT_READ_KEY;

/**
 * <H2>KeypairFileReader</H2>
 *
 * <p>Loads a Private/Public keypair from the filesystem; the actual format of the keys should
 * match the one expected by the {@link #algorithm}; we use here the {@link PemUtils} utility
 * classes.
 *
 * <p>For an example as to how to generate a pair of
 * {@link com.alertavert.opa.configuration.KeysProperties.AlgorithmType#EC Elliptic Curve}
 * cryptography keys, see the {@literal keygen.sh} script.
 *
 * @see PemUtils
 * @author M. Massenzio, 2022-01-24
 */
@Slf4j
public record KeypairFileReader(
    String algorithm,
    Path secretKeyPath,
    Path publicKeyPath
) implements KeypairReader {
  @Override
  public Mono<KeyPair> loadKeys() throws KeyLoadException {
    return Mono.just(new KeyPair(loadPublicKey(), loadPrivateKey()));
  }

  private PrivateKey loadPrivateKey() {
    log.info("Reading private key from file {}", secretKeyPath.toAbsolutePath());
    PrivateKey pk;
    try {
      pk = PemUtils.readPrivateKeyFromFile(secretKeyPath.toString(), algorithm);
    } catch (IOException e) {
      throw new KeyLoadException(e);
    }
    if (pk == null) {
      log.error(ERROR_CANNOT_READ_KEY, secretKeyPath, algorithm);
      throw new KeyLoadException(
          MessageFormatter.format(ERROR_CANNOT_READ_KEY, secretKeyPath, algorithm).getMessage());
    }
    log.info("Read private key, format: {}", pk.getFormat());
    return pk;
  }

  private PublicKey loadPublicKey() {
    log.info("Reading public key from file {}", publicKeyPath.toAbsolutePath());
    PublicKey pk;
    try {
      pk = PemUtils.readPublicKeyFromFile(publicKeyPath.toString(), algorithm);
    } catch (IOException e) {
      throw new KeyLoadException(e);
    }
    if (pk == null) {
      log.error(ERROR_CANNOT_READ_KEY, publicKeyPath, algorithm);
      throw new KeyLoadException(
          MessageFormatter.format(ERROR_CANNOT_READ_KEY, publicKeyPath, algorithm).getMessage());
    }
    log.info("Read public key, format: {}", pk.getFormat());
    return pk;
  }
}
