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

package com.alertavert.opa.security;

import lombok.SneakyThrows;
import reactor.core.publisher.Mono;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Collectors;

/**
 * <H2>FileSecretResolver</H2>
 *
 * <p>Reads the secret from a file, if it exists.
 *
 * @author M. Massenzio, 2022-11-19
 */
public class FileSecretResolver implements SecretsResolver {
  @SneakyThrows
  @Override
  public Mono<String> getSecret(String secretName) {
    Path secretFile = Paths.get(secretName);
    if (secretFile.toFile().exists()) {
      BufferedReader reader = new
          BufferedReader(new FileReader(secretFile.toFile()));
      return Mono.just(reader.lines().collect(Collectors.joining()));
    }
    return Mono.empty();
  }
}
