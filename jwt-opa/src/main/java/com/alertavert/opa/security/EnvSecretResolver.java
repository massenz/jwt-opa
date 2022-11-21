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

import reactor.core.publisher.Mono;

/**
 * <H2>EnvSecretResolver</H2>
 *
 * <p>Reads a secret from an environment variable.
 *
 * <p>In all its triviality, this class is virtually untestable, due to
 * the JVM limitations on setting test env vars (see {@literal EnvSecretReaderTest}).
 *
 * @author M. Massenzio, 2022-11-19
 */
public class EnvSecretResolver implements SecretsResolver {
  @Override
  public Mono<String> getSecret(String secretName) {
    return Mono.justOrEmpty(System.getenv(secretName));
  }
}
