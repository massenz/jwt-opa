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

import org.springframework.context.annotation.Bean;

import java.io.IOException;
import java.security.KeyPair;

/**
 * <H2>KeypairReader</H2>
 *
 * <p>Classes implementing this interface will retrieve keys from their storage for use with the
 * application.
 *
 * @author M. Massenzio, 2022-01-24
 */
public interface KeypairReader {
  KeyPair loadKeys() throws KeyLoadException;
}
