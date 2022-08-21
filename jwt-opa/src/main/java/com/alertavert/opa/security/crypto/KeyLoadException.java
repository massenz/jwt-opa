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

/**
 * <H2>KeyLoadException</H2>
 *
 * <p>Thrown when attempting to retrieve keys causes a failure.
 *
 * @author M. Massenzio, 2022-01-24
 */
public class KeyLoadException extends RuntimeException {
  public KeyLoadException(String reason) {
    super(reason);
  }

  public KeyLoadException(Throwable throwable) {
    super(throwable);
  }
}
