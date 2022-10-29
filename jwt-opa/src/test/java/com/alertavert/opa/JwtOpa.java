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

package com.alertavert.opa;

import com.alertavert.opa.security.crypto.KeyLoadException;
import com.alertavert.opa.security.crypto.KeypairReader;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.KeyPair;

import static com.alertavert.opa.Constants.PASSPHRASE;

/**
 * Simple marker class to hold Spring Boot annotations.
 */
@Profile("test")
@SpringBootApplication
public class JwtOpa {

  @Bean
  PasswordEncoder encoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  // A trivial reader that simply tells the application to use the passphrase stored in the
  // tokens.secret property.
  @Bean
  KeypairReader keypairReader() {
    return new KeypairReader() {
      @Override
      public KeyPair loadKeys() throws KeyLoadException {
        return null;
      }

      @Override
      public String algorithm() {
        return PASSPHRASE;
      }
    };
  }
}
