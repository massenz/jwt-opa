/*
 * Copyright (c) 2021 kapsules.io.  All rights reserved.
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
 */

package io.kapsules.jwt;

import io.kapsules.jwt.data.ReactiveUsersRepository;
import io.kapsules.jwt.data.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.UUID;

/**
 * Initializes the DB with a seed `admin` user and a random password, if doesn't already exist.
 */
@Profile("debug")
@Slf4j
@Component
public class DbInit {
  @Autowired
  ReactiveUsersRepository repository;

  @Autowired
  PasswordEncoder encoder;

  @Value("${db.admin:admin}")
  String adminUsername;


  @PostConstruct
  public void initDb() {
    String randomPwd = UUID.randomUUID().toString().substring(0, 10);
    String encodedPwd = encoder.encode(randomPwd);

    repository.findByUsername(adminUsername)
        .hasElement()
        .map(exists -> {
              if (!exists) {
                log.info("Initializing DB with seed user ({}). Use the generated password: {}",
                    adminUsername, randomPwd);
                repository.save(new User(adminUsername, encodedPwd, "SYSTEM")).subscribe();
              }
              return exists;
            })
        .subscribe();
  }
}
