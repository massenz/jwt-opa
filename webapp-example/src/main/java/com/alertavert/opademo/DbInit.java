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

package com.alertavert.opademo;

import com.alertavert.opademo.api.UserController;
import com.alertavert.opademo.data.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import javax.annotation.PostConstruct;
import java.util.UUID;

/**
 * Initializes the DB with a seed `admin` user and a random password, if it doesn't already exist.
 */
@Slf4j
@Component
public class DbInit {
  private final UserController controller;

  @Value("${db.admin.username:admin}")
  String adminUsername;

  @Value("${db.admin.password}")
  String adminPassword;

  public DbInit(UserController controller) {
    this.controller = controller;
  }


  @PostConstruct
  public void initDb() {
    if (!StringUtils.hasText(adminPassword)) {
      adminPassword = UUID.randomUUID().toString().substring(0, 10);
      log.info("Initializing DB with seed user ({}). Use the generated password: {}",
          adminUsername, adminPassword);
    }
    User admin = new User(adminUsername, adminPassword, "SYSTEM");
    log.info("Creating admin user: {}", adminUsername);
    controller.create(admin)
        .doOnSuccess(responseEntity -> {
          if (!responseEntity.getStatusCode().equals(HttpStatus.CREATED)) {
            log.warn("Unexpected response ({}): {}", responseEntity.getStatusCode(),
                responseEntity.hasBody() ?
                    responseEntity.getBody().toString() :
                    "no details");
          }
        })
        .doOnError(ResponseStatusException.class, ex -> {
          if (ex.getStatusCode().equals(HttpStatus.CONFLICT)) {
            log.info("User [{}] already exists in database, use existing credentials",
                adminUsername);
          } else {
            log.error("Unexpected error when creating SYSTEM user", ex);
            System.exit(1);
          }
        })
        .onErrorComplete()
        .subscribe();
  }
}
