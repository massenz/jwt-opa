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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

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
  UserController controller;


  @Value("${db.admin:admin}")
  String adminUsername;


  @PostConstruct
  public void initDb() {
    String randomPwd = UUID.randomUUID().toString().substring(0, 10);
    User admin = new User(adminUsername, randomPwd, "SYSTEM");

    controller.create(admin)
        .doOnSuccess(responseEntity -> {
          if (responseEntity.getStatusCode().equals(HttpStatus.CREATED)) {
            log.info("Initializing DB with seed user ({}). Use the generated password: {}",
                adminUsername, randomPwd);
          } else {
            log.warn("Unexpected response ({}): {}", responseEntity.getStatusCode(),
                responseEntity.hasBody() ?
                    responseEntity.getBody().toString() :
                    "no details");
          }
        })
        .doOnError(ResponseStatusException.class, ex -> {
          if (ex.getStatus().equals(HttpStatus.CONFLICT)) {
            log.info("User [{}] already exists in database, use existing credentials",
                adminUsername);
          } else {
            log.error("Unexpected error when creating SYSTEM user", ex);
            System.exit(1);
          }
        })
        .subscribe();
  }
}
