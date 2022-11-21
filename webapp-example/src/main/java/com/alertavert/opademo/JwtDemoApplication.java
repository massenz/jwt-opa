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

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.mongodb.repository.config.EnableReactiveMongoRepositories;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication
@EnableConfigurationProperties
@EnableReactiveMongoRepositories(basePackages = "com.alertavert.opademo")
@ComponentScan(basePackages = {"com.alertavert.opa", "com.alertavert.opademo"})
@EnableSwagger2
@Slf4j
public class JwtDemoApplication {

  public static void main(String[] args) {
    try {
      SpringApplication.run(JwtDemoApplication.class, args);
    } catch (Exception ex) {
      // Suppresses the insane amount of stacktrace Spring emits, and only logs the
      // cause of the error.
      log.error("Could not start application: {}", ex.getMessage());
    }
  }
}
