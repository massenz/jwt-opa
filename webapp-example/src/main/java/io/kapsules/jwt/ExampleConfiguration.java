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

import com.mongodb.MongoClientSettings;
import com.mongodb.ServerAddress;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractReactiveMongoConfiguration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.List;

@Slf4j
@Configuration
public class ExampleConfiguration extends AbstractReactiveMongoConfiguration {

  @Value("${db.port:27017}")
  Integer port;

  @Value("${db.server:localhost}")
  String server;

  @Value("${db.name:opa-demo}")
  String dbName;

  @Bean
  PasswordEncoder encoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Override
  public void configureClientSettings(MongoClientSettings.Builder builder) {
    List<ServerAddress> cluster = Collections.singletonList(
        new ServerAddress(server, port));
    log.info("Connecting to MongoDB: {} - DB: {}", cluster, getDatabaseName());
    builder.applyToClusterSettings(settings -> {
      settings.hosts(cluster);
    });
  }

  @Override
  protected String getDatabaseName() {
    return dbName;
  }

  @Override
  protected boolean autoIndexCreation() { return true; }
}
