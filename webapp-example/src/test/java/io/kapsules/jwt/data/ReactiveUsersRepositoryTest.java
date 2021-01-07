/*
 * Copyright (c) 2020 kapsules.io.  All rights reserved.
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

package io.kapsules.jwt.data;

import io.kapsules.jwt.Constants;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.List;

import static io.kapsules.jwt.RoleAuthority.USER;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@ContextConfiguration(initializers = {ReactiveUsersRepositoryTest.Initializer.class})
class ReactiveUsersRepositoryTest {

  private final static MongoDBContainer mongoDBContainer = new MongoDBContainer(
      DockerImageName.parse(Constants.IMAGE_NAME));

  @Autowired
  ReactiveUsersRepository repository;

  @BeforeEach
  void setup() {
    repository.deleteAll().block();
    repository.saveAll(
        Lists.list(
            new User("alice", "foo", "USER"),
            new User("bob", "bar", "USER"),
            new User("charlie", "baz", "ADMIN")
        )
    ).collectList().block();
  }

  @Test
  void insert() {
    User u = new User("david", "zekret", "ARTIST");
    User saved = repository.save(u).block();
    assertThat(saved).isEqualTo(u);

    User found = repository.findByUsername("david").block();
    assertThat(found).isEqualTo(u);
  }

  @Test
  void findAll() {
    List<User> all = repository.findAll().collectList().block();
    assertThat(all).isNotNull();
    assertThat(all.size()).isEqualTo(3);

    all.forEach(user -> assertThat(user.getUsername()).isIn("alice", "bob", "charlie"));
  }

  @Test
  void findByRole() {
    List<User> found = repository.findAllByRolesContains(USER).collectList().block();
    assertThat(found).isNotNull();
    assertThat(found.size()).isEqualTo(2);
    assertThat(found).containsAll(
        Lists.list(
            new User("alice", "foo", "USER"),
            new User("bob", "bar", "USER")
        )
    );
  }

  static class Initializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    public void initialize(ConfigurableApplicationContext configurableApplicationContext) {
      mongoDBContainer.start();
      TestPropertyValues.of(
          "db.port=" + mongoDBContainer.getFirstMappedPort(),
          "db.server=" + mongoDBContainer.getHost(),
          "db.name=test-db"
      ).applyTo(configurableApplicationContext.getEnvironment());
    }
  }
}
