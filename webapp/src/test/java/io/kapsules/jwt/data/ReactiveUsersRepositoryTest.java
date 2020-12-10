package io.kapsules.jwt.data;

import org.assertj.core.util.Lists;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static io.kapsules.jwt.data.User.RoleAuthority.USER;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class ReactiveUsersRepositoryTest {

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
    assertThat(all.size()).isEqualTo(3);

    all.forEach(System.out::println);
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
}
