
package com.alertavert.opademo.api;

import com.alertavert.opademo.JwtDemoApplication;
import com.alertavert.opademo.data.ReactiveUsersRepository;
import com.alertavert.opademo.data.ReactiveUsersRepositoryTest;
import com.alertavert.opademo.data.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;


@SpringBootTest(classes = {JwtDemoApplication.class},
                webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@ContextConfiguration(initializers = {ReactiveUsersRepositoryTest.Initializer.class})
class LoginControllerTest {
  @Autowired
  WebTestClient client;

  @Autowired
  ReactiveUsersRepository repository;

  @Autowired
  PasswordEncoder encoder;

  User bob, pete;

  /**
   * Takes a User with the password field in plaintext, and converts into a hashed one, then saves
   * it to the DB.
   *
   * @param user
   * @return the same user, but with a hashed password
   */
  private Flux<User> hashPasswordAndSave(User user) {
    return hashPasswordAndSaveAll(List.of(user));
  }

  private Flux<User> hashPasswordAndSaveAll(List<User> users) {
    return repository.saveAll(
        users.stream()
            .map(u -> User.withPassword(u, encoder.encode(u.getPassword())))
            .collect(Collectors.toList()));
  }

  @BeforeEach
  void setUp() {
    repository.deleteAll().block();
    bob = new User("bob", "zek", "USER");
    pete = new User("pete", "123456", "USER");
    hashPasswordAndSaveAll(List.of(bob, pete)).subscribe();
  }

  @Test
  public void validUserSuccessfullyLogin() {
    JwtController.ApiToken apiToken = client.get()
        .uri("/login")
        .header(HttpHeaders.AUTHORIZATION, LoginController.credentialsToHeader("bob:zek").block())
        .exchange()
        .expectStatus().isOk()
        .expectBody(JwtController.ApiToken.class)
        .value(t -> assertThat(t.username().equals("bob")))
        .returnResult()
        .getResponseBody();

    assertThat(apiToken).isNotNull();
    assertThat(apiToken.username()).isEqualTo("bob");
    assertThat(apiToken.roles()).contains("USER");
    assertThat(apiToken.apiToken()).isNotEmpty();
  }

  @Test
  public void validUserWrongPwdFailsLogin() {
    client.get()
        .uri("/login")
        .header(HttpHeaders.AUTHORIZATION, LoginController.credentialsToHeader("bob:foo").block())
        .exchange()
        .expectStatus().isUnauthorized();
  }

  @Test
  public void invalidUserFailsLogin() {
    client.get()
        .uri("/login")
        .header(HttpHeaders.AUTHORIZATION,
            LoginController.credentialsToHeader("evil:hacker").block())
        .exchange()
        .expectStatus().isUnauthorized();
  }

  @Test
  public void validUserCanResetPassword() {
    client.get()
        .uri("/login/reset/pete")
        .exchange()
        .expectStatus().isOk()
        .expectBody(User.class)
        .value(u -> assertThat(u.getUsername()).isEqualTo("pete"))
        .value(u -> assertThat(u.getPassword()).isNotEmpty());
  }

  @Test
  public void invalidUserWontResetPassword() {
    client.get()
        .uri("/login/reset/evil")
        .exchange()
        .expectStatus().isNotFound();
  }
}
