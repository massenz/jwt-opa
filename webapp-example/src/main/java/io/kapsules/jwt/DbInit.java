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
