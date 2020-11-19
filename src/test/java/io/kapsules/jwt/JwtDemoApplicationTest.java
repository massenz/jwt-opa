package io.kapsules.jwt;

import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class JwtDemoApplicationTest {
  @Test
  void contextLoads() {
  }
  @MockBean
  PrivateKey privateKey;
  @MockBean
  PublicKey publicKey;
  
  @Autowired
  ReactiveAuthenticationManager authenticationManager;

  @Test
  void security() {
    PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    String encoded = encoder.encode("password");
    System.out.println(">>>>> " + encoded);

    UserDetails details = User.withUsername("user")
        .password(encoder.encode("password"))
        .roles("USER", "EDITOR")
        .build();

    System.out.println(">>>> Auth Mgr: " + authenticationManager.getClass().getName());

    assertTrue(encoder.matches("password", encoded));
  }
}
