package io.kapsules.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class JwtDemoApplicationTest {
  @Test
  void contextLoads() {
  }

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
