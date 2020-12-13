package io.kapsules.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.kapsules.jwt.configuration.JwtSecurityConfiguration;
import io.kapsules.jwt.configuration.KeyMaterialConfiguration;
import io.kapsules.jwt.configuration.OpaServerConfiguration;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.ActiveProfiles;

import java.util.stream.Collectors;

import static io.kapsules.jwt.JwtTokenProvider.ROLE;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {
    OpaServerConfiguration.class,
    JwtSecurityConfiguration.class,
    KeyMaterialConfiguration.class,
    JwtOpa.class
})
@ActiveProfiles("test")
class JwtTokenProviderTest {

  @Autowired
  JwtTokenProvider provider;

  @Test
  public void createToken() {
    String token = provider.createToken("a-user", Lists.list("USER",
        "PAINTER", "POET"));

    JWT jwt = new JWT();
    DecodedJWT decoded = jwt.decodeJwt(token);
    assertThat(decoded).isNotNull();
    assertThat(decoded.getSubject()).isEqualTo("a-user");
    assertThat(decoded.getClaim(ROLE).asArray(String.class))
        .containsExactlyInAnyOrder("USER", "PAINTER", "POET");
  }

  @Test
  public void canVerifyCreated() {
    String token = provider.createToken("me", Lists.list("uno"));
    assertThat(provider.validateToken(token)).isTrue();
  }

  @Test
  public void verifyBogusFails() {
    String token = provider.createToken("attacker", Lists.list("CHEAT"));
    assertThat(provider.validateToken(
        token.replace("a", "A").replace("Y", "q"))).isFalse();
  }

  @Test
  public void getAuthentication() {
    String token = provider.createToken("alice", Lists.list("USER", "ADMIN"));

    Authentication auth = provider.getAuthentication(token);

    assertThat(auth).isNotNull();
    assertThat(auth.isAuthenticated()).isTrue();

    // This is needed, as the Authentication object does not know that its Principal is,
    // in fact, a User object
    User alice = (User) auth.getPrincipal();
    assertThat(alice.getUsername()).isEqualTo("alice");
    assertThat(auth.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.toList())
    ).containsExactlyInAnyOrder("USER", "ADMIN");
  }
}
