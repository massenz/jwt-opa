package io.kapsules.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.kapsules.jwt.configuration.KeyMaterialConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * <h3>JwtTokenProvider</h3>
 *
 * <p>Handles JWT tokens validation, creation and authentication.
 *
 * <p>Based on
 * <a href="https://github.com/hantsy/spring-reactive-jwt-sample/blob/master/src/main/java/com/example/demo/security/jwt/JwtTokenProvider.java">
 * this example code</a>
 *
 * @author M. Massenzio, 2020-11-19
 */
@Component
@Slf4j
public class JwtTokenProvider {

  public static final String ROLE = "role";

  @Autowired
  Algorithm hmac;

  @Autowired
  JWTVerifier verifier;


  public String createToken(String user, String role) {
    return JWT.create()
        .withIssuer(KeyMaterialConfiguration.ISSUER)
        .withSubject(user)
        .withClaim(ROLE, role)
        .sign(hmac);
  }

  public boolean validateToken(String token) {
    try {
      verifier.verify(token);
      return true;
    } catch (Exception error) {
      log.error("Failed to verify token: {}", error.getMessage());
    }
    return false;
  }

  public Authentication getAuthentication(String token) {
    try {
      DecodedJWT decodedJWT = verifier.verify(token);
      String subject = decodedJWT.getSubject();

      // TODO: users typically have several roles, so this should be an Array
      String role = decodedJWT.getClaim(ROLE).asString();

      List<? extends  GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(role);
      User principal = new User(subject, "", authorities);

      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    } catch (Exception error) {
      log.error("Could not authenticate with Token: {}", error.getMessage());
    }
    return null;
  }
}
