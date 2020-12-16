package io.kapsules.jwt;

import lombok.Value;

import javax.security.auth.Subject;
import java.security.Principal;

/**
 * <h3>JwtPrincipal</h3>
 *
 * <p>A simple implementation of the {@link Principal} interface, carries the {@literal "sub"}
 * claim contained in a JWT.
 *
 * @see ApiTokenAuthentication
 *
 * @author M. Massenzio, 2020-12-15
 */
@Value
public class JwtPrincipal implements Principal {

  public static final JwtPrincipal NONE = new JwtPrincipal("NONE");

  String sub;

  @Override
  public String getName() {
    return sub;
  }

  @Override
  public boolean implies(Subject subject) {
    return subject.getPrincipals().stream()
        .map(Principal::getName)
        .anyMatch(sub::equals);
  }
}
