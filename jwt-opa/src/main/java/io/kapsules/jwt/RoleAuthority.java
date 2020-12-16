package io.kapsules.jwt;

import lombok.Value;
import org.springframework.security.core.GrantedAuthority;

/**
 * <h3>RoleAuthority</h3>
 *
 * @author M. Massenzio, 2020-12-15
 */
@Value
public class RoleAuthority implements GrantedAuthority {
  public static final RoleAuthority USER = new RoleAuthority("USER");
  public static final RoleAuthority ADMIN = new RoleAuthority("ADMIN");
  public static final RoleAuthority SYSTEM = new RoleAuthority("SYSTEM");

  String role;

  @Override
  public String getAuthority() {
    return role;
  }
}
