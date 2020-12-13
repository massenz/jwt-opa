package io.kapsules.jwt.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * <h3>User</h3>
 *
 * <p>User entity, mapped to a MongoDB store.
 *
 * @author M. Massenzio, 2020-12-04
 */
@Data @Slf4j @NoArgsConstructor
@Document(collection = "users")
public class User implements UserDetails {

  @Value
  public static class RoleAuthority implements GrantedAuthority {
    public static final RoleAuthority USER = new RoleAuthority("USER");
    public static final RoleAuthority ADMIN = new RoleAuthority("ADMIN");
    public static final RoleAuthority SYSTEM = new RoleAuthority("SYSTEM");

    String role;

    @Override
    public String getAuthority() {
      return role;
    }
  }

  @Id @JsonProperty("user_id") @EqualsAndHashCode.Exclude
  @JsonSerialize(using = ToStringSerializer.class)
  ObjectId userId;

  @Indexed
  String username;

  @JsonProperty("password")
  String hashPassword;

  List<RoleAuthority> roles = new ArrayList<>();

  public User(String username, String password, String role) {
    this.username = username;
    this.hashPassword = password;
    if (!StringUtils.isEmpty(role)) {
      roles.add(new RoleAuthority(role));

    }
  }

  public List<String> roles() {
    return roles.stream()
        .map(RoleAuthority::toString)
        .collect(Collectors.toList());
  }

  /**
   * Factory method to create a new User object cloned from an existing one, but with a different
   * password.
   *
   * <p>Can be used to change an existing user's password, by simply saving the newly created
   * object, cloned from the one retrieved from the database.</p>
   *
   * @param user the original user objec to be cloned
   * @param password the new password
   * @return the cloned User
   * @see io.kapsules.jwt.api.UserController#changePassword(String, String)
   */
  public static User withPassword(User user, String password) {
    User newUser = new User();
    newUser.setUsername(user.username);
    newUser.setHashPassword(password);
    if (!StringUtils.isEmpty(user.getUserId())) {
      newUser.setUserId(user.userId);
    }
    newUser.roles.addAll(user.getRoles());
    return newUser;
  }

  /**
   * Factory method to create a new User object cloned from an existing one, but with a different
   * username.
   *
   * <p>Can be used to change an existing user's {@literal username}, by simply saving the newly
   * created object, cloned from the one retrieved from the database.</p>
   *
   * @param user the original user objec to be cloned
   * @param newUsername the new username
   * @return the cloned User
   * @see io.kapsules.jwt.api.UserController#changeUsername(String, String)
   */
  public static User withUsername(User user, String newUsername) {
    User newUser = new User();
    newUser.setUsername(newUsername);
    newUser.setHashPassword(user.hashPassword);
    if (!StringUtils.isEmpty(user.getUserId())) {
      newUser.setUserId(user.userId);
    }
    newUser.roles.addAll(user.getRoles());
    return newUser;
  }

  public UserDetails toUserDetails() {
    return this;
  }

  // ===== UserDetails implementation =======

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return roles;
  }

  @Override
  public String getPassword() {
    return "{noop}" + hashPassword;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
