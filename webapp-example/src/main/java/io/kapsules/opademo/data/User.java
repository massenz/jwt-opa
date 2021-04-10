/*
 * Copyright (c) 2020 kapsules.io.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.kapsules.opademo.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
@Data
@Slf4j
@NoArgsConstructor
@Document(collection = "users")
public class User implements UserDetails {

  @Id @JsonProperty("user_id") @EqualsAndHashCode.Exclude
  @JsonSerialize(using = ToStringSerializer.class)
  ObjectId userId;

  @Indexed(unique = true)
  String username;

  @JsonProperty("password")
  String hashPassword;

  List<String> roles = new ArrayList<>();

  public User(String username, String password, String role) {
    this.username = username;
    this.hashPassword = password;
    if (!StringUtils.isEmpty(role)) {
      roles.add(role);
    }
  }

  public List<String> roles() {
    return roles;
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
   * @see io.kapsules.opademo.api.UserController#changePassword(String, String)
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
   * @see io.kapsules.opademo.api.UserController#changeUsername(String, String)
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
  @Value
  private static class RoleAuthority implements GrantedAuthority {
    String role;

    @Override
    public String getAuthority() {
      return role;
    }
  }

  @Override @JsonIgnore
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return roles.stream()
        .map(RoleAuthority::new)
        .collect(Collectors.toList());
  }

  @Override @JsonIgnore
  public String getPassword() {
    return hashPassword;
  }

  @Override @JsonIgnore
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override @JsonIgnore
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override @JsonIgnore
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override @JsonIgnore
  public boolean isEnabled() {
    return true;
  }
}
