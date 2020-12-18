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
