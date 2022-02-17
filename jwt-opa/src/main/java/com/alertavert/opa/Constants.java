/*
 * Copyright (c) 2021 AlertAvert.com.  All rights reserved.
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
 *
 * Author: Marco Massenzio (marco@alertavert.com)
 */

package com.alertavert.opa;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.annotation.PostConstruct;
import java.util.Collection;
import java.util.Collections;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Constants {
  // Authorization header types.
  public static final String BASIC_AUTH = "Basic";
  public static final String BEARER_TOKEN = "Bearer";

  // Secrets options
  public static final String ELLIPTIC_CURVE = "EC";
  public static final String PASSPHRASE = "SECRET";

  // OPA Server API constants.
  public static final String OPA_VERSION = "v1";
  public static final String OPA_DATA_API = "data";
  public static final String OPA_POLICIES_API = "policies";

  // Default routes.
  public static final String DEFAULT_HEALTH_ROUTE = "/health";
  public static final String DEFAULT_LOGIN_ROUTE = "/login";

  // Error Messages.
  public static final String FILE_NOT_EXISTS = "The file '%s' doesn't exist.";
  public static final String USER_NOT_AUTHORIZED = "Cannot authorize user";
  public static final String TOKEN_MISSING_OR_INVALID = "API Token was missing or invalid";
  public static final String AUTHORIZATION_HEADER_MISSING = "No Authorization header, rejecting request";
  public static final String UNDEFINED_KEYPAIR = "Public/Private key pair paths must be defined, "
      + "using the 'secrets.keypair.priv/pub' properties";
  public static final String UNEXPECTED_AUTHENTICATION_CLASS = "Unexpected user not "
      + "authenticated, or Authentication type "
      + "({}) not an instance of ApiTokenAuthentication, cannot progress authorization";
  public static final String CANNOT_PARSE_AUTHORIZATION_REQUEST = "Cannot parse Authorization "
      + "request: {}";
  public static final String API_TOKEN = "api_token";

  /**
   * A completely inactive user, that needs to act as a placeholder when the `username` is not
   * found in the Users DB, and would trigger an exception in the Java Security HTTP Basic
   * authentication machinery.
   *
   * @see  org.springframework.security.authentication.UsernamePasswordAuthenticationToken
   */
  public static final UserDetails EMPTY_USERDETAILS = new UserDetails() {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      return Collections.EMPTY_LIST;
    }

    @Override
    public String getPassword() {return "{noop} fake";}
    @Override
    public String getUsername() {return "fake";}

    @Override
    public boolean isAccountNonExpired() {return false;}

    @Override
    public boolean isAccountNonLocked() {return false;}

    @Override
    public boolean isCredentialsNonExpired() {return false;}

    @Override
    public boolean isEnabled() {return false;}
  };
  public static final int MAX_TOKEN_LEN_LOG = 6;
}
