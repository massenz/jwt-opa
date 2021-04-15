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

package com.alertavert.opa.security;

import com.alertavert.opa.AbstractTestBase;
import com.alertavert.opa.ReactiveUserDetailsServiceStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PasswordAuthenticationManagerTest extends AbstractTestBase {

  @Autowired
  PasswordAuthenticationManager manager;

  @Autowired
  ReactiveUserDetailsService service;

  @Autowired
  PasswordEncoder encoder;

  UserDetails bob = mock(UserDetails.class);

  @BeforeEach
  public void init() {
    ReactiveUserDetailsServiceStub stub = (ReactiveUserDetailsServiceStub) service;

    when(bob.getUsername()).thenReturn("bob");
    when(bob.getPassword()).thenReturn(encoder.encode("secret"));
    stub.addUser(bob);
  }

  @Test
  public void checkSucceeds() {
    // This is a non-authenticated user.
    UsernamePasswordAuthenticationToken token =
        new UsernamePasswordAuthenticationToken("bob", "secret");

    SimpleGrantedAuthority userRole = new SimpleGrantedAuthority("user");

    // when(...).doReturn(...) does not work here.
    // See: https://stackoverflow.com/questions/51168430/cannot-resolve-method-with-mockito
    List<GrantedAuthority> roles = Collections.singletonList(userRole);
    doReturn(roles).when(bob).getAuthorities();

    // This should be authenticated.
    Authentication authentication = manager.authenticate(token).block();
    assertThat(authentication).isNotNull();
    assertThat(authentication.isAuthenticated()).isTrue();
    assertThat(authentication.getAuthorities().size()).isEqualTo(1);
    List<SimpleGrantedAuthority> authorities = (List<SimpleGrantedAuthority>) authentication.getAuthorities();
    assertThat(authorities).contains(userRole);
  }
}
