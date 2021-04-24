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

import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

/**
 * <h3>ReactiveUserDetailsServiceStub</h3>
 *
 * <p>Basic implementation of a {@link ReactiveUserDetailsService}, which will return any user
 * that was added via the {@link #addUser(UserDetails)} method.
 *
 * <p>Only to be used for tests; this is necessary as the
 * {@link com.alertavert.opa.security.PasswordAuthenticationManager authentication manager}
 * requires one to be injected, and tests will fail if there isn't one in the Spring Context
 * </p>
 *
 * <p>Applications using this library will have to implement their own, most likely backed by a
 * reactive repository.</p>
 *
 * @author M. Massenzio, 2021-04-19
 */
@Service
public class ReactiveUserDetailsServiceStub implements ReactiveUserDetailsService {
  Map<String, UserDetails> users = new HashMap<>();

  public void addUser(UserDetails userDetails) {
    users.put(userDetails.getUsername(), userDetails);
  }

  @Override
  public Mono<UserDetails> findByUsername(String username) {
    if (!users.containsKey(username)) {
      return Mono.empty();
    }
    return Mono.just(users.get(username));
  }
}
