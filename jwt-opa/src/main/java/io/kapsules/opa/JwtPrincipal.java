/*
 * Copyright (c) 2021 kapsules.io.  All rights reserved.
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

package io.kapsules.opa;

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
