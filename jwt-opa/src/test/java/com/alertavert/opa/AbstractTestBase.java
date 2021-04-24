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

import com.alertavert.opa.configuration.JwtSecurityConfiguration;
import com.alertavert.opa.configuration.KeyMaterialConfiguration;
import com.alertavert.opa.configuration.OpaServerConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.test.context.ActiveProfiles;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * <h3>AbstractTestBase</h3>
 *
 * <p>Base class for all test classes, used to group commonly-used annotations in a single place.
 *
 * @author M. Massenzio, 2020-12-14
 */
@SpringBootTest(classes = {
    OpaServerConfiguration.class,
    JwtSecurityConfiguration.class,
    KeyMaterialConfiguration.class,
    JwtOpa.class
})
@ActiveProfiles("test")
public abstract class AbstractTestBase {

  public static void setBearerTokenForRequest(ServerHttpRequest request, String token) {
    HttpHeaders headers = mock(HttpHeaders.class);
    when(request.getHeaders()).thenReturn(headers);
    when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn(
        String.format("%s %s", Constants.BEARER_TOKEN, token)
    );
  }
}
