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

package com.alertavert.opa.configuration;

import com.alertavert.opa.Constants;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;
import java.util.List;

/**
 * <h3>RoutesConfiguration</h3>
 *
 * Routes are defined as lists of paths which are either "allowed" without authentication (which
 * should really be kept to a minimum; ideally, only the {@literal "/health"} one); the ones
 * which are gated by Spring Security authentication (e.g., the {@literal "/login"} one, used to
 * get a valid API Token); and everything else, which will be authenticated (using the API Token)
 * and authorized (using the OPA Server's configured policies).
 *
 * @author M. Massenzio, 2021-01-14
 */
@Configuration
@Slf4j
@Data
@EnableConfigurationProperties(RoutesConfiguration.RoutesProperties.class)
public class RoutesConfiguration {

  @Data
  @ConfigurationProperties(prefix = "routes")
  public static class RoutesProperties {

    List<String> allowed = List.of(Constants.DEFAULT_HEALTH_ROUTE);
    List<String> authenticated = List.of(Constants.DEFAULT_LOGIN_ROUTE);
    List<String> authorized = Collections.emptyList();
  }

  private final RoutesProperties properties;
}
