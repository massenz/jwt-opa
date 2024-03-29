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
import org.springframework.http.HttpHeaders;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


/**
 * <h2>OpaServerProperties</h2>
 *
 * This class holds the properties required to connect to a running OPA server, and to correctly
 * build the API endpoints.
 *
 * <p>The {@link #server} value holds the hostname (and optionally, port) of the server, without
 * the {@literal scheme}: HTTP or HTTPS will be used based on the value of {@link #secure}.
 *
 * <p>The name of the {@link #policy} can be anything (so long as is a valid URL segment) and is
 * simply used when POSTing the Rego policy; however, {@link #rule} <strong>MUST</strong> match
 * the name of the Rego policy rule that ultimately decides whether the user/role is allowed to
 * access the given server API endpoint (typically, called {@literal allow}, but can really be
 * anything a valid Rego identifier can).
 *
 * The {@link #dataEndpoint()} and {@link #policyEndpoint()} endpoints are, respectively
 * {@literal /v1/data} and {@literal /v1/policies} (see also the
 * <a href="https://www.openpolicyagent.org/docs/latest/rest-api">OPA REST API document</a>
 *
 * @see OpaServerConfiguration
 * @author M. Massenzio, 2020-11-22
 */
@Data @Slf4j
@ConfigurationProperties(prefix = "opa")
public class OpaServerProperties {

  public static final Collection<String> DEFAULT_HEADERS = List.of(
      HttpHeaders.HOST,
      HttpHeaders.USER_AGENT);

  Boolean secure = false;
  String server;
  String policy;
  String rule;

  /**
   * The list of headers to be sent to OPA to evaluate for authorization.
   *
   * <p> {@link #DEFAULT_HEADERS default headers} are always sent</p>
   */
  List<String> headers = new ArrayList<>();


  @PostConstruct
  public void log() {
    headers.addAll(DEFAULT_HEADERS);
    log.info("Headers configured: headers = {}", headers);
  }

  protected String versionedApi(String api) {
    return String.format("/%s/%s", Constants.OPA_VERSION, api);
  }

  protected String endpoint(String api) {
    String scheme = secure ? "https" : "http";
    return String.format("%s://%s%s/%s", scheme, server,
        versionedApi(api), policy);
  }

  public String policyEndpoint() {
    return endpoint(Constants.OPA_POLICIES_API);
  }

  public String dataEndpoint() {
    return endpoint(Constants.OPA_DATA_API);
  }

  public String authorization() {
    return String.format("%s/%s", dataEndpoint(), rule);
  }
}
