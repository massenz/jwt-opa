package io.kapsules.jwt.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;


/**
 * <h3>OpaServerProperties</h3>
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
 * <a href="https://www.openpolicyagent.org/docs/latest/rest-api/>OPA REST API document</a>
 *
 * @see OpaServerConfiguration
 * @author M. Massenzio, 2020-11-22
 */
@Data
@ConfigurationProperties(prefix = "opa")
public class OpaServerProperties {

  public static final String OPA_VERSION = "v1";
  public static final String OPA_DATA_API = "data";
  public static final String OPA_POLICIES_API = "policies";


  Boolean secure = false;
  String server;
  String policy;
  String rule;

  protected String versionedApi(String api) {
    return String.format("/%s/%s", OPA_VERSION, api);
  }

  protected String endpoint(String api) {
    String scheme = secure ? "https" : "http";
    return String.format("%s://%s%s/%s", scheme, server,
        versionedApi(api), policy);
  }

  public String policyEndpoint() {
    return endpoint(OPA_POLICIES_API);
  }

  public String dataEndpoint() {
    return endpoint(OPA_DATA_API);
  }

  public String authorization() {
    return String.format("%s/%s", dataEndpoint(), rule);
  }
}
