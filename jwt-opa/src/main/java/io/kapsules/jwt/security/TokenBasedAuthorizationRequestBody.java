package io.kapsules.jwt.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Value;

/**
 * <h3>TokenBasedAuthorizationRequestBody</h3>
 *
 * @author M. Massenzio, 2020-11-22
 */
@Value
public class TokenBasedAuthorizationRequestBody {

  /**
   * The OPA server requires every POST body to the Data API to be wrapped inside an {@literal
   * "input"} object, we use this class to simplify the construction of the JSON body.
   */
  @Value
  public static class RequestBody {
    TokenBasedAuthorizationRequestBody input;
  }

  @Value
  public static class Resource {
    String path;
    String method;
  }

  @JsonProperty("api_token")
  String token;
  Resource resource;

  public static RequestBody build(String token, String path, String method) {
    return new RequestBody(new TokenBasedAuthorizationRequestBody(token,
        new Resource(path, method)));
  }
}
