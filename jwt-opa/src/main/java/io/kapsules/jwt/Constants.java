package io.kapsules.jwt;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

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

  // Error Messages
  public static final String FILE_NOT_EXISTS = "The file '%s' doesn't exist.";
  public static final String INVALID_RESULT = "OPA Server did not return a valid result";
  public static final String UNEXPECTED_AUTHENTICATION_OBJECT = "Unexpected Authentication object";
  public static final String TOKEN_MISSING_OR_INVALID = "API Token was missing or invalid";
  public static final String AUTHORIZATION_HEADER_MISSING =
      "No Authorization header, rejecting request";
}
