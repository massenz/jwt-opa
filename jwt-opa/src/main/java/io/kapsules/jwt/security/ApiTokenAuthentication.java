package io.kapsules.jwt.security;

import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

/**
 * <h3>ApiTokenAuthentication</h3>
 *
 * @author M. Massenzio, 2020-11-22
 */
@Value
@Slf4j
public class ApiTokenAuthentication implements Authentication {

  /**
   * A JWT that carries the Principal ("sub") and the Authorities ("roles"); this is typically
   * signed and validated by a {@link JwtTokenProvider}
   */
  String token;
  boolean authenticated;

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    // TODO: decode the token and extract the "roles"
    return Collections.EMPTY_LIST;
  }

  /**
   * The API Token (JWT) that authenticates the request.
   *
   * @return the JWT as a String (Base64 encoded)
   */
  @Override
  public Object getCredentials() {
    return token;
  }

  /**
   * These will be the properties carried in the JWT header.
   *
   * <p>For example, in a JWT like this:
   * <code>[
       {
           "alg": "HS256",
           "typ": "JWT"
       },
       {
           "iss": "demo",
           "role": "USER",
           "sub": "marco"
       }
   ]</code>
   * the details will be a {@literal Map<String, String>} such as:
   * <code>
     {
       "alg": "HS256",
       "typ": "JWT"
       "iss": "demo",
     }
   </code>
   *
   * @return a {@literal Map<String, String>} with additional properties
   */
  @Override
  public Object getDetails() {
    // TODO: implement the method
    return Collections.EMPTY_MAP;
  }

  /**
   * The identity of the principal being authenticated, in practice the {@link "sub"} in the JWT
   * body.
   *
   * @return the <code>Principal</code> being authenticated or the authenticated principal after
   * authentication.
   */
  @Override
  public Object getPrincipal() {
    // TODO: implement the method
    return null;
  }

  /**
   * Used to confirm whether the Token was validated prior to this object being created.
   *
   * @return true if the token has been authenticated and this {@link Authentication} object was
   * created by initializing the {@link #authenticated} value to {@literal true}
   */
  @Override
  public boolean isAuthenticated() {
    return authenticated;
  }

  /**
   * This {@link Authentication} implementation is immutable, and whether the JWT is valid (hence
   * the {@link #getPrincipal() Principal} is authenticated) is set at creation time; any attempt
   * to change this will throw an {@link IllegalArgumentException}.
   *
   * @param isAuthenticated always ignored
   * @throws IllegalArgumentException always thrown by this method
   */
  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    throw new IllegalArgumentException("API Token validity must be set at creation time");
  }

  @Override
  public String getName() {
    return getPrincipal().toString();
  }
}
