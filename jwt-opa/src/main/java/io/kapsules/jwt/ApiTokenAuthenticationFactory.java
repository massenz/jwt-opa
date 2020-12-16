package io.kapsules.jwt;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static io.kapsules.jwt.JwtTokenProvider.ROLE;

/**
 * <h3>ApiTokenAuthenticationFactory</h3>
 *
 * <p>Insert class description here...
 *
 * @author M. Massenzio, 2020-12-15
 */
@Service
public class ApiTokenAuthenticationFactory {

  @Autowired
  JwtTokenProvider provider;

  public ApiTokenAuthentication createAuthentication(String token) {
    ApiTokenAuthentication auth;
    try {
      DecodedJWT jwt = provider.decode(token);
      List<? extends  GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(
          jwt.getClaim(ROLE).asArray(String.class));
      String subject = jwt.getSubject();

      auth = new ApiTokenAuthentication(token, subject, authorities, jwt);

    } catch (JWTVerificationException exception) {
      // We don't want to throw inside a factory method, so we partially construct
      // the authentication object, but we set its state to "unauthenticated".
      // We need to use here the superclass #setAuthenticated() because the method
      // in the ApiTokenAuth class has been disabled and throws if called.
      //
      auth = new ApiTokenAuthentication(token, "", Collections.EMPTY_LIST, null);
    }
    return auth;
  }
}
