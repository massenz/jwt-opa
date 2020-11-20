package io.kapsules.jwt.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * <h3>JwtTokenAuthorizationFilter</h3>
 *
 * <p>Insert class description here...
 *
 * @author M. Massenzio, 2020-11-19
 */
@RequiredArgsConstructor
@Slf4j
public class JwtTokenAuthorizationFilter implements WebFilter {

  public static final String PREFIX = "Bearer";
  private final JwtTokenProvider provider;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    String token = resolveToken(exchange.getRequest());
    log.debug("filter request for token: {}", token);
    if (StringUtils.hasText(token) && provider.validateToken(token)) {
      Authentication authentication = provider.getAuthentication(token);
      log.debug("Authentication retrieved for Principal: [{}]", authentication.getPrincipal());
      return chain.filter(exchange)
          .subscriberContext(
              ReactiveSecurityContextHolder.withAuthentication(authentication));
    }
    return chain.filter(exchange);
  }

  private String resolveToken(ServerHttpRequest request) {
    String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(PREFIX)) {
      return bearerToken.substring(PREFIX.length() + 1);
    }
    return null;
  }
}
