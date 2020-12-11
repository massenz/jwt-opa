package io.kapsules.jwt.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * <h3>HeartbeatController</h3>
 * <p>
 * This class simply provides a {@literal /health} unauthenticated endpoint that returns a 200 OK so
 * long as the server is running and accepting incoming requests.
 *
 * @author M. Massenzio, 2020-12-04
 */
@RestController
@RequestMapping(
    path = "/health",
    produces = MimeTypeUtils.TEXT_PLAIN_VALUE,
    consumes = MimeTypeUtils.ALL_VALUE)
@Slf4j
public class HeartbeatController {
  @GetMapping
  @ResponseStatus(code = HttpStatus.OK)
  Mono<String> get() {
    return Mono.just("Server is UP");
  }

  @PostMapping
  @ResponseStatus(code = HttpStatus.OK)
  Mono<String> echo(@RequestBody String body) {
    return Mono.just(body);
  }
}
