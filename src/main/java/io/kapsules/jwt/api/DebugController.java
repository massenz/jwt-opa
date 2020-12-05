package io.kapsules.jwt.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * <h3>DebugController</h3>
 *
 * @author M. Massenzio, 2020-12-04
 */
@RestController
@RequestMapping(
    path = "/test",
    produces = MimeTypeUtils.TEXT_PLAIN_VALUE,
    consumes = MimeTypeUtils.TEXT_PLAIN_VALUE)
@Slf4j
public class DebugController {
  @GetMapping
  Mono<String> get() {
    return Mono.just("This is a test");
  }

  @PostMapping
  Mono<String> echo(@RequestBody String body) {
    return Mono.just(body);
  }
}
