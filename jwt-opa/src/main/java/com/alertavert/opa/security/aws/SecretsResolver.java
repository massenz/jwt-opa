/*
 * Copyright (c) 2021 AlertAvert.com.  All rights reserved.
 * Author: Marco Massenzio (marco@alertavert.com)
 */

package com.alertavert.opa.security.aws;

import reactor.core.publisher.Mono;

/**
 * <h2>Secrets Resolver</h2>
 *
 * <p>Interface to resolve secrets in the application.
 *
 * <p>Concrete classes will extract secrets from whatever store (local filesystem, env vars,
 * Hashicorp Vault, AWS Secrets Manager) as configured and return to the caller.
 */
public interface SecretsResolver {
  Mono<String> getSecret(String secretName);
}
