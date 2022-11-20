/*
 * Copyright (c) 2021 AlertAvert.com.  All rights reserved.
 * Author: Marco Massenzio (marco@alertavert.com)
 */

package com.alertavert.opa.security.aws;

import com.alertavert.opa.security.SecretsResolver;
import com.alertavert.opa.security.crypto.KeyLoadException;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

/**
 * <H2>AwsSecretsManagerResolver</H2>
 *
 * <p>Accesses <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html">
 * AWS Secrets Manager</a> and retrieves the secrets, if any, stored there.
 *
 * @author M. Massenzio, 2022-01-04
 */
@Slf4j
public class AwsSecretsManagerResolver implements SecretsResolver {

  private final SecretsManagerClient secretsClient;

  public AwsSecretsManagerResolver(SecretsManagerClient secretsClient) {
    this.secretsClient = secretsClient;
  }

  @Override
  public Mono<String> getSecret(String secretName) {
    log.debug("Retrieving SecretValue for secret = {}", secretName);
    try {
      GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
          .secretId(secretName)
          .build();
      GetSecretValueResponse valueResponse = secretsClient.getSecretValue(valueRequest);
      return Mono.just(valueResponse.secretString());
    } catch (SecretsManagerException e) {
      log.error("Could not retrieve secret = {}, error = {}", secretName,
          e.awsErrorDetails().errorMessage());
      return Mono.error(new KeyLoadException(e));
    } catch (software.amazon.awssdk.core.exception.SdkClientException sdkException) {
      // This typically happens when AWS client cannot authenticate with the given credentials.
      log.error("AWS SDK Client error retrieving secret = {}, error = {}",
          secretName, sdkException.getLocalizedMessage());
      return Mono.error(new KeyLoadException(sdkException));
    }
  }
}
