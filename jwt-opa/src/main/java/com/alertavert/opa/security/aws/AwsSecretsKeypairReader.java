/*
 * Copyright (c) 2021 AlertAvert.com.  All rights reserved.
 * Author: Marco Massenzio (marco@alertavert.com)
 */

package com.alertavert.opa.security.aws;

import com.alertavert.opa.ExcludeFromCoverageGenerated;
import com.alertavert.opa.security.SecretsResolver;
import com.alertavert.opa.security.crypto.KeyLoadException;
import com.alertavert.opa.security.crypto.KeypairReader;
import com.alertavert.opa.thirdparty.PemUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.alertavert.opa.Constants.KEYPAIR_ERROR;
import static com.alertavert.opa.Constants.KEYPAIR_LOADED;
import static com.alertavert.opa.Constants.PRIVATE_KEY;
import static com.alertavert.opa.Constants.PUBLIC_KEY;
import static com.alertavert.opa.configuration.KeysProperties.AlgorithmType.EC;

/**
 * <H2>AwsSecretsKeypairReader</H2>
 *
 * <p>Insert class description here.
 *
 * @author M. Massenzio, 2022-01-24
 */
@Value
@Slf4j
public class AwsSecretsKeypairReader implements KeypairReader {
  private static final ObjectMapper JSON_DECODER = new ObjectMapper();

  /**
   * Utility class to simplify the parsing of the secret value, stored as a JSON object.
   */
  @Data
  public static class SecretKeys {
    String priv;
    String pub;
  }

  SecretsResolver resolver;
  String secretName;

  public AwsSecretsKeypairReader(SecretsResolver resolver, String secretName) {
    this.resolver = resolver;
    this.secretName = secretName;
  }

  /**
   * Utility method to read the keys from the JSON object returned by AWS Secrets Manager.
   *
   * @param jsonEncodedKeys the JSON string returned by the Secrets Manager
   * @return a {@link SecretKeys} object
   */
  @ExcludeFromCoverageGenerated
  private SecretKeys getKeysFromJson(String jsonEncodedKeys) {
    try {
      return JSON_DECODER.readValue(jsonEncodedKeys, SecretKeys.class);
    } catch (Exception exception) {
      log.error("Cannot parse secret: {}", exception.getMessage());
      throw new KeyLoadException(exception);
    }
  }

  private Mono<SecretKeys> getSecret() {
    if (!StringUtils.hasText(secretName)) {
      return Mono.error(new KeyLoadException("AWS SecretsManager: no secret name specified"));
    }
    return resolver.getSecret(secretName)
        .map(this::getKeysFromJson)
        .switchIfEmpty(Mono.error(new KeyLoadException("No secret found for " + secretName)));
  }

  @Override
  public Mono<KeyPair> loadKeys() throws KeyLoadException {
    return getSecret()
        .map(keys -> new KeyPair(loadPublicKey(keys), loadPrivateKey(keys)))
        .doOnSuccess(kp -> log.info(KEYPAIR_LOADED, secretName))
        .onErrorMap(KeyLoadException::new)
        .switchIfEmpty(Mono.error(new KeyLoadException("Cannot load keys from secret " + secretName)))
        .doOnError(ex -> log.error(KEYPAIR_ERROR, secretName, ex.getMessage()));
  }

  private PublicKey loadPublicKey(SecretKeys secretKeys) {
    PemObject object = new PemObject(PUBLIC_KEY, Base64.decode(secretKeys.pub));
    return PemUtils.getPublicKey(object.getContent(), EC.name());
  }

  private PrivateKey loadPrivateKey(SecretKeys secretKeys) {
    PemObject object = new PemObject(PRIVATE_KEY, Base64.decode(secretKeys.priv));
    return PemUtils.getPrivateKey(object.getContent(), EC.name());
  }
}
