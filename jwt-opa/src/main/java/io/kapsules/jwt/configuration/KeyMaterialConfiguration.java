package io.kapsules.jwt.configuration;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import io.kapsules.jwt.KeyPair;
import io.kapsules.jwt.thirdparty.PemUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

@Slf4j
@Configuration
@EnableConfigurationProperties(KeyProperties.class)
public class KeyMaterialConfiguration {

  public static final String ELLIPTIC_CURVE = "EC";
  public static final String PASSPHRASE = "SECRET";

  private final KeyProperties secrets;

  public KeyMaterialConfiguration(KeyProperties secrets) {
    this.secrets = secrets;
  }

  @Bean
  public String issuer() {
    return secrets.getIssuer();
  }

  @Bean
  Algorithm hmac(KeyPair keyPair) {
    return switch (secrets.getAlgorithm()) {
      case PASSPHRASE -> Algorithm.HMAC256(secrets.getSecret());
      case ELLIPTIC_CURVE -> Algorithm.ECDSA256((ECPublicKey) keyPair.getPublicKey(),
          (ECPrivateKey) keyPair.getPrivateKey());
      default -> throw new IllegalArgumentException(String.format("Algorithm [%s] not supported",
          secrets.getAlgorithm()));
    };
  }

  @Bean
  JWTVerifier verifier() throws IOException {
    return JWT.require(hmac(keyPair()))
        .withIssuer(issuer())
        .build();
  }

  @Bean
  public KeyPair keyPair() throws IOException {
    return KeyPair.build(loadPrivateKey(), loadPublicKey());
  }

  private PrivateKey loadPrivateKey() throws IOException {
    Path p = Paths.get(secrets.getKeypair().getPriv());
    log.info("Reading private key from file {}", p.toAbsolutePath());

    PrivateKey pk = PemUtils.readPrivateKeyFromFile(p.toString(), secrets.getAlgorithm());
    if (pk == null) {
      log.error("Could not read Public key");
      throw new IllegalStateException(
          String.format("Not a valid EC Private key file %s", p.toAbsolutePath()));
    }
    log.info("Read private key, format: {}", pk.getFormat());
    return pk;
  }

  private PublicKey loadPublicKey() throws IOException {
    Path p = Paths.get(secrets.getKeypair().getPub());
    log.info("Reading public key from file {}", p.toAbsolutePath());

    PublicKey pk = PemUtils.readPublicKeyFromFile(p.toString(), secrets.getAlgorithm());
    if (pk == null) {
      log.error("Could not read Public key");
      throw new IllegalStateException(
          String.format("Not a valid EC Public key file %s", p.toAbsolutePath()));
    }
    log.info("Read public key, format: {}", pk.getFormat());
    return pk;
  }
}
