package io.kapsules.jwt.configuration;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import io.kapsules.jwt.thirdparty.PemUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
@Configuration
public class KeyMaterialConfiguration {

  public static final String ISSUER = "demo";
  public static final String ELLIPTIC_CURVE = "EC";

  // TODO(marco): move to their own Properties class, and retrieve it from Vault
  @Value("${secrets.secret}")
  String secret;

  @Value("${secrets.keypair.private}")
  String privateKey;

  @Value("${secrets.keypair.pub}")
  String publicKey;

  @Bean
  Algorithm hmac() {
    return Algorithm.HMAC256(secret);
  }

  @Bean
  JWTVerifier verifier() {
    return JWT.require(hmac())
        .withIssuer(KeyMaterialConfiguration.ISSUER)
        .build();
  }

  @Bean
  PrivateKey privateKey() throws IOException {
    Path p = Paths.get(privateKey);
    log.info("Reading private key from file {}", p.toAbsolutePath());

    // See this: https://github.com/auth0/java-jwt/issues/270
    // Keys generated with:
    // 1. generate the EC param
    //    openssl ecparam -name prime256v1 -genkey -noout -out ec-key.pem
    // 2. generate EC private key
    //    openssl pkcs8 -topk8 -inform pem -in ec-key.pem -outform pem -nocrypt -out ec-key-1.pem
    // 3. generate EC public key
    //    openssl ec -in ec-key-1.pem -pubout -out public.pem
    PrivateKey pk = PemUtils.readPrivateKeyFromFile(privateKey, ELLIPTIC_CURVE);
    if (pk == null) {
      log.error("Could not read Public key");
      throw new IllegalStateException(
          String.format("Not a valid EC Private key file %s", p.toAbsolutePath()));
    }
    log.info("Read private key, format: {}", pk.getFormat());
    return pk;
  }

  @Bean
  PublicKey publicKey() throws IOException {
    Path p = Paths.get(publicKey);
    log.info("Reading public key from file {}", p.toAbsolutePath());

    PublicKey pk = PemUtils.readPublicKeyFromFile(publicKey, ELLIPTIC_CURVE);
    if (pk == null) {
      log.error("Could not read Public key");
      throw new IllegalStateException(
          String.format("Not a valid EC Public key file %s", p.toAbsolutePath()));
    }
    log.info("Read public key, format: {}", pk.getFormat());
    return pk;
  }
}
