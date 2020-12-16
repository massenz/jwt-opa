package io.kapsules.jwt.thirdparty;

import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

import static io.kapsules.jwt.configuration.KeyMaterialConfiguration.ELLIPTIC_CURVE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class PemUtilsTest {

  @Test
  public void readKeys() throws IOException {
    PrivateKey pk = PemUtils.readPrivateKeyFromFile("testdata/test.pem", ELLIPTIC_CURVE);
    PublicKey pubk = PemUtils.readPublicKeyFromFile("testdata/test-pub.pem", ELLIPTIC_CURVE);
    assertThat(pk).isNotNull();
    assertThat(pubk).isNotNull();
  }

  @Test
  public void readKeysThrowsNotFound() throws IOException {
    assertThrows(FileNotFoundException.class, () ->
      PemUtils.readPublicKeyFromFile("bogus.pem", ELLIPTIC_CURVE));
  }

  @Test
  public void nonExistAlgoReturnsNull() throws IOException {
    PrivateKey pk = PemUtils.readPrivateKeyFromFile("testdata/test.pem", "foo-algo");
    assertThat(pk).isNull();
    PublicKey pubk = PemUtils.readPublicKeyFromFile("testdata/test-pub.pem", "foo-algo");
    assertThat(pubk).isNull();
  }

}
