//Copyright 2017 - https://github.com/lbalmaceda
//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package io.kapsules.jwt.thirdparty;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
public class PemUtils {

  private static byte[] parsePEMFile(File pemFile) throws IOException {
    if (!pemFile.isFile() || !pemFile.exists()) {
      throw new FileNotFoundException(
          String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
    }
    PemReader reader = new PemReader(new FileReader(pemFile));
    PemObject pemObject = reader.readPemObject();
    byte[] content = pemObject.getContent();
    reader.close();
    return content;
  }

  public static PublicKey getPublicKey(byte[] keyBytes, String algorithm) {
    PublicKey publicKey = null;
    try {
      KeyFactory kf = KeyFactory.getInstance(algorithm);
      EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
      publicKey = kf.generatePublic(keySpec);
    } catch (NoSuchAlgorithmException e) {
      log.error("Could not reconstruct the public key, algorithm [{}] could not be found.", algorithm);
    } catch (InvalidKeySpecException e) {
      log.error("Could not reconstruct the public key: {}", e.getMessage());
    }
    return publicKey;
  }

  public static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) {
    PrivateKey privateKey = null;
    try {
      KeyFactory kf = KeyFactory.getInstance(algorithm);
      EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
      privateKey = kf.generatePrivate(keySpec);
    } catch (NoSuchAlgorithmException e) {
      log.error("Could not reconstruct the private key, "
          + "the given algorithm could not be found. {}", e.getLocalizedMessage());
    } catch (InvalidKeySpecException e) {
      log.error("Could not reconstruct the private key: {}", e.getLocalizedMessage());
    }

    return privateKey;
  }

  public static PublicKey readPublicKeyFromFile(String filepath, String algorithm) throws IOException {
    byte[] bytes = PemUtils.parsePEMFile(new File(filepath));
    log.debug("PemUtils: Read {} bytes", bytes.length);
    return PemUtils.getPublicKey(bytes, algorithm);
  }

  public static PrivateKey readPrivateKeyFromFile(String filepath, String algorithm) throws IOException {
    byte[] bytes = PemUtils.parsePEMFile(new File(filepath));
    log.debug("PemUtils: Read {} bytes", bytes.length);
    return PemUtils.getPrivateKey(bytes, algorithm);
  }
}
