package app.crypt.utils;

import java.util.Arrays;

import java.security.SecureRandom;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

interface CryptSpecs {
  public static final int IV_LENGTH = 12;
  public static final int SALT_LENGTH = 16;
  public static final Charset UTF_8 = StandardCharsets.UTF_8;
}

public class CryptUtils implements CryptSpecs {

  public CryptUtils() { }

  private static byte[] genRandomBytes(int len) {
    byte[] randomBytes = new byte[len];
    new SecureRandom().nextBytes(randomBytes);
    return randomBytes;
  }

  public static byte[] genIV() {
    return genRandomBytes(IV_LENGTH);
  }

  public static byte[] genSalt() {
    return genRandomBytes(SALT_LENGTH);
  }

  public static byte[] stringToBytes(String plaintext) {
    return plaintext.getBytes(UTF_8);
  }

  public static String bytesToString(byte[] hash) {
    String result = new String(hash, UTF_8);
    return result;
  }

}
