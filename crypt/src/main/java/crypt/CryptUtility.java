package crypt;

import static toolbox.RandomUtility.generateRandomBytes;

import java.util.Arrays;

import java.security.SecureRandom;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

interface CryptSpecs {
  public static final int IV_LENGTH = 12;
  public static final int SALT_LENGTH = 16;
  public static final Charset UTF_8 = StandardCharsets.UTF_8;
}

public class CryptUtility implements CryptSpecs {

  public CryptUtility() { }


  public static byte[] genIV() {
    return toolbox.RandomUtility.generateRandomBytes(IV_LENGTH);
  }

  public static byte[] genSalt() {
    return toolbox.RandomUtility.generateRandomBytes(SALT_LENGTH);
  }

  public static byte[] stringToBytes(String plaintext) {
    return plaintext.getBytes(UTF_8);
  }

  public static String bytesToString(byte[] hash) {
    String result = new String(hash, UTF_8);
    return result;
  }
}
