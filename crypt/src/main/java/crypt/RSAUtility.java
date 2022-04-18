package crypt;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RSAUtility {
  private final int RSA_KEY_LENGTH = 2048;

  public RSAUtility () { }

  public KeyPair genKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(RSA_KEY_LENGTH, SecureRandom.getInstanceStrong());
    return keyGen.genKeyPair();
  }

  public String encrypt(String plaintext) {
    return "This is not the plaintext";
  }
}
