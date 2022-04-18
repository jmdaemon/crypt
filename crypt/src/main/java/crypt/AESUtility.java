package crypt;

import static crypt.CryptUtility.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.KeyGenerator;

import java.security.SecureRandom;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import java.util.Base64;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.io.IOException;

public class AESUtility {
  // AES Utility defaults
  private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
  private static final int AES_KEY_LENGTH = 256;
  private static final int TAG_LENGTH_BIT = 128;

  private byte[] iv;
  private byte[] salt;
	private KeyGenerator generator;
  private SecretKey key;
  private int keyLength;

  /**
    * AESUtility constructors
    * 
    * These constructors provide different defaults:
    * - Default constructor   : Initialize the AESUtility with an IV and salt
    * - Normal constructor    : Initialize the AESUtility with the specified options
    */
  public AESUtility() {
    init(true, true, AES_KEY_LENGTH);
  }

  /**
   * Normal AESUtility constructor
   * @param withIV Generate an initilization vector
   * @param withSalt Generate a salt
  */
  public AESUtility(boolean withIV, boolean withSalt, int keyLength) {
    init(withIV, withSalt, keyLength);
  }

  /**
   * Initializes the AESUtility
   * @param withIV Generate an initilization vector
   * @param withSalt Generate a salt
   * @param keyLength The The key length to use for the AES cipher key.
  */
  private void init(boolean withIV, boolean withSalt, int keyLength) {
    // Initializes the AES Key generator with the provided defaults
    this.initKeyGen(keyLength, "AES");
    this.setKeyLength(keyLength);
    this.setIV(withIV ? genIV() : null);
    this.setSalt(withSalt ? genSalt() : null);
    this.setKey(this.generator.generateKey());
  }

  // Getters
  public byte[] getSalt()   { return this.salt;  }
  public byte[] getIV()     { return this.iv;    }
  public SecretKey getKey() { return this.key;   }

  // Setters
  public void setKey(SecretKey key) { this.key = key; }
  public void setIV(byte[] iv)      { this.iv = iv; }
  public void setSalt(byte[] salt)  { this.salt = salt; }
  public void setKeyLength(int keyLength)  { this.keyLength = keyLength; }

  // Initializes the AES key generator
	private void initKeyGen(int keyLength, String algorithm) {
    KeyGenerator keyGen = null;
    try {
      keyGen = KeyGenerator.getInstance(algorithm);
      keyGen.init(keyLength, SecureRandom.getInstanceStrong());
      this.generator = keyGen;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
  }

  // Generate the AES key 
  public SecretKey genKey() {
    return this.generator.generateKey();
  }

  public byte[] createHeader(byte[] ciphertext) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    output.write(this.iv);
    if (this.salt != null) { output.write(this.salt); }
    output.write(ciphertext);
    byte[] result = output.toByteArray();
    return result;
  }

  public byte[] parseHeader(byte[] decodedCiphertext) throws NoSuchAlgorithmException, InvalidKeySpecException {
    ByteBuffer bb = ByteBuffer.wrap(decodedCiphertext);
    byte[] iv = new byte[CryptUtility.IV_LENGTH];
    bb.get(iv);
    this.iv = iv;

    byte[] salt = new byte[CryptUtility.SALT_LENGTH];
    bb.get(salt);
    this.salt = salt;

    byte[] result = new byte[bb.remaining()];
    bb.get(result);
    return result;
  }

  public static String b64encode(byte[] ciphertext) {
    String result = Base64.getEncoder().encodeToString(ciphertext);
    return result;
  }

  public static byte[] b64decode(String ciphertext) {
    byte[] result = Base64.getDecoder().decode(ciphertext.getBytes(UTF_8));
    return result;
  }

  private Cipher initCipher(int cipherMode) throws Exception {
    Cipher result = Cipher.getInstance(AES_ALGORITHM);
    result.init(cipherMode, this.getKey(), new GCMParameterSpec(TAG_LENGTH_BIT, this.getIV()));
    return result;
  }

  public String encrypt(String plaintext, boolean withHeader) throws Exception {
    Cipher cipher = initCipher(Cipher.ENCRYPT_MODE);
    byte[] ciphertext = cipher.doFinal(stringToBytes(plaintext));
    String result = (withHeader) ? b64encode(createHeader(ciphertext)) : b64encode(ciphertext);
    return result;
  }

  public String decrypt(String ciphertext, boolean withHeader) throws Exception {
    Cipher cipher = initCipher(Cipher.DECRYPT_MODE);
    byte[] cipherstring = (withHeader) ? parseHeader(b64decode(ciphertext)) : b64decode(ciphertext);
    byte[] result = cipher.doFinal(cipherstring);
    return new String(result, UTF_8);
  }
}
