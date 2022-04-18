package crypt;

import static crypt.CryptUtility.*;

import crypt.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;

import java.security.SecureRandom;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import java.util.Base64;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.io.IOException;

import static java.util.Objects.isNull;

interface AESSpecs {
  static final String AES_ALGORITHM = "AES/GCM/NoPadding";
  static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA1";
  static final int TAG_LENGTH_BIT = 128;
  static final int ITERATION_COUNT = 65536;
  static final int AES_KEY_LENGTH = 256;
}

public class AESUtility implements AESSpecs {
  private byte[] iv;
  private byte[] salt;
	private KeyGenerator generator;
  private SecretKey key;

  /**
    * AESUtility constructors
    * 
    * These constructors provide different defaults:
    * - Default constructor   : Initialize the AESUtility with an IV and salt
    * - Normal constructor    : Initialize the AESUtility with the specified options and/or a password key
    */
  public AESUtility() {
    init(true, true, false, "");
  }

  /**
   * Normal AESUtility constructor
   * @param withIV Generate an initilization vector
   * @param withSalt Generate a salt
   * @param withPassword Generate a normal key or a key derived from a hashed password
   * @param password The password to hash
  */
  public AESUtility(boolean withIV, boolean withSalt, boolean withPassword, String password) {
    init(withIV, withSalt, withPassword, password);
  }

  private void init(boolean withIV, boolean withSalt, boolean withPassword, String password) {
    this.initKeyGen();
    this.iv = (withIV) ? genIV() : null;
    this.salt = (withSalt) ? genSalt() : null;
    this.key = (withPassword) ? genPswdKey(password) : this.generator.generateKey();
  }

  // Initializes the AES Key generator with the provided defaults
  private void initKeyGen() {
    this.initKeyGen(AES_KEY_LENGTH, "AES");
  }

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
    // Ensure the key generator is not null
    if (isNull(this.generator)) { System.exit(1); }
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

  public static String encodeBase64(byte[] ciphertext) {
    String result = Base64.getEncoder().encodeToString(ciphertext);
    return result;
  }

  public static byte[] decodeBase64(String ciphertext) {
    byte[] result = Base64.getDecoder().decode(ciphertext.getBytes(UTF_8));
    return result;
  }

  public byte[] decodeCiphertext(String ciphertextWithHeader) throws NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] decodedCiphertext = decodeBase64(ciphertextWithHeader);
    byte[] result = parseHeader(decodedCiphertext);
    return result;
  }

  public byte[] genPswdHash(String pswd) throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeySpec spec = new PBEKeySpec(pswd.toCharArray(), this.salt, ITERATION_COUNT, AES_KEY_LENGTH);
    SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
    byte[] result = factory.generateSecret(spec).getEncoded();
    return result;
  }

  public SecretKey genPswdKey(String pswd) {
    SecretKey result = null;
    try {
      result = new SecretKeySpec(genPswdHash(pswd), "AES");
    } catch (Exception e) {
      e.printStackTrace();
    }
    if (isNull(result)) { System.exit(1); }
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
    String result = (withHeader) ? encodeBase64(createHeader(ciphertext)) : encodeBase64(ciphertext);
    return result;
  }

  public String decrypt(String ciphertext, boolean withHeader) throws Exception {
    Cipher cipher = initCipher(Cipher.DECRYPT_MODE);
    byte[] cipherstring = (withHeader) ? decodeCiphertext(ciphertext) : decodeBase64(ciphertext);
    byte[] result = cipher.doFinal(cipherstring);
    return new String(result, UTF_8);
  }

  public byte[] getSalt()   { return this.salt;  }
  public byte[] getIV()     { return this.iv;    }
  public SecretKey getKey() { return this.key;   }

  public void setKey(SecretKey key) { this.setKey(key); }
  }
