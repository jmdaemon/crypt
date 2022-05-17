package crypt;

// Third Party Packages
import toolbox.RandomUtility;
import static toolbox.Toolbox.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Standard Library
import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.KeyGenerator;

import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
  * Encrypt and decrypt messages with the Advanced Encryption Standard
  *
  * <p>
  *
  * Examples: 
  * <pre>
  * {@code
  * AESUtility aesUtility = new AESUtility();
  * AESUtility aesUtilityIVOnly = new AESUtility(true, false, 256, "AES/GCM/NoPadding", 12, 16);
  * AESUtility aesUtilityIVandSalt = new AESUtility(true, true, 256, "AES/GCM/NoPadding", 12, 16);
  * }
  * </pre>
  *  
  * Encrypting and Decrypting:
  * <pre>
  * {@code
  * String encryptedMessage = aesUtility.encrypt("This is the plaintext", false);
  * String decryptedMessage = aesUtility.decrypt(encryptedMessage, false);
  * }
  * </pre>
  */
public class AESUtility {
  // Class Fields
  // AES Utility defaults

  // Logging utility 
  private static final Logger log = LoggerFactory.getLogger("logback.example.App");

  /** Default AES algorithm: AES/GCM/NoPadding */
  private static final String DEFAULT_ALGORITHM = "AES/GCM/NoPadding";

  /** Default AES key length: 256 */
  private static final int DEFAULT_KEY_LENGTH = 256;

  /** Default AES IV length: 12 */
  public static final int DEFAULT_IV_LENGTH = 12;

  /** Default AES Salt length: 16 */
  public static final int DEFAULT_SALT_LENGTH = 16;

  // Instance Fields
  private RandomUtility random;
	private KeyGenerator generator;
  private SecretKey key;

  private String algorithm;
  private int aesKeyLength;

  private byte[] iv;
  private byte[] salt;

  private int ivLength;
  private int saltLength;

  /**
    * Default AESUtility constructor
    *
    * <p>
    * Initializes the AESUtility with our specified defaults
    */
  public AESUtility() {
    init(true, true, DEFAULT_KEY_LENGTH, DEFAULT_ALGORITHM, DEFAULT_IV_LENGTH, DEFAULT_SALT_LENGTH);
  }

  /**
   * Normal AESUtility constructor
   * 
   * <p>
   * Initializes the AESUtility with the specified options
   * 
   * @param withIV Generate an initilization vector
   * @param withSalt Generate a salt
   * @param aesKeyLength The specified AES key length
   * @param algorithm The specified AES encryption algorithm
   * @param ivLength The length of the initilization vector
   * @param saltLength The length of the salt array
  */
  public AESUtility(boolean withIV, boolean withSalt, int aesKeyLength, String algorithm, int ivLength, int saltLength) {
    init(withIV, withSalt, aesKeyLength, algorithm, ivLength, saltLength);
  }

  /**
   * Initializes the AESUtility
   * 
   * @param withIV Generate an initilization vector
   * @param withSalt Generate a salt
   * @param aesKeyLength The specified AES key length
   * @param algorithm The specified AES encryption algorithm
   * @param ivLength The length of the initilization vector
   * @param saltLength The length of the salt array
  */
  private void init(boolean withIV, boolean withSalt, int aesKeyLength, String algorithm, int ivLength, int saltLength) {
    // Initializes the AES Key generator with the provided defaults
    log.debug("Initializing AES Utility");
    this.initKeyGen(aesKeyLength, "AES");
    this.setAlgorithm(algorithm);
    log.debug("Initialized Key Generator");

    this.setIVLength(ivLength);
    this.setIV(withIV ? genIV() : null);
    log.debug("Initialized IV");

    this.setSaltLength(saltLength);
    this.setSalt(withSalt ? genSalt() : null);
    log.debug("Initialized Salt");

    this.setKeyLength(aesKeyLength);
    this.setKey(this.generator.generateKey());
    log.debug("Initialized Key");
  }

  // Getters
  public byte[] getSalt()           { return this.salt;  }
  public byte[] getIV()             { return this.iv;    }
  public SecretKey getKey()         { return this.key;   }
  public int getAesKeyLength()      { return this.aesKeyLength; }
  public String getAlgorithm()      { return this.algorithm; }
  public int getIVLength()          { return this.ivLength; }
  public int getSaltLength()        { return this.saltLength; }

  // Setters
  public void setKey(SecretKey key) { this.key = key; }
  public void setIV(byte[] iv)      { this.iv = iv; }
  public void setSalt(byte[] salt)  { this.salt = salt; }
  public void setKeyLength(int aesKeyLength)  { this.aesKeyLength = aesKeyLength; }
  public void setAlgorithm(String algorithm)  { this.algorithm = algorithm; }
  public void setIVLength(int ivLength)       { this.ivLength = ivLength; }
  public void setSaltLength(int saltLength)   { this.saltLength = saltLength; }

  /**
   * Initializes the AES key generator
   *
   * @param aesKeyLength The length of key to use for the AES algorithm. Default: 256.
   * @param algorithm The specific AES algorithm implementation to use. Default: AES/GCM/NoPadding.
  */
	private void initKeyGen(int aesKeyLength, String algorithm) {
    KeyGenerator keyGen = null;
    try {
      keyGen = KeyGenerator.getInstance(algorithm);
      keyGen.init(aesKeyLength, SecureRandom.getInstanceStrong());
      this.generator = keyGen;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
  }

  /**
   * Generate the symmetric AES key 
   *
   * @return The generated AES key from the specified AES implementation
  */
  public SecretKey genKey() {
    log.debug("Generating Key");
    SecretKey key = this.generator.generateKey();
    log.debug("Key: {}", key);
    return key;
  }

  /**
   * Pack the ciphertext into a byte header containing the IV and the salt
   *
   * @param ciphertext The encrypted ciphertext
   * @return A byte[] containing the packed IV and salt.
   * @throws IOException An IOException is thrown if output is unable to be written to
  */
  public byte[] createHeader(byte[] ciphertext) throws IOException {
    log.debug("Creating Message");
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    log.debug("Writing IV to Message");
    output.write(this.iv);
    if (this.salt != null) {
      log.debug("Writing Salt to Message");
      output.write(this.salt);
    }
    log.debug("Writing CipherText to Message");
    output.write(ciphertext);
    byte[] result = output.toByteArray();
    return result;
  }

  /**
   * Unpacks the header into a byte array containing the plaintext
   *
   * @param decodedCiphertext The decoded base64 byte header
   * @return The decrypted plaintext
  */
  public byte[] parseHeader(byte[] decodedCiphertext) {
    ByteBuffer bb = ByteBuffer.wrap(decodedCiphertext);
    log.debug("Parsing IV Message");
    byte[] iv = new byte[this.getIVLength()];
    bb.get(iv);
    this.iv = iv;

    log.debug("Parsing Salt Message");
    byte[] salt = new byte[this.getSaltLength()];
    bb.get(salt);
    this.salt = salt;

    log.debug("Parsing CipherText Message");
    byte[] result = new byte[bb.remaining()];
    bb.get(result);
    return result;
  }

  /**
   * Generate the Initilization Vector (IV)
   *
   * @return The initialization vector
  */
  public byte[] genIV() {
    log.debug("Generating IV");
    byte[] iv = this.random.generateRandomBytes(this.getIVLength());
    log.debug("IV: {}", iv);
    return iv;
  }

  /**
   * Generate the salt
   *
   * @return The salt array
  */
  public byte[] genSalt() {
    log.debug("Generating IV");
    byte[] salt = this.random.generateRandomBytes(this.getSaltLength());
    log.debug("Salt: {}", salt);
    return salt;
  }

  /**
   * Initializes the cipher in either encryption/decryption mode
   *
   * @param cipherMode Either Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
   * @return The initialized cipher
   * @throws Exception A general exception
  */
  private Cipher initCipher(int cipherMode) throws Exception {
    Cipher result = Cipher.getInstance(this.getAlgorithm());
    // Note that the tag length bit used for the GCMParameterSpec is always half the aes key length
    result.init(cipherMode, this.getKey(), new GCMParameterSpec(this.getAesKeyLength() / 2, this.getIV()));
    return result;
  }

  /**
   * Returns the plaintext encrypted with the AES algorithm
   *
   * @param plaintext The data message to encrypt
   * @param withHeader Pack data message into a header containing the iv and salt
   * @return The encrypted ciphertext
   * @throws Exception A general exception
  */
  public String encrypt(String plaintext, boolean withHeader) throws Exception {
    Cipher cipher = initCipher(Cipher.ENCRYPT_MODE);
    byte[] ciphertext = cipher.doFinal(stringToBytes(plaintext));
    String result = (withHeader) ? b64encode(createHeader(ciphertext)) : b64encode(ciphertext);
    return result;
  }

  /**
   * Returns the plaintext decrypted with the AES algorithm
   *
   * @param ciphertext The encrypted ciphertext
   * @param withHeader Unpack data message from a header containing the iv and the salt
   * @return The unencrypted plaintext message
   * @throws Exception A general exception
  */
  public String decrypt(String ciphertext, boolean withHeader) throws Exception {
    Cipher cipher = initCipher(Cipher.DECRYPT_MODE);
    byte[] cipherstring = (withHeader) ? parseHeader(b64decode(ciphertext)) : b64decode(ciphertext);
    String result = bytesToString(cipher.doFinal(cipherstring));
    return result;
  }
}
