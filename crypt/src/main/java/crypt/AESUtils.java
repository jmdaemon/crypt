package app.crypt.utils.aes;

import static app.crypt.utils.CryptUtils.*;
import app.crypt.data.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import static java.util.Objects.isNull;

interface AESSpecs {
  static final String AES_ALGORITHM = "AES/GCM/NoPadding";
  static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA1";
  static final int TAG_LENGTH_BIT = 128;
  static final int ITERATION_COUNT = 65536;
  static final int AES_KEY_LENGTH = 256;
}

public class AESUtils implements AESSpecs {
  private Data data;

  public AESUtils() { }

  public AESUtils(CIPHER_MODE mode) {
    switch(mode) {
      case IV_ONLY:   createDataIV();   break;
      case IV_SALT:   createDataSalt(); break;
      default:        createDataIV();   break;
    }

    //try {
    //switch(mode) {
    //case IV_ONLY:   createDataIV();   break;
    //case IV_SALT:   createDataSalt(); break;
    //default:        createDataIV();   break;
    //}
    //} catch (Exception e) {
    //e.printStackTrace();
    //}
  }

  public AESUtils(String pswd) {
    createData(pswd);
    //try {
    //createData(pswd);
    //} catch (Exception e) {
    //e.printStackTrace();
    //}
  }

  public static SecretKey genKey() {
    KeyGenerator keyGen = null;
    try {
      keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(AES_KEY_LENGTH, SecureRandom.getInstanceStrong());
    } catch (Exception e) {
      e.printStackTrace();
    }
    if (isNull(keyGen)) { System.exit(1); }
    return keyGen.generateKey();
  }

  public static byte[] genPswdHash(String pswd, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeySpec spec = new PBEKeySpec(pswd.toCharArray(), salt, ITERATION_COUNT, AES_KEY_LENGTH);
    SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
    byte[] result = factory.generateSecret(spec).getEncoded();
    return result;
  }

  //public static SecretKey genPswdKey(String pswd, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
  public static SecretKey genPswdKey(String pswd, byte[] salt) {
    SecretKey result = null;
    try {
      result = new SecretKeySpec(genPswdHash(pswd, salt), "AES");
    } catch (Exception e) {
      e.printStackTrace();
    }
    if (isNull(result)) { System.exit(1); }
    return result;
  }

  private Cipher initCipher(int cipherMode) throws Exception {
    Cipher result = Cipher.getInstance(AES_ALGORITHM);
    result.init(cipherMode, getKey(), new GCMParameterSpec(TAG_LENGTH_BIT, getIV()));
    return result;
  }

  public byte[] encrypt(String plaintext) throws Exception {
    Cipher cipher = initCipher(Cipher.ENCRYPT_MODE);
    byte[] result = cipher.doFinal(stringToBytes(plaintext));
    return result;
  }

  public String encryptWithHeader(String plaintext) throws Exception {
    byte[] ciphertext = encrypt(plaintext);
    byte[] result = data.genHeader(ciphertext);
    return data.encodeBase64(result);
  }

  public String decrypt(byte[] ciphertext) throws Exception {
    Cipher cipher = initCipher(Cipher.DECRYPT_MODE);
    byte[] result = cipher.doFinal(ciphertext);
    return new String(result, UTF_8);
  }

  public String decryptWithHeader(String ciphertextWithHeader) throws Exception {
    byte[] ciphertext = data.decodeCiphertext(ciphertextWithHeader);
    String result = decrypt(ciphertext);
    return result;
  }

  public void createDataIV()    { this.data = new Data(genIV(), null, genKey()); }
  public void createDataSalt()  { this.data = new Data(genIV(), genSalt(), genKey()); }
  public void createData(String pswd) { this.data = new Data (genIV(), genSalt(), genPswdKey(pswd, getSalt())); }

  //public void createData(String pswd) throws NoSuchAlgorithmException, InvalidKeySpecException {
  //this.data = new Data (genIV(), genSalt(), genPswdKey(pswd, getSalt()));
  //}

  public byte[] getSalt()   { return data.getSalt();  }
  public byte[] getIV()     { return data.getIV();    }
  public SecretKey getKey() { return data.getKey();   }

  public void setKey(SecretKey key) { data.setKey(key); }
  }
