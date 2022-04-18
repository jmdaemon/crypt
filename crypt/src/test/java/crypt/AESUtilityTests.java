package crypt;

import static org.junit.jupiter.api.Assertions.*; 
import org.junit.jupiter.api.*;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class AESUtilityTests { 
  private AESUtility cipher;
  private AESUtility cipherIV;
  private AESUtility cipherSalt;

  @BeforeEach 
  public void setUp() {
    this.cipher = new AESUtility();
    this.cipherIV = new AESUtility(true, false, 256, "AES/GCM/NoPadding");
    this.cipherSalt = new AESUtility(true, true, 256, "AES/GCM/NoPadding");
  }

  @Test
  public void genSalt() {
    assertNotNull(this.cipher.genSalt(), "Salt should be initialized");
  }

  @Test
  public void genIV() {
    assertNotNull(this.cipher.genIV(), "IV should be initialized");
  }

  @Test
  public void genKey_AES_ReturnAESKey() throws NoSuchAlgorithmException {
    SecretKey key = cipher.genKey();
    assertNotNull(key);
  }
  
  @Test
  public void encrypt_Plaintext_ReturnAESUtilitytext() throws Exception {
    String res = cipherIV.encrypt("This is the plaintext", false);
    assertNotEquals("This is the plaintext", res, "Ciphertext is encrypted");
  }

  @Test
  public void encrypt_IVPlaintext_ReturnAESUtilitytext() throws Exception {
    String res = cipherIV.encrypt("This is the plaintext", false);
    assertNotEquals("This is the plaintext", res, "Ciphertext is encrypted");
  }

  @Test
  public void decrypt_Ciphertext_ReturnPlaintext() throws Exception {
    String ciphertext = cipher.encrypt("This is the plaintext", false);
    assertEquals("This is the plaintext", cipher.decrypt(ciphertext, false));
  }

  @Test 
  public void decrypt_IVCiphertext_ReturnPlaintext() throws Exception {
    String res = cipherSalt.decrypt(cipherSalt.encrypt("This is the plaintext", true), true);
    assertEquals("This is the plaintext", res);
  }

  @Test 
  public void decrypt_SaltCiphertext_ReturnPlaintext() throws Exception {
    AESUtility cipherSaltPass = new AESUtility(true, true, 256, "AES/GCM/NoPadding");
    String ciphertext = cipherSaltPass.encrypt("This is the plaintext", true);
    assertEquals("This is the plaintext", cipherSaltPass.decrypt(ciphertext, true));
  }
}
