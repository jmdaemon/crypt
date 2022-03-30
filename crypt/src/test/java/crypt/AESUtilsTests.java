package test.crypt.utils.aes;

import static app.crypt.utils.CryptUtils.*;
import app.crypt.data.*;
import app.crypt.utils.aes.*;

import static org.junit.jupiter.api.Assertions.*; 
import org.junit.jupiter.api.*;

import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class AESUtilsTests { 
  private AESUtils cipher;
  private AESUtils cipherIV;
  private AESUtils cipherSalt;

  @BeforeEach 
  public void setUp() {
    this.cipher = new AESUtils();
    this.cipherIV = new AESUtils(CIPHER_MODE.IV_ONLY);
    this.cipherSalt = new AESUtils(CIPHER_MODE.IV_SALT);
  }

  @Test
  public void genKey_AES_ReturnAESKey() throws NoSuchAlgorithmException {
    assertNotNull(cipher.genKey());
  }

  @Test
  public void genKeyPswd_AES_ReturnAESKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    assertNotNull(cipherSalt.genPswdKey("This is the user password", cipherSalt.getSalt()));
  }
  
  @Test
  public void encrypt_Plaintext_ReturnAESUtilstext() throws Exception {
    byte[] res = cipherIV.encrypt("This is the plaintext");
    assertNotEquals("This is the plaintext", bytesToString(res), "Ciphertext is encrypted");
  }

  @Test
  public void encrypt_IVPlaintext_ReturnAESUtilstext() throws Exception {
    String res = cipherIV.encryptWithHeader("This is the plaintext");
    assertNotEquals("This is the plaintext", res, "Ciphertext is encrypted");
  }

  @Test
  public void encrypt_SaltPlaintext_ReturnAESUtilstext() throws Exception {
    String res = cipherSalt.encryptWithHeader( bytesToString(cipherSalt.genPswdHash("This is the plaintext", cipherSalt.getSalt())) );
    assertNotEquals("This is the plaintext", res, "Ciphertext is encrypted");
  }

  @Test
  public void decrypt_Ciphertext_ReturnPlaintext() throws Exception {
    byte[] ciphertext = cipher.encrypt("This is the plaintext");
    assertEquals("This is the plaintext", cipher.decrypt(ciphertext));
  }

  @Test 
  public void decrypt_IVCiphertext_ReturnPlaintext() throws Exception {
    String res = cipherSalt.decryptWithHeader(cipherSalt.encryptWithHeader("This is the plaintext"));
    assertEquals("This is the plaintext", res);
  }

  @Test 
  public void decrypt_SaltCiphertext_ReturnPlaintext() throws Exception {
    AESUtils cipherSaltPass = new AESUtils("password");
    String ciphertext = cipherSaltPass.encryptWithHeader("This is the plaintext");
    assertEquals("This is the plaintext", cipherSaltPass.decryptWithHeader(ciphertext));
  }
  
}
