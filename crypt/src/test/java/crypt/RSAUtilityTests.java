package crypt;

import static org.junit.jupiter.api.Assertions.*; 
import org.junit.jupiter.api.*;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class RSAUtilityTests {
  private RSAUtility cipher;

  @BeforeEach
  public void setUp() {
    this.cipher = new RSAUtility();
  }

  @Test
  public void genKey_RSA_ReturnRSAKeyPair() throws NoSuchAlgorithmException {
    KeyPair RSAKey = this.cipher.genKeyPair();
    assertNotNull(RSAKey, "RSA Key should be initialized");
    assertNotNull(RSAKey.getPrivate(), "KeyPair should have a private key");
    assertNotNull(RSAKey.getPublic(), "KeyPair should have a public key");
  }
}
