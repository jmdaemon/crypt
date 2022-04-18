package crypt.aes;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;

public class AesKeyGenerator {
  static final int AES_KEY_LENGTH = 256;
	private KeyGenerator generator;

	public AesKeyGenerator() {
		this.init(AES_KEY_LENGTH, "AES");
	}

	private void init(int keyLength, String algorithm) {
		KeyGenerator keyGen = null;
    	try {
      		keyGen = KeyGenerator.getInstance(algorithm);
      		keyGen.init(keyLength, SecureRandom.getInstanceStrong());
      		this.generator = keyGen;
    	} catch (NoSuchAlgorithmException e) {
      		e.printStackTrace();
    	}
    }
    
    public SecretKey generate() {
        return this.generator.generateKey();
    }

    KeyGenerator getGenerator() {
      return this.generator;
    }
}
