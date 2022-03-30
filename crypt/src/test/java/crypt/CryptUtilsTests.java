package test.crypt.utils;

import app.crypt.utils.*;

import static org.junit.jupiter.api.Assertions.*; 
import org.junit.jupiter.api.*;

public class CryptUtilsTests {
  private CryptUtils cutil;

  @BeforeEach
  public void setUp() {
   this.cutil = new CryptUtils();
  }

  @Test
  public void genSalt() {
    assertNotNull(cutil.genSalt(), "Salt should be initialized");
  }

  @Test
  public void genIV() {
    assertNotNull(cutil.genIV(), "IV should be initialized");
  }

  public void decrypt_(){
  }
  
  //public void encodeBase64_(){
  //}

  //public void decodeBase64_(){
  //}

  //public void encodeBase64_Salt(){
  //}

  //public void decodeBase64_Salt(){
  //}

  //public void encodeBase64_IV(){
  //}

  //public void decodeBase64_IV(){
  //}

  //public void encodeBase64_IVSalt(){
  //}

  //public void decodeBase64_IVSalt(){
  //}

  //public void getKey_() {
  //}

  //public void getSalt_() {
  //}
  
  //public void getKey_FromKS() {
  //}

  //public void getSalt_FromKS() {
  //}

}
