//package test.crypt.utils;
package crypt;

import crypt.*;

import static org.junit.jupiter.api.Assertions.*; 
import org.junit.jupiter.api.*;

public class CryptUtilityTests {
  private CryptUtility cutil;

  @BeforeEach
  public void setUp() {
   this.cutil = new CryptUtility();
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
  
  //public void b64encode_(){
  //}

  //public void decodeBase64_(){
  //}

  //public void b64encode_Salt(){
  //}

  //public void decodeBase64_Salt(){
  //}

  //public void b64encode_IV(){
  //}

  //public void decodeBase64_IV(){
  //}

  //public void b64encode_IVSalt(){
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
