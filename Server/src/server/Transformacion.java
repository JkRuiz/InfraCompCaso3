package server;

import javax.xml.bind.DatatypeConverter;

public class Transformacion {

  public Transformacion() {
  }
  

  
  /**
   * @param b que es un arreglo de bytes que queremos codificar como hexadecimal
   * @return un string en version hexadecimal del array de bytes pasado por parámetro
   */

  public static String toHexString(byte[] array) {
    return DatatypeConverter.printHexBinary(array);
  }

  public static byte[] toByteArray(String s) {
    return DatatypeConverter.parseHexBinary(s);
  }
  
}
