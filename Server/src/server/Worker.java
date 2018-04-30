package server;

import java.awt.FontFormatException;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import server.Seguridad;
import server.Transformacion;

public class Worker implements Runnable {
    public static final boolean SHOW_ERROR = true;
    public static final boolean SHOW_S_TRACE = true;
    public static final boolean SHOW_IN = true;
    public static final boolean SHOW_OUT = true;
   
    // algoritmos
    public static final String RC4 = "RC4";
    public static final String BLOWFISH = "BLOWFISH";
    public static final String AES = "AES";
    public static final String DES = "DES";
    public static final String RSA = "RSA";
    public static final String HMACMD5 = "HMACMD5";
    public static final String HMACSHA1 = "HMACSHA1";
    public static final String HMACSHA256 = "HMACSHA256";
    public static final String CERTSRV = "CERTSRV";
    public static final String CERTPA = "CERTPA";
    
    // separador
    public static final String SEPARADOR = ":";
    
    // cadenas de control
    public static final String OK = "OK";
    public static final String ALGORITMOS = "ALGORITMOS";
    public static final String HOLA = "HOLA";
    public static final String INICIO = "INICIO";
    public static final String RTA = "RTA";
    public static final String INFO = "INFO";
    public static final String ERROR = "ERROR";
    public static final String ESTADO = "ESTADO";
    public static final String ERROR_FORMATO = "Error en el formato. Cerrando conexion";
    public static final String CERTCLNT = "CERTCLNT";
    public static final String CERTSVR = "CERTSVR";
    
    private int id;
    private Socket ss;
    private KeyPair keyPair;
    
    private X509Certificate certificadoCliente;

    public Worker(int pId, Socket pSocket) {
        id = pId;
        ss = pSocket;
        Security.addProvider(new BouncyCastleProvider());
    }

    private void printError(Exception e) {
        System.out.println(e.getMessage() + " ES LO DEL WORKER");
        //e.printStackTrace();
    }

    private String read(BufferedReader reader) throws IOException {
        String linea = reader.readLine();
        System.out.println("Thread " + id + " (recibe) de <<CLNT-" + linea);
        return linea;
    }

    private void write(PrintWriter writer, String msg) {
        writer.println(msg);
        System.out.println("Srv " + id + ">>SERV (envia):" + msg);
    }

    public void run() {
        try {
            PrintWriter writer = new PrintWriter(ss.getOutputStream(), true);
            InputStream is = ss.getInputStream();
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader reader = new BufferedReader(isr);
            String linea = read(reader);

            if (!linea.equals("HOLA")) {
                write(writer, "Error en el formato. Cerrando conexion");
                throw new FontFormatException(linea);
            }
            write(writer, "INICIO");
            
            
            // revisamos los algoritmos
            linea = read(reader);
            if ((!linea.contains(":"))
                    || (!linea.split(":")[0].equals("ALGORITMOS"))) {
                write(writer, "Error en el formato. Se espera que la cadena empieze con la palabra ALGORITMOS. Cerrando conexion");
                throw new FontFormatException(linea);
            }

            String[] algoritmos = linea.split(":");

            if ((!algoritmos[1].equals(BLOWFISH)) && (!algoritmos[1].equals(AES))
                    && (!algoritmos[1].equals(DES)) && (!algoritmos[1].equals(RC4))) {
                write(writer, "ERROR: Algoritmo no soportado o no reconocido: "
                        + algoritmos[1] + ". Cerrando conexion");
                throw new NoSuchAlgorithmException();
            }

            if (!algoritmos[2].equals(RSA)) {
                write(writer, "ERROR: Algoritmo no soportado o no reconocido: "
                        + algoritmos[2] + ". Cerrando conexion");
                throw new NoSuchAlgorithmException();
            }

            if ((!algoritmos[3].equals(HMACMD5))
                    && (!algoritmos[3].equals(HMACSHA1))
                    && (!algoritmos[3].equals(HMACSHA256))) {
                write(writer, "ERROR: Algoritmo no soportado o no reconocido: "
                        + algoritmos[3] + " . Cerrando conexion");
                throw new NoSuchAlgorithmException();
            }

            write(writer, "ESTADO:OK");
            
            // 
            
            // linea que marca el inicio del recibimiendo del certificado cliente
            linea = read(reader);
            if ((!linea.equals(CERTCLNT))) {
                write(writer, "Error en el formato. Se espera que la cadena fuera CERTCLNT. Cerrando conexion");
                throw new FontFormatException(linea);
            }
                        
            // revisamos la calidad del certificado
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            byte[] certificadoClienteBytes = new byte[5000]; // buffer para almacenar los bytes del certificado (en cliente, este tiene un un tamanio de mas o menos467 bytes)
            
            is.read(certificadoClienteBytes);
            InputStream inputStream = new ByteArrayInputStream(certificadoClienteBytes);
            try {
            	certificadoCliente = (X509Certificate)certFactory.generateCertificate(inputStream);
            } catch(CertificateException ce){
            	write(writer, ESTADO + SEPARADOR + ERROR);
            	System.out.println("Error en el certificado recibido, no se puede decodificar");
            	//ce.printStackTrace();
            	//throw new FontFormatException(
                //  "Error en el certificado recibido, no se puede decodificar");
            }
            
            write(writer, "ESTADO:OK");
            
            //linea de inicio de envio de certificado cliente
            write(writer, CERTSRV);

            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
                keyPair = keyGen.generateKeyPair();

                Security.addProvider(new BouncyCastleProvider());
                keyGen.initialize(1024);
                X509Certificate certificadoServidor = Seguridad.generateV3Certificate(keyPair);
                
                byte[] certAsBytes = certificadoServidor.getEncoded();
          			
          			try {
          				ss.getOutputStream().write(certAsBytes);
          				ss.getOutputStream().flush();
          			} catch(IOException exception){
          				System.out.println("Hubo un error enviado bytes de certificado al cliente");
          			}
          			
            } catch (Exception e) {
                e.printStackTrace();
            }

            // verificamos que el cliente comprobo nuestro certificado
            linea = read(reader);
            if (linea.split(SEPARADOR).length < 2 || !linea.split(SEPARADOR)[1].equals("OK")) {
                System.out.println("Error de confirmación, cerrando conexion: " + linea);
                throw new Exception("Cerrando conexion");
                //return;
            }

            
            // inicio de la comunicacion de las llaves

            SecretKey llaveSimetrica = Seguridad.keyGenGenerator(algoritmos[1]);
            byte[] cyph = Seguridad.aE(llaveSimetrica.getEncoded(),
                    certificadoCliente.getPublicKey(), algoritmos[2]);

            String llav = Transformacion.toHexString(cyph);           
            write(writer, INICIO + SEPARADOR + llav); // aqui le enviamos al cliente la llave simetrica cifrada con la asimetrica del certificado

            // recibimos respuesta del cliente con la localizacion cifrada con la simetrica. 
            linea = read(reader);
            String[] parts = linea.split(SEPARADOR);
            String cipheredLocationHex = parts[1];
            
            byte[] cipheredLocationBytes = Transformacion.toByteArray(cipheredLocationHex);
            
            byte[] cipheredLocation = Seguridad.sD(
            		cipheredLocationBytes, llaveSimetrica,
                    algoritmos[1]);
            
           
                       
            // recibimos el digest cifrado con la clave publica del server
            linea = read(reader);
            String[] parts2 = linea.split(SEPARADOR);
            String digestHex = parts2[1];
            byte[] encryptedDigestBytes = Transformacion.toByteArray(digestHex);
            
            byte[] digestBytes = Seguridad.aD(
            		encryptedDigestBytes, keyPair.getPrivate(),
                    algoritmos[2]);
            
            // hacemos la verificacion final
            boolean verificacion = Seguridad.verifyIntegrity(cipheredLocation,
                    llaveSimetrica, algoritmos[3], digestBytes);

            if (verificacion) {
                String rta = ESTADO + SEPARADOR + OK;
                write(writer, rta);

            } else {
                String rta = ESTADO + SEPARADOR + ERROR;
                write(writer, rta);
            }
            System.out.println("Thread " + id + "Terminando\n");

        } catch (NullPointerException e) {

            printError(e);

            try {
                ss.close();
            } catch (Exception localException2) {
            }
        } catch (IOException e) {
            printError(e);

            try {
                ss.close();
            } catch (Exception localException3) {
            }
        } catch (FontFormatException e) {
            printError(e);

            try {
                ss.close();
            } catch (Exception localException4) {
            }
        } catch (NoSuchAlgorithmException e) {
            printError(e);

            try {
                ss.close();
            } catch (Exception localException5) {
            }
        } catch (InvalidKeyException e) {
            printError(e);

            try {
                ss.close();
            } catch (Exception localException6) {
            }
        } catch (IllegalStateException e) {
            printError(e);

            try {
                ss.close();
            } catch (Exception localException7) {
            }
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();

            try {
                ss.close();
            } catch (Exception localException8) {
            }
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            try {
                ss.close();
            } catch (Exception localException9) {
            }
        } catch (BadPaddingException e) {
            e.printStackTrace();
            try {
                ss.close();
            } catch (Exception localException10) {
            }
        } catch (Exception e) {
            e.printStackTrace();
            try {
                ss.close();
            } catch (Exception localException11) {
            }
        } finally {
            try {
                ss.close();
            } catch (Exception localException12) {
            }
        }
    }
}
