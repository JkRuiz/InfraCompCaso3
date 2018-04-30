import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

public class Cliente {
    //Cadenas de control
    private static final String CTO = "Connection timed out";
    private static final String SIN = "Server << ";
    private static final String SOUT = "Client >> ";
    private static final String INIC = "HOLA";
    private static final String ALG = "ALGORITMOS";
    private static final String CC = "CERTCLNT";
    private static final String CS = "CERTSRV";
    private static final String OK = "ESTADO:OK";
    private static final String ERR = "ESTADO:ERROR";
    private static final String CRTERR = "El certificado enviado no es valido";
    private static final String ACT1 = "ACT1:";
    private static final String ACT2 = "ACT2:";

    //Cadenas de referencia
    private static final String MD5 = "HMACMD5";
    private static final String SHA1 = "HMACSHA1";
    private static final String SHA256 = "HMACSHA256";
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String BF = "BLOWFISH";
    private static final String PADDING = "/ECB/PKCS5Padding";
    private long timeSimetrica = 0;
    private long timeSalidaACT = 0;
    private long timeResp = 0;
    private static final int TIMEOUT = 10000;

    //Server data
    private  X509Certificate serverCert = null;
    private PublicKey publicKey = null;
    private SecretKey secretKey = null;

    //Client data
    private Socket socket = null;
    private PrintWriter writer = null;
    private BufferedReader reader = null;
    private KeyPair keyPair = null;
    private X509Certificate cert = null;
    private int tries = 0;
    private boolean sent = false;
    private String[] ALGORITMOS = null;

    //Input data
    BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
    String pos = null;

    public void enviarCoordenadas() {
        while(!sent && tries < 5)
            try {
                long timeL = System.currentTimeMillis();
                definirCoordenadas();
                definirPuerto();
                iniciarProtocolo();
                definirProtocolo();
                intercambiarCertificados();
                timeSimetrica = timeL - System.currentTimeMillis();
                obtenerLlaveSimetrica();
                timeSalidaACT = System.currentTimeMillis();
                generarACT1ACT2();
                esperarRespuesta();
                timeResp = System.currentTimeMillis() - timeSalidaACT;
                sent = true;
            } catch (Exception e){ tries++; }
        }


    public void esperarRespuesta() throws IOException {
        //Leer respuesta servidor
        String s = reader.readLine();
        if(s != null) {
            //(SIN + s);
        }
        else {
            //(CTO);
            System.exit(-1);
        }
        writer.close();
        reader.close();
        stdIn.close();
    }

    public void generarACT1ACT2() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        //Cifrar coordenadas
        byte[] act1Bytes = AESCipher.cifrar(pos, secretKey, ALGORITMOS[0] + PADDING);
        String act1 = toHexString(act1Bytes).toUpperCase();

        //Enviar act1 cifrado
        //(SOUT + ACT1 + act1);
        writer.println(ACT1+act1);

        //Obtener MAC de act1
        byte[] macText = getMAC(pos.getBytes(), secretKey, ALGORITMOS[1]);
        byte[] act2Bytes = RSACipher.cifrar(publicKey, macText);
        String act2 = toHexString(act2Bytes).toUpperCase();
        //(SOUT + ACT2 + act2);
        writer.println(ACT2 + act2);
    }

    public void definirCoordenadas() throws IOException {
        //Pedir coordenadas
        ////("Cuales son las coordenadas a enviar?"  + "\n" +
        //        "(Por defecto (1) se envia: \"41 24.2028, 2 10.4418)\")");
        //pos = stdIn.readLine();
        pos = "1";
        if(pos.equals("1")) pos = "41 24.2028, 2 10.4418";
    }

    public void obtenerLlaveSimetrica() throws IOException {
       //Tiempo en obtener la llave siemtrica

        //Leer mensaje encriptado
        String s = reader.readLine();
        //.println(SIN + s);

        //Descifrar llave del mensaje
        s = s.split(":")[1];
        //(s);
        byte[] llaveBytes = RSACipher.descifrar(DatatypeConverter.parseHexBinary(s), keyPair.getPrivate());
        secretKey = new SecretKeySpec(llaveBytes, 0, llaveBytes.length, ALGORITMOS[0]);
    }

    public void intercambiarCertificados() throws IOException {
        //Generar certificado
        try {
            cert = generarCertificado("SHA256WithRSA");
        } catch (Exception e) { }
        if(cert == null) {
            //.print("ES EN INTERCAMBIAR CERTIFICADOS OR");
            System.exit(-1);
        }

        //Enviar certificado
        writer.println(CC);
        //.println(SOUT + CC);
        try {
            socket.getOutputStream().write(cert.getEncoded());
            socket.getOutputStream().flush();
            //.print(SOUT + "Client certificate bytes");
        } catch (Exception e) { }

        //Leer resultado certificado
        String s = reader.readLine();
        if(s != null) {
            //.print(SIN + s);
        }
        else {
            //.print(CTO);
            //System.exit(-1);
        }

        /*//Leer bytes del certificado
        byte[] temp = new byte[1024];
        int k = 0;
        k = socket.getInputStream().read(temp);
        //(k);
        byte[] bytes = Arrays.copyOf(temp, k);
        //(SIN + "Server certificate bytes");*/

        s = reader.readLine();
        if(s != null) {
            //.print(SIN + s);
        }
        else {
            //.print(CTO);
            //System.exit(-1);
        }
        //Obtener certificado del servidor y extraer la PublicKey
        try {
            serverCert = (X509Certificate) (CertificateFactory.getInstance("X.509")).generateCertificate(socket.getInputStream());
        } catch (Exception e) {
            writer.println(ERR);
            //.println(SOUT + ERR);
            //.print(e.getMessage());
            //.print("ES EN EXTRAER PUBLICKEY");
            //System.exit(-1);
        }
        publicKey = serverCert.getPublicKey();

        //Validar fecha certificado
        Date a = serverCert.getNotAfter();
        Date b = serverCert.getNotBefore();
        Date d = new Date();
        if(a.compareTo(d) * d.compareTo(b) > 0) {
            writer.println(OK);
            //(SOUT + OK);
        }
        else {
            writer.println(ERR);
            //(CRTERR);
            //.print("ES EN VALIDACION DEL CERTIFICADO");
            System.exit(-1);
        }
    }

    public void definirPuerto() throws IOException {
        ////("En que puerto esta el servidor?");
        int port = 9160;
        //try {
        //    port = Integer.parseInt(stdIn.readLine());
        //    if(port == 1) port = 9160;
        //} catch (Exception e) { }

        try {
            socket = new Socket("172.24.42.26", 9160);
            socket.setSoTimeout(TIMEOUT);
        } catch (Exception e) { throw e; }
        ////("Conectado al puerto " + port);

        writer = new PrintWriter(socket.getOutputStream(), true);
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    public void definirProtocolo() throws IOException {
        //Enviar algoritmos a usar

        ALGORITMOS = preguntaAlgoritmos();
        String msg = ALG + ":" + ALGORITMOS[0] + ":RSA:" + ALGORITMOS[1];
        writer.println(msg);
        //(SOUT + msg);

        //Recibir compatibilidad de algoritmos
        String s = reader.readLine();
    }

    public void iniciarProtocolo() throws IOException {

        writer.println(INIC);

        //Iniciar protocolo con el servidor
        ////("Desea iniciar la conexion? (Y/N)");
        //String s = stdIn.readLine();
        //if(s.equals("1") || s.toLowerCase().equals("y")) {
        //   writer.println(INIC);
        //    //(SOUT + INIC);
        //}
        //else System.exit(0);

        //Recibir respuesta servidor
        String s = reader.readLine();
    }

    private String toHexString(byte[] data)
    {
        String rta = "";
        for (byte b: data)
            rta+= String.format("%2s",Integer.toHexString((char)b & 0xFF)).replace(' ', '0');
        return rta;
    }

    public static byte[] getMAC(byte[] text, Key key, String alg) throws NoSuchAlgorithmException, InvalidKeyException
    {
        Mac macGen = Mac.getInstance(alg);
        macGen.init(key);
        return macGen.doFinal(text);
    }

    public java.security.cert.X509Certificate generarCertificado(String algorithm) throws Exception
    {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        keyPair = keygen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(2018, 12, 31);
        BigInteger randomSerial = new BigInteger(32,new Random());
        Security.addProvider(new BouncyCastleProvider());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(new X500Name("CN=Cert"),
                randomSerial, notBefore, notAfter, new X500Name("CN=JAGV"),
                new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded())));

        AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        X509CertificateHolder holder = builder.build((new BcRSAContentSignerBuilder(sigAlgId, digAlgId)).build(privateKeyAsymKeyParam));

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    public String[] preguntaAlgoritmos() throws IOException {
        String[] alg = new String[2];
        alg[0] = AES;
        alg[1] = MD5;

        ////("Que algoritmo simetrico desea usar?" +
        //       "\n" + "(1) AES" + "\n" + "(2) Blowfish");
        //if(stdIn.readLine().equals("2")) alg[0] = BF;
        //else alg[0] = AES;

        ////("Que algoritmo HMAC desea usar?" +
        //        "\n" + "(1) MD5" + "\n" + "(2) SHA1" + "\n" + "(3) SHA256");
        //String s = stdIn.readLine();
        //if(s.equals("2")) alg[1] = SHA1;
        //else if(s.equals("3")) alg[1] = SHA256;
        //else alg[1] = MD5;

        return alg;
    }

    public void test(){
        //("HOLAAA QUE TALLL???");
    }


    public long getTimeSim(){
        return timeSimetrica;
    }

    public long getTimeAct(){
        return timeResp;
    }

    public boolean isSent() {
        return sent;
    }

    public static void main(String[] args) {
        Cliente cliente = new Cliente();
        try {
            cliente.enviarCoordenadas();
            //("Tiempo de respuesta: " + cliente.timeResp);
            //("Tiempo de simetria: " + cliente.timeSimetrica);
        } catch (Exception e) { e.printStackTrace(); }
    }
}
