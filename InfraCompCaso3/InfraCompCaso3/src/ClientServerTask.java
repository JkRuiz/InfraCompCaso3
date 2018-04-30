import uniandes.gload.core.Task;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class ClientServerTask extends Task {

    String fallo = "";

    @Override
    public void execute() {
        Cliente client = new Cliente();
        try {
            client.enviarCoordenadas();
            success();
        } catch (IOException e) {
            fallo = e.getMessage();
            fail();
        } catch (CertificateException e) {
            fallo = e.getMessage();
            fail();
        } catch (InvalidKeyException e) {
            fallo = e.getMessage();
            fail();
        } catch (NoSuchAlgorithmException e) {
            fallo = e.getMessage();
            fail();
        }
        catch (Exception e){
            fallo = e.getMessage();
            fail();
        }

    }

    @Override
    public void fail() {
        System.out.println("Fallo por: " + fallo);
    }

    @Override
    public void success() {
        System.out.println("SIRVIOO");
    }
}
