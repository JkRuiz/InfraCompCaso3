    import uniandes.gload.core.Task;

    public class ClientServerTask extends Task {

        long tiempoActualizar = 0;
        long tiempoLlave = 0;

        @Override
        public void execute() {
            Cliente client = new Cliente();
            client.enviarCoordenadas();
            tiempoActualizar = client.getTimeAct();
            tiempoLlave = client.getTimeSim();
            if(client.isSent()) {
                success();
            } else {
                fail();
            }

        }

        @Override
        public void fail() {
            System.out.println("Fallo");
        }

        @Override
        public void success() {
            System.out.println("Sirvio");
            System.out.println("Tiempo actualizacion: " + tiempoActualizar);
            System.out.println("Tiempo llave: " + tiempoLlave);

        }
    }
