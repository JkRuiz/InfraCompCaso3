    import uniandes.gload.core.Task;

    public class ClientServerTask extends Task {

        private long tiempoActualizar = 0;
        private long tiempoLlave = 0;
        private DataLogger dataLogger;

        public ClientServerTask(DataLogger dataLogger) {
            this.dataLogger = dataLogger;
        }

        @Override
        public void execute() {
            Cliente client = new Cliente();
            client.enviarCoordenadas();
            tiempoActualizar = client.getTimeAct();
            tiempoLlave = client.getTimeSim();
            dataLogger.logData(tiempoActualizar, tiempoLlave, client.isSent());
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
