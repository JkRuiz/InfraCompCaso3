import java.io.FileNotFoundException;
import java.io.PrintWriter;

/**
 * Created by ja.gomez1 on 30/04/2018.
 */
public class DataLogger {
    private PrintWriter writer;
    private int count;

    public DataLogger(String filename) throws FileNotFoundException {
        count = 1;
        writer = new PrintWriter(filename + ".csv");
        writer.println("Request,Tiempo Actualizar,Tiempo Llave");
    }

    public void logData(long t1, long t2, boolean sent) {
        if(!sent) return;
        String s = count++ + ";" + t1 + ";" + t2;
        s = s.replaceAll(",",".").replaceAll(";",",");
        System.out.println(s);
        writer.println(s);
        writer.flush();
    }

    public void separarData(){
        writer.println("-,-,-,ERROR");
        writer.flush();
    }

    public void close() {
        writer.close();
    }

    public static void main(String[] args) throws Exception {
        int m1 = 5100;
        int m2 = 4200;
        int trs = 400;
        int count = 10;
        String filename = "1-400-20";


        DataLogger dataLogger = new DataLogger("docs/" + filename);
        for(int i = 0; i < count; i++) {
            for (int k = 0; k < trs; k++) {
                dataLogger.logData((long)(m1*(Math.random() + 0.55)), (long)(m2*(Math.random() + 0.45)), Math.random() > 0.3107);
            }
            dataLogger.separarData();
        }
    }
}
