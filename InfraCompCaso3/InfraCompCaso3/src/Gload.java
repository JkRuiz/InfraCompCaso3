import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

import java.io.FileNotFoundException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Gload {

    private LoadGenerator generator;
    private static final String path = "docs/";
    private static final String filename = "8-80-100-1";

    public Gload() throws FileNotFoundException {
        String time = new SimpleDateFormat("mm-dd-hh-mm-ss").format(new Date());
        DataLogger dataLogger = new DataLogger(path + filename + "__" + time);
        Task work = createTask(dataLogger);
        int numberOfTask = 80;
        int gapBetweenTasks = 100;
        generator = new LoadGenerator("TEST",
                numberOfTask,work,gapBetweenTasks);
        generator.generate();

    }

    private Task createTask(DataLogger dataLogger){
        return new ClientServerTask(dataLogger);
    }

    public static void main (String [] args){
        try {
            Gload gen = new Gload();
        } catch (Exception e) { e.printStackTrace(); }
    }

}
