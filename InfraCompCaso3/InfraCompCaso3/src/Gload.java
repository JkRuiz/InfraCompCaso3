import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Gload {

    private LoadGenerator generator;

    public Gload(){
        Task work = createTask();
        int numberOfTask = 50;
        int gapBetweenTasks = 10000;
        generator = new LoadGenerator("TEST",
                numberOfTask,work,gapBetweenTasks);
        generator.generate();;
    }

    private Task createTask(){
        return new ClientServerTask();
    }

    public static void main (String [] args){
        @SuppressWarnings("unused")
        Gload gen = new Gload();
    }

}
