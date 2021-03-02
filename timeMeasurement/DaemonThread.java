package kpp.timeMeasurement;

public class DaemonThread extends Thread
{
    private int stopTime = 20; // standartwert 20 Minuten, wird im Konstruktor
                               // neu gesetzt.

    // zeigt jede Minute die vergangen Minuten an, beendet bei stopTime
    public DaemonThread()
    {
        this.setDaemon(true);
        System.out.println("Start daemon thread...");
        this.stopTime = TimeMeasurement.RuntimeInMin * 60000;
    }

    public void run()
    {

        int minutes = 1;
        long startTime = System.currentTimeMillis();
        long currentTime;

        while (true)
        {
            currentTime = System.currentTimeMillis();

            if (((int) ((currentTime - startTime) / 60000)) == minutes)
            {
                System.out.println(minutes++ + " minutes");
            }
            else if (((int) ((currentTime - startTime) / 60000)) >= stopTime)
            {
                System.err.println("program running time over " + stopTime + " minutes");

            }
        }
        // System.out.println("... end daemon thread");
    }

}
