package kpp.timeMeasurement;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class TimeThread extends Thread
{

    private int method, runTime, bitLength;

    private TimeMeasurement tm;

    private TimeManager manager;

    public TimeThread(int method, int runTimeInSeconds, int length, TimeManager manager)
    {
        this.tm = new TimeMeasurement();
        this.manager = manager;
        this.method = method;
        this.runTime = (runTimeInSeconds * 1000);
        this.bitLength = length;

    }

    public void run()
    {
        long startingTime = System.currentTimeMillis();

        while (((System.currentTimeMillis() - startingTime) <= runTime))
        {

            try
            {
                tm.run(method, bitLength, manager);
            }
            catch (InvalidKeyException | NoSuchAlgorithmException
            | NoSuchProviderException | NoSuchPaddingException
            | InvalidAlgorithmParameterException | IllegalBlockSizeException
            | BadPaddingException e)
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            if (bitLength < bitLength * 5)
            {
                bitLength *= 5;
            }
            else
            {
                break;
            }
        }

        try
        {
            manager.writeDataToFile();
        }
        catch (IOException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

}
