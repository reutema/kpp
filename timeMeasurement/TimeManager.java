package kpp.timeMeasurement;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class TimeManager
{
    private ArrayList<Time> list;

    public TimeManager()
    {
        this.list = new ArrayList<>();
    }

    public void add(String name, int blockSize, int keyLength, long startTimeMethod, long startTimeDoFinal, long endTime)
    {
        list.add(new Time(name, blockSize, keyLength, startTimeMethod, startTimeDoFinal, endTime));
    }

    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        list.forEach(e -> sb.append(e.toString() + "\n"));
        return sb.toString();
    }

    public ArrayList<Time> getList()
    {
        return list;
    }

    public String getNameOfFirstObject()
    {
        return list.get(0).getName();
    }

    public String getStringOfCurrentObject()
    {
        return list.get(list.size() - 1).toString();
    }

    public void writeDataToFile() throws IOException
    {
        String name = getNameOfFirstObject();
        String filename = "output" + getNameOfFirstObject() + ".txt";
        System.out.println("write " + name + " data to file " + filename);
        String path = "./src/kpp/timeMeasurement/" + filename;
        File f = new File(path);
        BufferedWriter bw = new BufferedWriter(new FileWriter(f));

        for (Time t : getList())
        {
            bw.write(t.toString() + "\n");
        }
        bw.close();
    }
}

class Time
{
    private final static String seperator1 = " | ";

    private String name;

    private int bitLength, keyLength;

    private long startTimeMethod, startTimeDoFinal, endTime;

    public Time(String name, int bitLength, int keyLength, long startTimeMethod, long startTimeDoFinal, long endTime)
    {
        this.name = name;
        this.bitLength = bitLength;
        this.keyLength = keyLength;
        this.startTimeMethod = startTimeMethod;
        this.startTimeDoFinal = startTimeDoFinal;
        this.endTime = endTime;
    }

    public String getName()
    {
        return name;
    }

    public String toString()
    {
        return seperator1 + name + seperator1 + bitLength + seperator1 + keyLength * 8 + seperator1 + (endTime - startTimeMethod) + seperator1 + (endTime - startTimeDoFinal) + seperator1;
    }
}
