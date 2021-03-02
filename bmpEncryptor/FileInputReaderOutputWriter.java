package kpp.bmpEncryptor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileInputReaderOutputWriter
{

    public byte[] readFromFile(String path, String content) throws IOException
    {

        return Files.readAllBytes(Paths.get(path + "\\" + content));
    }

    public void writeToFile(String path, byte[] content, String tail, String format)
    {
        File file = new File(path + "_" + tail + format);

        try (FileOutputStream fop = new FileOutputStream(file))
        {

            // if file doesn't exists, then create it
            if (!file.exists())
            {
                file.createNewFile();
            }

            fop.write(content);
            fop.flush();
            fop.close();

            System.out.println("Done");

        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }

}
