package kpp.otp;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class OTP_Crack extends Thread
{
    private static boolean uncheckedDictionary = false;

    private static boolean uncheckedFilter = true;

    private static String path = "./src/kpp/otp/otp_crack_plaintext.txt";

    private static String dictionaryPath;

    // private static List<String> dictionary;

    private static String[] dictionary =
    { "die", "der", "und", "in", "zu", "den", "das", "nicht", "von", "sie", "ist", "des", "sich", "mit", "dem", "dass", "er", "es", "ein", "ich", "auf", "so", "eine", "auch", "als", "an", "nach", "wie", "im", "für", "man", "aber", "aus", "durch", "wenn", "nur", "war", "noch", "werden", "bei", "hat", "wir", "was", "wird", "sein", "einen", "welche", "sind", "oder", "zur", "um", "haben", "einer", "mir", "über", "ihm", "diese", "einem", "ihr", "uns", "da", "zum", "kann", "doch", "vor", "dieser", "mich", "ihn", "du", "hatte", "seine", "mehr", "am", "denn", "nun", "unter", "sehr", "selbst", "schon", "hier", "bis", "habe", "ihre", "dann", "ihnen", "seiner", "alle", "wieder", "meine", "Zeit", "gegen", "vom", "ganz", "einzelnen", "wo", "muss", "ohne", "eines", "können", "sei", "ja", "wurde", "jetzt", "immer", "seinen", "wohl", "dieses", "ihren", "würde", "diesen", "sondern", "weil", "welcher", "nichts", "diesem", "alles", "waren", "will", "Herr", "viel", "mein", "also", "soll", "worden", "lassen", "dies", "machen", "ihrer", "weiter", "Leben", "recht", "etwas", "keine", "seinem", "ob", "dir", "allen", "großen", "Jahre", "Weise", "müssen", "welches", "wäre", "erst", "einmal", "Mann", "hätte", "zwei", "dich", "allein", "Herren", "während", "Paragraph", "anders", "Liebe", "kein", "damit", "gar", "Hand", "Herrn", "euch", "sollte", "konnte", "ersten", "deren", "zwischen", "wollen", "denen", "dessen", "sagen", "bin", "Menschen", "gut", "darauf", "wurden", "weiß", "gewesen", "Seite", "bald", "weit", "große", "solche", "hatten", "eben", "andern", "beiden", "macht", "sehen", "ganze", "anderen", "lange", "wer", "ihrem", "zwar", "gemacht", "dort", "kommen", "Welt", "heute", "Frau", "werde", "derselben", "ganzen", "deutschen", "lässt", "vielleicht", "meiner" };

    private long startTime;

    private long endTime;

    private String cipherText;

    private static long countDropped;

    private static int maxCount;// max number of woerterbuch elements in string

    private static int countPrinted;

    // 26347263761667
    public OTP_Crack(String name, long startTime, long endTime)
    {
        super(name);
        this.startTime = startTime;
        this.endTime = endTime;
    }

    @Override
    public void run()
    {

        // OTP_Cipher cipher = new OTP_Cipher();
        // long differenz = endTime - startTime;

        for (long i = startTime; i < endTime; i++)
        {

            OTP_Cipher cipher = new OTP_Cipher();

            cipher.setCiphertextByBase64(cipherText); // setzen des
                                                      // Chiffretextes
            cipher.setKnownKey(i); // setzen des
            cipher.decrypt(); // entschlüsseln

            /*
             * Ausgabe
             */
            String plaintext = new String(cipher.getCiphertext());// new
                                                                  // String(cipher.getPlaintext());//
                                                                  // cipher.getEncodedPlaintext();
            System.out.println(plaintext);
            if (uncheckedFilter || plaintext.matches("^[a-zA-Z0-9]*$"))
            {
                int count = 0;
                if (uncheckedDictionary || (count = checkWoerterbuch(plaintext)) > 0)
                {
                    String s = new String("<<" + count + ">>\n" + " Plaintext: " + plaintext + "\nKey: " + i + "\n\n");
                    try
                    {
                        writeToFile(s);
                    }
                    catch (IOException e)
                    {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
                else
                {
                    countDropped++;
                }
            }
            else
            {
                System.out.println("Contains numbers");
                countDropped++;
            }

        }

    }

    public int checkWoerterbuch(String plaintext)
    {
        int i = 0;
        for (String s : dictionary)
        {
            if (plaintext.toLowerCase().contains(s))
            {
                i++;
            }
        }
        if (getMaxCount() < i)
        {
            setMaxCount(i);
        }
        return i;
    }

    public static int checkWoerterbuchsequentiell(String plaintext)
    {
        int i = 0;
        for (String s : dictionary)
        {
            if (plaintext.toLowerCase().contains(s))
            {
                i++;
            }
        }
        if (maxCount < i)
        {
            maxCount = i;
        }
        return i;
    }

    public static int getMax()
    {
        return maxCount;
    }

    private synchronized void setMaxCount(int count)
    {
        this.maxCount = count;
    }

    private synchronized int getMaxCount()
    {
        return maxCount;
    }

    void setStartTime(long time)
    {
        startTime = time;
    }

    void setEndTime(long time)
    {
        endTime = time;
    }

    public void setCipherText(String cipherText)
    {
        this.cipherText = cipherText;
    }

    public static void main(String[] args) throws InterruptedException, IOException
    {
        int numberOfThreads;
        if (args.length != 0)
        {
            path = args[0];
        }
        if (args.length > 0 && args[1] != null)
        {
            numberOfThreads = Integer.parseInt(args[1]);
        }
        else
        {
            numberOfThreads = 4;
        }
        // dictionary = new ArrayList<>();
        // if (args[2] != null)
        // {
        // dictionaryPath = args[2];
        // }
        //
        // fillDictionary();
        System.out.println("start cracking...");
        String cipherText = "5hYOBsQLb476eVv/vwNw93rP2ZSAjRoji/OJ4A3wyBtpWty/VEipd9wCBpMRMZUcTSWZp3jGPMr9yd5Kx37eYKQiihYc6PqQxOQXJUO5CznDgOXwiyKMZ9ar54ngwmJLNH0CeDSWh3aZReRBfjowW1x86pbKE1eatWJWvGhcdtt41HsEbWT1fCZnWmSSktH18C1NwANhJWSQxrQ2e2jNSgQDypg11/bOuaKYz/2bGW2QtXOaH1qyHbCSkzxAGztehg2jfimxpbQFeQ2kjmapxQEPz1+AqzSDRMAoVqxRYZQh0boAu6U=";
        // 26347263761667L
        long startTime = 26347263761600L;// 26347263066052l;
        long endTime = 26347263761700L;// 26347264117365l;
        long differenz = endTime - startTime;

        System.out.println("Threads: " + numberOfThreads + "\nstartTime: " + startTime + "\nendTime: " + endTime + "\ndifferenz: " + differenz);
        long t1 = System.currentTimeMillis();

        // ----------------------------------------------------------------------------------
        //
        for (long i = startTime; i <= endTime; i++)
        {
            System.out.println("i: " + i);

            OTP_Cipher cipher = new OTP_Cipher();

            cipher.setCiphertextByBase64(cipherText); // setzen des
                                                      // Chiffretextes
            cipher.setKnownKey(i); // setzen des
            cipher.decrypt(); // entschlüsseln

            /*
             * Ausgabe
             */
            String plaintext = new String(cipher.getPlaintext(), "UTF-8");// new
            // String(cipher.getPlaintext());//
            // cipher.getEncodedPlaintext();
            System.out.println(plaintext);
            if (uncheckedFilter || plaintext.matches("^[a-zA-Z0-9]*$"))
            {
                int count = 0;
                if ((count = checkWoerterbuchsequentiell(plaintext)) > 0)
                {
                    String s = new String("<<" + count + ">>\n" + " Plaintext: " + plaintext + "\nKey: " + i + "\n\n");
                    try
                    {
                        writeToFile(s);
                    }
                    catch (IOException e)
                    {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
                else
                {
                    countDropped++;
                }
            }
            else
            {
                System.out.println("Contains numbers");
                countDropped++;
            }

        }

        // -------------------------------------------------------------------------------------

        // Thread[] list = new Thread[numberOfThreads];
        //
        // long dif;
        // if ((differenz % numberOfThreads) != 0)
        // {
        // dif = ((differenz + numberOfThreads) / numberOfThreads);
        // }
        // else
        // {
        // dif = (differenz / numberOfThreads);
        // }
        //
        // long tmpEndTime = startTime + dif;
        // for (int i = 0; i < numberOfThreads; ++i)
        // {
        // OTP_Crack c = new OTP_Crack(i + "", startTime, tmpEndTime);
        // System.out.println("Thread " + i + ": startTime = " + startTime +
        // "endTime = " + tmpEndTime);
        // c.setCipherText(cipherText);
        //
        // startTime = tmpEndTime + 1;
        // tmpEndTime += dif;
        // list[i] = c;
        // c.start();
        // }
        // for (Thread t : list)
        // {
        // t.join();
        // }

        long t2 = System.currentTimeMillis();
        System.out.println("Benötigte Zeit: " +

        convertTime(t1, t2) + " Sekunden" + "\n");
        System.out.println(countPrinted + " geschrieben;  ~" + countDropped + " Plaintexte nicht geschrieben (Counter nicht Thread geschützt)");
        System.out.println("MaxCount: " + getMax());
    }

    public static String convertTime(long t1, long t2)
    {
        long time = (t2 - t1) / 1000;
        return (((time / 60) > 0) ? ((time / 60) + " Minuten " + time % 60 + " Sekunden") : (time + " Sekunden"));
    }

    public static synchronized void writeToFile(String s) throws IOException
    {
        countPrinted++;
        // URL path = OTP_Crack.class.getResource("");
        // System.out.println("size " + s.length() + " " + s);
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(path, true)))
        {

            bw.write(s);

            // no need to close it.
            // bw.close();

            System.out.println("Done " + Thread.currentThread().getName());

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }

    }

    // public static void fillDictionary() throws IOException
    // {
    // if (dictionaryPath == null)
    // {
    // URL path = OTP_Crack.class.getResource("Dictionary.txt");
    // dictionaryPath = path.getPath();
    // }
    // BufferedReader br = new BufferedReader(new FileReader(dictionaryPath));
    // String next;
    // while ((next = br.readLine()) != null)
    // {
    // dictionary.add(next);
    // }
    // }

}
