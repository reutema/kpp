package kpp.timeMeasurement;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TimeMeasurement
{
    public final static int RuntimeInMin = 5;

    private static String modi = "ECB";

    private static int methods = 3;

    public static void main(String[] args) throws InterruptedException, IOException
    {
        long startTime = System.currentTimeMillis();

        // Deamon Thread zum anzeigen der Zeit die vergangen ist.
        DaemonThread daemon = new DaemonThread();
        daemon.setDaemon(true);
        daemon.start();

        int laufzeitInSekunden = RuntimeInMin * 60;
        int bitLength = 1024;
        System.out.println("Starting with " + RuntimeInMin + "minutes (" + laufzeitInSekunden + " seconds) and bit-length of " + bitLength);

        // Container
        // TimeManager aesManager = new TimeManager();
        // TimeManager salsa20Manager = new TimeManager();
        // TimeManager rsaManager = new TimeManager();

        TimeManager[] managers = new TimeManager[methods];
        TimeThread[] threads = new TimeThread[methods];

        System.out.println("initialize Threads");
        for (int i = 0; i < methods; i++)
        {
            managers[i] = new TimeManager();
            threads[i] = new TimeThread(i, laufzeitInSekunden, bitLength, managers[i]);
            threads[i].start();
        }

        System.out.println("start Threads");
        for (TimeThread t : threads)
        {
            t.join();
        }

        long time = (System.currentTimeMillis() - startTime);
        System.out.println("Time: " + (time / 1000) + ":" + (time % 1000) + " Sekunden");

        System.out.println("done");
    }

    public void AES(int bitLength, TimeManager manager) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        String name = "AES";

        System.out.println(name + " " + bitLength);
        long startTimeMethod = System.nanoTime();

        byte[] input = generateInput(bitLength);

        Cipher cipher = Cipher.getInstance(name + "/" + modi + "/PKCS7Padding", "BC");
        SecureRandom random = new SecureRandom();

        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        long startTimeDoFinal = System.nanoTime();

        cipher.doFinal(input);

        long endTime = System.nanoTime();

        manager.add(name, bitLength, key.getEncoded().length, startTimeMethod, startTimeDoFinal, endTime);
        System.out.println(">" + manager.getStringOfCurrentObject());
    }

    public void Salsa20(int bitLength, TimeManager manager) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        String name = "Salsa20";

        System.out.println(name + " " + bitLength);
        long startTimeMethod = System.nanoTime();

        SecureRandom random = new SecureRandom();

        // Manipulation der Schlüssellänge auf einen Wert <> 16 Btye =>
        // InvalidKeyException
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, name);

        Cipher cipher = Cipher.getInstance(name, "BC");

        byte[] input = generateInput(bitLength);

        // Verkürzung des IVs auf 11 Bytes => InvalidKeyException
        byte[] iv = new byte[8];
        random.nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        long startTimeDoFinal = System.nanoTime();

        cipher.doFinal(input);

        long endTime = System.nanoTime();

        manager.add(name, bitLength, key.getEncoded().length, startTimeMethod, startTimeDoFinal, endTime);
        System.out.println(">" + manager.getStringOfCurrentObject());
    }

    public void RSA(int bitLength, TimeManager manager) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        String name = "RSA";

        System.out.println(name + " " + bitLength);
        long startTimeMethod = System.nanoTime();

        byte[] input = generateInput(bitLength);

        Cipher cipher = Cipher.getInstance(name + "/" + modi + "/PKCS1Padding", "BC");

        SecureRandom random = new SecureRandom();

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

        generator.initialize(bitLength * 2, random);

        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();

        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        long startTimeDoFinal = System.nanoTime();

        cipher.doFinal(input);

        long endTime = System.nanoTime();

        manager.add(name, bitLength, pubKey.getEncoded().length, startTimeMethod, startTimeDoFinal, endTime);
        System.out.println(">" + manager.getStringOfCurrentObject());
    }

    public byte[] generateInput(int lengthInBits)
    {
        byte[] array = new byte[lengthInBits / 8];
        Random random = new Random();

        random.nextBytes(array);

        return array;
    }

    public void run(int method, int length, TimeManager manager) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        switch (method)
        {
            case 0:
                AES(length, manager);
                break;
            case 1:
                Salsa20(length, manager);
                break;
            case 2:
                RSA(length, manager);
                break;
        }
    }

}
