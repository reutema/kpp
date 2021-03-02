package kpp.rsa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

public class Main
{
    public static void main(String[] args) throws IOException, MessageTooLongException, PrivateKeyNotSetException
    {
        String line;
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        do
        {
            System.out.println("Enter 'close' to end this application");
            System.out.println("Please enter 'encrypt' for Encryption or 'decrypt' for Decryption:");
            line = reader.readLine();

            if (line.equals("encrypt"))
            {
                System.out.println("Enter e:");
                BigInteger e = new BigInteger(reader.readLine());
                System.out.println("Enter n:");
                BigInteger n = new BigInteger(reader.readLine());

                RSACipher cipher = new RSACipher(e, n);

                System.err.println("Enter message:");
                BigInteger result = cipher.encrypt(new BigInteger(reader.readLine()));

                System.out.println("result = " + result);
            }
            else if (line.equals("decrypt"))
            {
                System.out.println("Enter p:");
                BigInteger p = new BigInteger(reader.readLine());
                System.out.println("Enter q:");
                BigInteger q = new BigInteger(reader.readLine());
                System.out.println("Enter d:");
                BigInteger d = new BigInteger(reader.readLine());

                RSACipher cipher = new RSACipher(p, q, d);

                System.err.println("Enter message:");
                BigInteger result = cipher.decrypt(new BigInteger(reader.readLine()));

                System.out.println("result = " + result);
            }
        }
        while (!line.equals("close"));
    }

}
