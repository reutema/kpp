package kpp.lamport;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;

/*Aufgabenstellung

Implementieren Sie die Lamport-Signatur nach der in der Vorlesung vorgestellten Art.

Java-Klasse: LamportSignature.java
Package-Name: kpp.lamport
*/
/*Attribute

    int numberOfBytesInHash ; // Anzahl der Bytes im Hashwert
    int n; // Anzahl der Bits im Hashwert
    String hashFunction; // Name of Hash Function e.g. MD5
*/
/*Konstruktor:
public LamportSignature(int lengthOfHashInBit, String hashFunction) throws NoSuchAlgorithmException, InvalidHashLengthException
Setzt alle obigen Attribute.
Wirft NoSuchAlgorithmException, falls es die Hashfunktion nicht gibt.
Wirft InvalidHashLengthException, falls n<0, n <> 0 mod 8 oder n größer der Hashlänge der Hashfunktion.
*/
/*Methoden

    public byte[][][] generatePrivateKey() => generiert einen privaten Schlüssel
    public byte[][][] generatePublicKey(byte[][][] privateKey) => generiert den zum privaten Schlüssel passenden öffentlichen Schlüssel
    public byte[][] sign(byte[] messageBytes, byte[][][] privateKey) => signiert die messageBytes mit dem privaten Schlüssel.
    public boolean verify(byte[] messageBytes, byte[][] signature, byte[][][] publicKey) => Prüft, ob die Signatur valide ist.
    public byte[] getHash(int lenghtInByte, byte[] messageBytes) => liefert die ersten lengthInByte Bytes des Hashwerts der messageBytes.

Dazu werfen die ersten Bytes der Hashfunktion hashFunction verwendet.

    public static int[] byteToIntArr(byte x) => liefert ein int Array mit den Bits des Bytes beginnend mit dem LSB. Beispiel: 80 = [0, 0, 0, 0, 1, 0, 1, 0] (LSB first)
*/
/*Hinweise:

    Verwenden SIe für privateKey die folgenden Dimensionen:

byte[][][] privateKey = new byte[n][2][numberOfBytesInHash];

    Beim Berechnen der Signatur durchlaufen Sie zunächst die einzelnen Bytes des Hashes der Nachricht und dann die einzelnen Bits mit der Methode byteToBoolArray vom LSB zum MSB.
    Verwenden Sie zum Testen zunächst kleine Werte für n wie z.B. 8 oder 16.
    Empfohlen ist eine manuelle Testklasse, in der zunächst die Schlüssel und die Signatur erzeugt werden und dann die Signatur verifiziert wird.
*/

public class LamportSignature
{

    private int numberOfBytesInHash; // Anzahl der Bytes im Hashwert

    private int n; // Anzahl der Bits im Hashwert

    private String hashFunction; // Name of Hash Function e.g. MD5

    private MessageDigest md;

    public LamportSignature(int lengthOfHashInBit, String hashFunction) throws NoSuchAlgorithmException, InvalidHashLengthException
    {
        /*
         * Setzt alle obigen Attribute. Wirft NoSuchAlgorithmException, falls es
         * die Hashfunktion nicht gibt. Wirft InvalidHashLengthException, falls
         * n<0, n <> 0 mod 8 oder n größer der Hashlänge der Hashfunktion.
         */
        System.out.println("Konstruktor: lengthOfHashInBit = " + lengthOfHashInBit + ", hashFunction = " + hashFunction);
        this.md = MessageDigest.getInstance(hashFunction);
        this.hashFunction = hashFunction;
        this.numberOfBytesInHash = lengthOfHashInBit / 8;
        this.n = lengthOfHashInBit;

        if ((lengthOfHashInBit % 8 != 0) || (n < 0) || (n > md.getDigestLength() * 8))
        {
            throw new InvalidHashLengthException("the parameter lengthOfHashInBit is not divisible by 8");
        }

    }

    public byte[][][] generatePrivateKey() throws NoSuchAlgorithmException
    {// => generiert einen privaten Schlüssel
        System.out.println("generate PrivateKey");
        SecureRandom sRandom = new SecureRandom();
        byte[][][] privateKey = new byte[n][2][numberOfBytesInHash];

        for (int i = 0; i < n; i++)
        {

            sRandom.nextBytes(privateKey[i][0]);
            sRandom.nextBytes(privateKey[i][1]);

        }

        return privateKey;
    }

    public byte[][][] generatePublicKey(byte[][][] privateKey)
    {// => generiert den zum privaten Schlüssel passenden öffentlichen Schlüssel
        System.out.println("generate PublicKey: privateKey = " + privateKey.toString());
        byte[][][] publicKey = new byte[n][2][numberOfBytesInHash];

        for (int i = 0; i < n; i++)
        {

            publicKey[i][0] = getHash(numberOfBytesInHash, privateKey[i][0]);

            publicKey[i][1] = getHash(numberOfBytesInHash, privateKey[i][1]);

        }

        return publicKey;

    }

    public byte[][] sign(byte[] messageBytes, byte[][][] privateKey)
    {// => signiert die messageBytes mit dem privaten Schlüssel.
        System.out.println("sign: messageBytes = " + messageBytes.toString() + ", privateKey = " + privateKey.toString());
        byte[] hMessage = getHash(numberOfBytesInHash, messageBytes);
        byte[][] result = new byte[n][numberOfBytesInHash];
        int[][] con = new int[numberOfBytesInHash][n];

        for (int i = 0; i < numberOfBytesInHash; i++)
        {
            con[i] = byteToIntArr(hMessage[i]);
        }

        for (int i = 0; i < n; i++)
        {
            int tmp = con[i / 8][i % 8];
            result[i] = privateKey[i][tmp];
        }

        return result;
    }

    public boolean verify(byte[] messageBytes, byte[][] signature, byte[][][] publicKey)
    {// => Prüft, ob die Signatur valide ist.
        System.out.println("verify: messageBytes = " + messageBytes.toString() + ", signature = " + signature.toString() + ", publicKey = " + publicKey.toString());
        byte[] hMessage = getHash(numberOfBytesInHash, messageBytes);
        int[][] con = new int[numberOfBytesInHash][n];

        for (int i = 0; i < numberOfBytesInHash; i++)
        {

            con[i] = byteToIntArr(hMessage[i]);

        }

        for (int i = 0; i < signature.length; i++)
        {

            int tmp = con[i / 8][i % 8];
            if (Arrays.equals(publicKey[i][tmp], getHash(numberOfBytesInHash, signature[i])))
            {
                continue;
            }
            else
            {
                return false;
            }
        }
        return true;
    }

    public byte[] getHash(int lenghtInByte, byte[] messageBytes)
    {// => liefert die ersten lengthInByte Bytes des Hashwerts der messageBytes.
        System.out.println("getHash: lengthInByte = " + lenghtInByte + ", messageBytes = " + messageBytes.toString());
        byte[] hMessage = md.digest(messageBytes);
        byte[] result = new byte[lenghtInByte];

        for (int i = 0; i < lenghtInByte; i++)
        {
            result[i] = hMessage[i];
        }

        return result;
    }

    public static int[] byteToIntArr(byte x)
    {// => liefert ein int Array mit den Bits des Bytes beginnend mit dem LSB.
     // Beispiel: 80 = [0, 0, 0, 0, 1, 0, 1, 0] (LSB first)
        System.out.println("byteToIntArr: " + x);
        int[] result = new int[8];
        for (int i = 0; i < 8; i++)
        {
            result[i] = (int) (x & 1);
            x = (byte) (x >>> 1);
        }
        return result;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidHashLengthException
    {
        LamportSignature ls1 = new LamportSignature(8, "MD5");

        byte[][][] privateKey1 =
        {
            {
                { 74 },
                { -69 } },
            {
                { -49 },
                { -28 } },
            {
                { -49 },
                { 24 } },
            {
                { -21 },
                { 72 } },
            {
                { 88 },
                { 99 } },
            {
                { -121 },
                { -85 } },
            {
                { -90 },
                { 117 } },
            {
                { 10 },
                { 63 } } };

        byte[][][] publicKey1 =
        {
            {
                { -1 },
                { -42 } },
            {
                { 85 },
                { -63 } },
            {
                { 85 },
                { -53 } },
            {
                { -85 },
                { -63 } },
            {
                { 2 },
                { 74 } },
            {
                { -113 },
                { 36 } },
            {
                { 96 },
                { 123 } },
            {
                { 104 },
                { -47 } } };

        byte[][][] publicKey2 = ls1.generatePublicKey(privateKey1);

        String message1 = "Hallo Leslie.";
        System.out.println("verify = " + ls1.verify(message1.getBytes(), ls1.sign(message1.getBytes(), privateKey1), publicKey1));

        System.out.println("verify = " + ls1.verify(message1.getBytes(), ls1.sign(message1.getBytes(), privateKey1), publicKey2));

        System.out.println("______________");

        LamportSignature ls = new LamportSignature(16, "MD5");

        byte[][][] privateKey =
        {
            {
                { -64, 74 },
                { 29, 37 } },
            {
                { 112, -37 },
                { -94, -87 } },
            {
                { -43, -87 },
                { 100, -119 } },
            {
                { 13, -18 },
                { 122, 13 } },
            {
                { -27, 127 },
                { 93, -13 } },
            {
                { -70, -53 },
                { -54, 124 } },
            {
                { -119, 125 },
                { -6, -127 } },
            {
                { -34, 55 },
                { 2, 48 } },
            {
                { 40, -47 },
                { -121, 5 } },
            {
                { 88, 111 },
                { -47, 61 } },
            {
                { -48, -22 },
                { 32, -79 } },
            {
                { 65, 76 },
                { -110, 118 } },
            {
                { 124, 66 },
                { 75, 23 } },
            {
                { -62, -60 },
                { -43, -37 } },
            {
                { -103, -102 },
                { 40, 29 } },
            {
                { -71, 78 },
                { -11, -87 } } };
        byte[][][] publicKey = ls.generatePublicKey(privateKey);
        String input = "Hallo Leslie";
        ls.verify(input.getBytes(), ls.sign(input.getBytes(), privateKey), publicKey);

    }

}

class InvalidHashLengthException extends Exception
{
    public InvalidHashLengthException(String message)
    {
        super(message);
    }
}
