package kpp.bmpEncryptor;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class BMPEncryptor_v_1
{

    private static String chiffre = "AES";

    public static void main(String[] args) throws Exception
    {
        // Pfad und Datei angeben.

        String path = "C:\\...";
        String content = "butterfly.bmp";

        encryption("CBC", path, content);
        encryption("ECB", path, content);

    }

    public static void encryption(String mode, String path, String content) throws Exception
    {

        FileInputReaderOutputWriter firow = new FileInputReaderOutputWriter();

        System.out.println(path + "\\" + content);
        System.out.println("Verschlüsselung mit " + mode + "!");

        // File auslesen und mit Headergroeße den Header bestimmen
        byte[] input = Files.readAllBytes(Paths.get(path, content));
        int headerSize = input[10];

        // Schluessel generieren
        KeyGenerator generator = KeyGenerator.getInstance(chiffre, "BC");
        SecretKey skey = generator.generateKey();

        // Cipher erstellen und initialisieren
        Cipher cipher = Cipher.getInstance(chiffre + "/" + mode + "/PKCS7Padding", "BC");

        cipher.init(Cipher.ENCRYPT_MODE, skey);

        // cipherText Array vorbereiten
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int ctLength;

        // Verschluesselung ausfuehren
        ctLength = cipher.update(input, 0, input.length, cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        // Header vorne anfuegen
        for (int i = 0; i < headerSize; i++)
        {
            cipherText[i] = input[i];
        }

        // Zieldatei bestimmen
        content = content.replace(".bmp", "_enc" + mode + ".bmp");

        // in File zurueckschreiben
        Files.write(Paths.get(path, content), cipherText, StandardOpenOption.CREATE);
        System.out.println(mode + "Verschlüsselung fertig!");
    }

}
