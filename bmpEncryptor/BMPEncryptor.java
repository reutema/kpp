package kpp.bmpEncryptor;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public class BMPEncryptor
{
    private Key secretKey;

    private Cipher cipher;

    public BMPEncryptor(String chiffre, String modi, String key, String path, boolean encrypt) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {

        if (key == (null))
        {
            this.secretKey = generateKey(chiffre);
        }
        else
        {
            this.secretKey = new SecretKeySpec(key.getBytes(), chiffre);
        }
        this.cipher = Cipher.getInstance(chiffre + "/" + modi + "/BC");

        FileInputReaderOutputWriter firow = new FileInputReaderOutputWriter();
        byte[] data = firow.readToFile(path);
        int offset = data[10];
        if (encrypt)
        {
            encrypt(data, offset);
        }

        firow.writeToFile(path, data, "_" + modi + "_enc" + ".bmp");

    }

    public SecretKey generateKey(String chiffre) throws NoSuchAlgorithmException
    {
        KeyGenerator generator = KeyGenerator.getInstance("SunTlsRsaPremasterSecret");
        return generator.generateKey();
    }

    public byte[] encrypt(byte[] data, int offset) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        int cpLength = cipher.update(data, offset, data.length, data);
        return cipher.doFinal(input, inputOffset, inputLen)al(data, cpLength);

    }

    public static void main(String[] args)
    {
        String path = "C:\\...";
        String picture = "butterfly.bmp";

        try
        {
            try
            {
                BMPEncryptor bmp = new BMPEncryptor("AES", "ECB", "SunTlsRsaPremasterSecret", path + picture, true);
            }
            catch (ShortBufferException e)
            {
                e.printStackTrace();
            }
        }
        catch (InvalidKeyException | NoSuchAlgorithmException
                        | NoSuchPaddingException | IllegalBlockSizeException
                        | BadPaddingException | IOException e)
        {
            e.printStackTrace();
        }
    }

}
