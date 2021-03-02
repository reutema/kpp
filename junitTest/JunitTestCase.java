package kpp.junitTest;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

public class JunitTestCase
{

    @Test(expected = AEADBadTagException.class)
    public void testAEADBadTagException() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException
    {

        String chiffre = "AES";
        String mode = "GCM";
        byte[] plainText = new byte[]
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        IvParameterSpec ivSpec = new IvParameterSpec("ABCDEFG".getBytes());
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        Key key = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance(chiffre + "/" + mode + "/NoPadding", "BC");

        byte[] cipherText = new byte[plainText.length];
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        cipher.update(plainText, 0, plainText.length, cipherText, 0);
        cipher.doFinal(cipherText, 0);

        cipher = Cipher.getInstance(chiffre + "/" + mode + "/NoPadding", "BC");
        plainText = new byte[cipherText.length];
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        cipher.update(cipherText, 0, cipherText.length, plainText, 0);
        cipher.doFinal(plainText, 0);

    }

    @Test(expected = BadPaddingException.class)
    public void testBadPaddingException() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidAlgorithmParameterException
    {
        String chiffre = "AES";
        String mode = "GCM";
        byte[] plainText = new byte[]
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        IvParameterSpec ivSpec = new IvParameterSpec("ABCDEFG".getBytes());
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        Key key = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance(chiffre + "/" + mode + "/NoPadding", "BC");

        byte[] cipherText = new byte[plainText.length];
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        cipher.update(plainText, 0, plainText.length, cipherText, 0);
        cipher.doFinal(cipherText, 0);

        cipher = Cipher.getInstance(chiffre + "/" + mode + "/NoPadding", "BC");
        plainText = new byte[cipherText.length];
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        cipher.update(cipherText, 0, cipherText.length, plainText, 0);
        cipher.doFinal();
    }

    @Test(expected = IllegalBlockSizeException.class)
    public void testIllegalBlockSizeException() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, BadPaddingException, InvalidKeyException, NoSuchProviderException
    {
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding", "BC");

        byte[] keyBytes = new byte[]
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        c.init(Cipher.ENCRYPT_MODE, key);
        c.update(keyBytes, 0, keyBytes.length);
        c.doFinal(new byte[keyBytes.length + 1], 0);
    }

    @Test(expected = IllegalStateException.class) //
    public void testIllegalStateException() throws NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, NoSuchProviderException, InvalidKeyException
    {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.update(new byte[1], 0, 0, new byte[0]);
    }

    @Test(expected = InvalidAlgorithmParameterException.class) //
    public void testInvalidAlgorithmParameterException() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
        byte[] keyBytes = new byte[]
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        AlgorithmParameters ag = null;
        c.init(Cipher.DECRYPT_MODE, key, ag);
    }

    @Test(expected = InvalidKeyException.class) //
    public void testInvalidKeyException() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
    {
        byte[] keyBytes = new byte[]
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        byte[] keyBytes2 = new byte[]
        { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        SecretKeySpec key2 = new SecretKeySpec(keyBytes2, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        c.init(Cipher.DECRYPT_MODE, key2);
    }

    @Test(expected = NoSuchAlgorithmException.class) //
    public void testNoSuchAlgorithmException() throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        Cipher c = Cipher.getInstance("GDC");
    }

    @Test(expected = NoSuchPaddingException.class)
    public void testNoSuchPaddingException() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException
    {
        Cipher c = Cipher.getInstance("AES/CBC/PKCSPadddding", "BC");
        // c.init(Cipher.ENCRYPT_MODE, (Key) KeyGenerator.getInstance(null), new
        // AlgorithmParameters(null, "BC", "Padding"));

    }

    @Test(expected = ShortBufferException.class) //
    public void testShortBufferException() throws NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] keyBytes = new byte[]
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        c.init(Cipher.ENCRYPT_MODE, key);
        c.doFinal(new byte[10], 0);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnsupportedOperationException() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, ShortBufferException, BadPaddingException, NoSuchProviderException
    {
        // Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // // byte[] keyBytes = new byte[]
        // // { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        // 0x0a,
        // // 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        // // 0x16, 0x17 };
        // // SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        // KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        // SecretKey skey = generator.generateKey();
        // // c.init(Cipher.ENCRYPT_MODE, skey);
        //
        // c.wrap(skey);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        byte[] keyBytes = new byte[]
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        c.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());
        c.update(keyBytes, 0, keyBytes.length);
        c.init(Cipher.DECRYPT_MODE, key);
        c.doFinal(new byte[10], 0);
        c.init(Cipher.WRAP_MODE, key);
        c.doFinal();
        c.wrap(key);
        c.init(Cipher.WRAP_MODE, key);
        c.update(keyBytes, 0, keyBytes.length);
    }

}
