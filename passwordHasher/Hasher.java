package kpp.passwordHasher;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.generators.SCrypt;

public class Hasher
{

    public byte[] getMD5(byte[] salt, String password) throws NoSuchAlgorithmException
    {
        String input = new String(salt) + password;
        MessageDigest mDigest = MessageDigest.getInstance("MD5");
        return mDigest.digest(input.getBytes());
    }

    public byte[] getSHA1(byte[] salt, String password) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String input = new String(salt) + password;
        MessageDigest mDigest = MessageDigest.getInstance("SHA1", "BC");
        return mDigest.digest(input.getBytes());
    }

    public byte[] getSHA2_512(byte[] salt, String password) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String input = new String(salt) + password;
        MessageDigest mDigest = MessageDigest.getInstance("SHA-512", "BC");
        return mDigest.digest(input.getBytes());
    }

    public byte[] getSHA3_512(byte[] salt, String password) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String input = new String(salt) + password;
        MessageDigest mDigest = MessageDigest.getInstance("SHA3-512", "BC");
        return mDigest.digest(input.getBytes());
    }

    public byte[] getPBKDF2WithHmacSHA1(byte[] salt, String password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        SecretKeyFactory factorybc = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA1", "BC");
        KeySpec keyspecbc = new PBEKeySpec(password.toCharArray(), salt, 1000, 128);
        Key keybc = factorybc.generateSecret(keyspecbc);
        return keybc.getEncoded();
    }

    public byte[] getPBKDF2WithHmacSHA512(byte[] salt, String password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        SecretKeyFactory factorybc = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BC");
        KeySpec keyspecbc = new PBEKeySpec(password.toCharArray(), salt, 1000, 128);
        Key keybc = factorybc.generateSecret(keyspecbc);
        return keybc.getEncoded();
    }

    public byte[] getScrypt(byte[] salt, String password) throws NoSuchAlgorithmException, NoSuchProviderException // iterationen
    // angeben und
    // cpu kosten //65000
    {
        return SCrypt.generate(password.getBytes(), salt, 64, 64, 64, 128);
    }

    public byte[] getBcrypt(byte[] salt, String password) throws NoSuchAlgorithmException, NoSuchProviderException
    {//
        return BCrypt.generate(password.getBytes(), salt, 8);

    }

}
