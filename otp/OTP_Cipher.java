package kpp.otp;

import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

public class OTP_Cipher
{

    byte[] key = null;

    byte[] ciphertext = null;

    byte[] plaintext = null;

    OTP_Base64Coder otpBase;

    Random r = null;

    public OTP_Cipher()
    {
        otpBase = new OTP_Base64Coder();
        r = new Random();
    }

    public void encrypt() throws RuntimeException
    {
        if (plaintext == null)
            throw new RuntimeException("plaintext not set");
        if (key == null)
            throw new RuntimeException("key not set");
        ciphertext = xorByte(plaintext, key);
    }

    public void decrypt() throws RuntimeException
    {
        if (ciphertext == null)
            throw new RuntimeException("ciphertext not set");
        if (key == null)
            throw new RuntimeException("key not set");
        plaintext = this.xorByte(ciphertext, key);
    }

    public void setRandomKey() throws RuntimeException
    {
        if (plaintext == null)
            throw new RuntimeException("no plaintext set");
        setRandomKey(plaintext.length);
    }

    public void setRandomKey(int size)
    {
        key = new byte[size];
        r.nextBytes(key);
    }

    public void setKnownKey(long knownKey)
    {
        if (ciphertext == null)
        {
            throw new RuntimeException("no ciphertext set");
        }
        key = new byte[ciphertext.length];
        // r = new Random((seedUniquifier() ^ knownKey));
        r = new Random((knownKey + 8682522807148012L));
        r.nextBytes(key);
    }

    public void setKnownKeyEnc(long knownKey)
    {
        if (plaintext == null)
        {
            throw new RuntimeException("no plaintext set");
        }
        key = new byte[plaintext.length];
        r.setSeed(knownKey);
        r.nextBytes(key);
    }

    public byte[] xorByte(byte[] a, byte[] b) throws RuntimeException
    {
        if (a == null || b == null || a.length != b.length)
            throw new RuntimeException("size does not match");

        byte[] c = new byte[a.length];
        for (int i = 0; i < a.length; i++)
        {
            c[i] = (byte) (a[i] ^ b[i]);
        }
        return c;
    }

    public byte[] getPlaintext()
    {
        return plaintext;
    }

    public String getEncodedPlaintext()
    {
        byte[] p = getPlaintext();
        return otpBase.encodeLines(p);
    }

    public byte[] getCiphertext()
    {
        return ciphertext;
    }

    public String getEncodedCiphertext()
    {
        byte[] c = getCiphertext();
        return otpBase.encodeLines(c);
    }

    public byte[] getKey()
    {
        return key;
    }

    public String getEncodedKey()
    {
        byte[] k = getKey();
        return otpBase.encodeLines(k);
    }

    public void resetKey()
    {
        key = null;
    }

    public void setPlaintextByString(String s)
    {
        plaintext = s.getBytes();
    }

    public void setPlaintextByBase64(String s)
    {
        plaintext = otpBase.decode(s);
    }

    public void setCiphertextByBase64(String s)
    {
        ciphertext = otpBase.decode(s);
    }

    public void setKeyByBase64(String s)
    {
        key = otpBase.decode(s);
    }

    private static long seedUniquifier()
    {
        // L'Ecuyer, "Tables of Linear Congruential Generators of
        // Different Sizes and Good Lattice Structure", 1999
        for (;;)
        {
            long current = seedUniquifier.get();
            long next = current * 181783497276652981L;
            if (seedUniquifier.compareAndSet(current, next))
                return next;
        }
    }

    private static final AtomicLong seedUniquifier = new AtomicLong(8682522807148012L);

}
