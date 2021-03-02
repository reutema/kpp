package kpp.rsa;

import java.math.BigInteger;
import java.util.Random;

public class RSACipher
{

    private BigInteger p;

    private BigInteger q;

    public BigInteger n; // n = p*q

    private BigInteger d;

    public BigInteger e;

    private BigInteger phin; // Eulersche phi-Funktion, phi(n) = (p-1)*(q-1)

    // -> Erzeugt alle Attribute passend, p und q sind Primzahlen mit Bitlänge
    // bitLength
    public RSACipher(int bitLength)
    {
        if (bitLength > 0)
        {
            this.p = BigInteger.probablePrime(bitLength, new Random());
            do
            {
                this.q = BigInteger.probablePrime(bitLength, new Random());
            }
            while (p.compareTo(q) == 0);

            this.phin = calculatePhiN(p, q);
            this.n = calculateN(p, q);
            // e = this.n = p.multiply(q);

            do
            {
                this.e = new BigInteger(bitLength, new Random());
            }
            while (checkForE(e, phin));

            this.d = e.modInverse(phin);
        }
        else
        {
            throw new IllegalArgumentException("length is to short");
        }
    }

    // -> Privater Schlüssel vorgegeben, die anderen Attribute werden passend
    // gesetzt
    public RSACipher(BigInteger p, BigInteger q, BigInteger e)
    {
        this.phin = calculatePhiN(p, q);
        if (!(p.compareTo(q) == 0) && checkForE(e, phin))
        {
            this.p = p;
            this.q = q;
            this.n = calculateN(p, q);
            this.e = e;
            this.d = e.modInverse(phin);
        }
        else
        {
            throw new IllegalArgumentException("p == q nicht erlaubt!");
        }
    }

    // -> Nur der öffentliche Schlüssel ist bekannt, die anderen Attribute sind
    // null.
    public RSACipher(BigInteger e, BigInteger n)
    {
        if (e.compareTo(BigInteger.ONE) == 1)
        {
            this.e = e;
            this.n = n;
        }
        else
        {
            throw new IllegalArgumentException("e to short");
        }
    }

    // -> verschlüsselt die Nachricht m
    public BigInteger encrypt(BigInteger m) throws MessageTooLongException
    {
        if (m.bitCount() <= n.bitCount() && m.bitCount() >= 0)
        {
            return m.modPow(e, n);
        }
        else
        {
            throw new MessageTooLongException("message is to long");
        }
    }

    public BigInteger decrypt(String m) throws PrivateKeyNotSetException
    {
        return decrypt(new BigInteger(m));
    }

    // -> entschlüsselt Ciphertext m
    public BigInteger decrypt(BigInteger m) throws PrivateKeyNotSetException
    {
        if (d != null)
        {
            return m.modPow(d, n);
        }
        else
        {
            throw new PrivateKeyNotSetException("private key (p,q,d) not set");
        }
    }

    private BigInteger calculatePhiN(BigInteger p, BigInteger q)
    {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    private BigInteger calculateN(BigInteger p, BigInteger q)
    {
        return p.multiply(q);
    }

    private boolean checkForE(BigInteger e, BigInteger phin)
    {
        // BigInteger phin = calculatePhiN(p, q);
        return e.compareTo(BigInteger.ONE) == 1 && e.compareTo(phin) == -1 && e.gcd(phin).compareTo(BigInteger.ONE) == 0;
    }

    private boolean checkForD(BigInteger d, BigInteger phin)
    {
        return d.compareTo(BigInteger.ONE) == 1 && d.compareTo(phin) == -1 && d.multiply(e).mod(phin).compareTo(BigInteger.ONE) == 0;
    }

    /*
     * Zu implementierende Exceptions
     * 
     * MessageTooLongException -> wird geworfen, wenn m>n
     * PrivateKeyNotSetException -> wird geworfen, wenn versucht wird ohne
     * Kenntnis des privaten Schlüssels zu entschlüsseln
     * 
     * Hinweise: Eine Nachricht kann optional als String eingelesen und in
     * BigInteger-Werte zum Verschlüsseln umgewandelt werden.
     */

}
