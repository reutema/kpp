package kpp.rabin;

import java.math.BigInteger;
import java.util.Random;

public class RabinCipher
{

    private BigInteger p, q;

    private BigInteger n; // => n = p*q

    /*
     * Der Constructor setzt alle Attribute und prüft
     *//*
        * 1. ob p = q = 3 mod 4
        *//*
           * 2. ob p und q prim sind
           *//*
              * 3. ob p<>q und wirft andernfalls die passende Exception
              */
    public RabinCipher(BigInteger p, BigInteger q) throws PrimeNotRabinValidException, pqNotPrimeException, pEqualsqException
    {

        if (isEqual3(p, q))
        {
            if (isPrime(p, q))
            {
                if (isNotEqual(p, q))
                {

                    this.p = p;
                    this.q = q;
                    this.n = p.multiply(q);

                }
                else
                {
                    throw new pEqualsqException("p equals q are not allowed");
                }
            }
            else
            {
                throw new pqNotPrimeException("p or q is not prime");
            }
        }
        else
        {
            throw new PrimeNotRabinValidException("prime is not rabin valid");
        }
    }

    /*
     * Hier muss nur eine passende Bitlänge angegeben werden und der Constructor
     * generiert p und q passend. Es muss gelten ob p = q = 3 mod 4, p und q
     * prim, p<>q Methoden
     */
    public RabinCipher(int keyLength)
    {
        BigInteger[] pq = genRabinKeys(keyLength);

        this.p = pq[0];
        this.q = pq[1];
        this.n = p.multiply(q);

    }

    // => verschlüsselt die Nachricht m zu m^2 mod n.
    public BigInteger encrypt(BigInteger m)
    {
        return m.modPow(new BigInteger("2"), n);
    }

    // Generiert p und q für den Contructor RabinCipher(int keyLength)
    private BigInteger[] genRabinKeys(int bitLength)
    {
        BigInteger p, q;

        do
        {
            p = BigInteger.probablePrime(bitLength, new Random());

        }
        while (isEqual3(p) && isPrime(p));

        do
        {
            q = BigInteger.probablePrime(bitLength, new Random());
        }
        while (isEqual3(q) && isPrime(q) && isNotEqual(p, q));

        return new BigInteger[]
        { p, q };
    }

    // Entschlüsselt den BigInteger c mit dem CRT und liefert die möglichen
    // Plaintexte
    public BigInteger[] decrypt(BigInteger c) throws ModuliNotRPrimeException, TupelsNotValidException, ArrayToShortException
    {
        BigInteger bi4 = new BigInteger("4");

        BigInteger x1 = c.modPow(p.add(BigInteger.ONE).divide(bi4), p);
        BigInteger x2 = c.modPow(q.add(BigInteger.ONE).divide(bi4), q);

        ChineseRemainderTheorem result1 = new ChineseRemainderTheorem(new BigInteger[]
        { x1, x2 }, new BigInteger[]
        { p, q });

        ChineseRemainderTheorem result2 = new ChineseRemainderTheorem(new BigInteger[]
        { x1, x2.negate().mod(q) }, new BigInteger[]
        { p, q });

        BigInteger[] plaintext = new BigInteger[4];

        plaintext[0] = result1.getCommonX();
        plaintext[1] = result2.getCommonX();

        plaintext[2] = plaintext[0].negate().mod(result1.getCommonModul());
        plaintext[3] = plaintext[1].negate().mod(result2.getCommonModul());

        return plaintext;
    }

    private boolean isEqual3(BigInteger p, BigInteger q)
    {

        return isEqual3(p) && isEqual3(q);
    }

    private boolean isEqual3(BigInteger number)
    {
        BigInteger bi3 = new BigInteger("3");
        BigInteger bi4 = new BigInteger("4");

        return number.mod(bi4).compareTo(bi3) == 0;
    }

    private boolean isPrime(BigInteger p, BigInteger q)
    {
        return isPrime(p) && isPrime(q);
    }

    private boolean isPrime(BigInteger number)
    {
        return number.isProbablePrime(1);
    }

    private boolean isNotEqual(BigInteger p, BigInteger q)
    {
        return !(p.compareTo(q) == 0);
    }
}
