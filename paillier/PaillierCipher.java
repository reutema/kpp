package kpp.paillier;

import java.math.BigInteger;
import java.util.Random;

/*
 * Aufgabenstellung Paillier-Chiffre

Implementieren Sie die Paillier-Chiffre in der in der Vorlesung vorgestellten Weise.

Name der Klasse: PaillierCipher.java
Name des Packages: kpp.paillier
*/
/*
Attribute

    BigInteger p
    BigInteger q
    BigInteger g
    BigInteger n=p*q
    BigInteger lambda
*/
/*
Konstruktoren

    PaillierCipher(BigInteger p, BigInteger q, BigInteger g)
    PaillierCipher(BigInteger p, BigInteger q) => g wird passend generiert
*/
/*
Methoden

    BigInteger encrypt(BigInteger m, BigInteger r)
    BigInteger encryptGenRandom(BigInteger m) => r wird passend generiert
    BigInteger decrypt(BigInteger c)
*/
/*
Exceptions:

    Falls g nicht die Voraussetzungen erfüllt, soll die Exception "gInvalidException" geworfen werden.
    Falls p oder q nicht prim, soll die Exception "notPrimeException" geworfen werden.
    Falls r nicht teilerfremd zu n, soll die Exception "rInvalidException" geworfen werden.
*/
/*
Hinweise:
Sie brauchen die Ver und Entschlüsselung nur für BigInteger-Werte zu implementieren (keine Buchstaben).
 */

public class PaillierCipher
{

    BigInteger p;

    BigInteger q;

    BigInteger g;

    BigInteger n;

    BigInteger lambda;

    PaillierCipher(BigInteger p, BigInteger q, BigInteger g) throws notPrimeException, gInvalidException
    {
        if (!(p.isProbablePrime(1) && q.isProbablePrime(1)))
        {
            throw new notPrimeException("p or q is not prime");
        }
        this.p = p;
        this.q = q;
        setLamda(p, q);
        setN(p, q);
        if (!isGValid(g, n))
        {
            throw new gInvalidException("g does not fulfill the requirements");
        }
        this.g = g;

    }

    PaillierCipher(BigInteger p, BigInteger q) throws notPrimeException, gInvalidException
    { // => g wird passend generiert
        if (!(p.isProbablePrime(1) && q.isProbablePrime(1)))
        {
            throw new notPrimeException("p or q is not prime");
        }
        this.p = p;
        this.q = q;
        setLamda(p, q);
        setN(p, q);

        do
        {
            BigInteger a = getNumberGCDTo(n);
            BigInteger b = getNumberGCDTo(n);

            this.g = a.multiply(n).add(BigInteger.ONE).multiply(b.modPow(n, n));
        }
        while (!isGValid(g, n));
    }

    BigInteger encrypt(BigInteger m, BigInteger r) throws rInvalidException
    {
        isRelativelyPrime(r, n);
        BigInteger modulo = n.multiply(n);
        return g.modPow(m, modulo).multiply(r.modPow(n, modulo)).mod(modulo);
    }

    BigInteger encryptGenRandom(BigInteger m) throws rInvalidException
    { // => r wird passend generiert

        // hier r generieren
        BigInteger r;
        do
        {
            r = new BigInteger(n.bitLength(), new Random()).mod(n);
        }
        while (r.compareTo(n) != -1 && r.gcd(n).compareTo(BigInteger.ONE) == 0);

        return encrypt(m, r);
    }

    BigInteger decrypt(BigInteger c)
    {
        BigInteger modulo = n.multiply(n);

        return L(c.modPow(lambda, modulo)).multiply(L(g.modPow(lambda, modulo)).modInverse(modulo)).mod(n);
    }

    public void isRelativelyPrime(BigInteger r, BigInteger n) throws rInvalidException
    {
        if (r.gcd(n).compareTo(BigInteger.ONE) != 0)
        {
            throw new rInvalidException("r is not relatively prime to n");
        }
    }

    private BigInteger kgv(BigInteger m, BigInteger n)
    {
        BigInteger gcd = m.gcd(n);
        return m.multiply(n).divide(gcd);
    }

    private BigInteger L(BigInteger u)
    {
        return u.subtract(BigInteger.ONE).divide(n);
    }

    private BigInteger LInverse(BigInteger u)
    {
        return u.multiply(n).add(BigInteger.ONE);
    }

    private boolean isGValid(BigInteger g, BigInteger n)
    {
        BigInteger modulo = n.multiply(n);
        return g.gcd(modulo).compareTo(BigInteger.ONE) == 0 && L(g.modPow(lambda, modulo)).gcd(n).compareTo(BigInteger.ONE) == 0;
    }

    private BigInteger generateG()
    {
        BigInteger modulo = n.multiply(n);
        BigInteger g = lambda.modInverse(modulo);
        return g;
    }

    private BigInteger getNumberGCDTo(BigInteger modulo)
    {
        BigInteger a;
        do
        {
            a = new BigInteger(modulo.bitLength(), new Random()).mod(n);
        }
        while (a.gcd(modulo).compareTo(BigInteger.ONE) != 0);
        return a;
    }

    private void setLamda(BigInteger p, BigInteger q)
    {

        this.lambda = kgv(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
    }

    private void setN(BigInteger p, BigInteger q)
    {

        this.n = p.multiply(q);
    }

    public static void main(String[] args) throws gInvalidException, notPrimeException, rInvalidException
    {
        PaillierCipher pc = new PaillierCipher(new BigInteger("3"), new BigInteger("5"), new BigInteger("16"));

        BigInteger m = new BigInteger("3");
        BigInteger r = new BigInteger("11");
        BigInteger c = pc.encrypt(m, r);
        m = pc.decrypt(c);
        System.out.println(m);
        System.out.println(c);

    }

}
