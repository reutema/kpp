package kpp.elgamal;

import java.math.BigInteger;
import java.util.Random;

/*
 * Erstellen Sie ein Programm für die Ver- und Entschlüsselung nach Elgamal
nach der in der Vorlesung vorgestellten Weise in der Klasse

ElgamalCipher.java.

Package: kpp.elgamal
*/

/*
Attribute

BigInteger p; // Prim number
BigInteger g; // Primitivwurzel
BigInteger x; // Private Key
BigInteger y; // Public Key
*/
/*
Konstruktor

    public ElgamalCipher(int bitLength)

// Konstruktor, der alle Attribute generiert mit bitLength Bits für p

    public ElgamalCipher(BigInteger p, BigInteger g, BigInteger x)

// Konstruktor, der alle Attribute entgegennimmt und y berechnet
*/
/*
Exceptions

notPrimeException wird geworfen, wenn p nicht prim ist.
gNotPrimtiveRootException wird geworfen, wenn g keine Primitivwurzel mod p ist.
InvalidPrivateKeyException wird geworfen, falls x<2 oder x>p-1.
*/
/*
Methoden

BigInteger[] encrypt(BigInteger y, BigInteger m)

// Verschlüsselt m mit y zum Ciphertext.// Wirft eine RuntimeException, falls der angegebene Schlüssel nicht zum Attribut der Klasse passt oder m>p.

BigInteger decrypt(BigInteger x, BigInteger[] c)

// Entschlüsselt m mit x. // Wirft eine RuntimeException, falls der angegebene Schlüssel nicht zum Attribut der Klasse passt,
// oder einer der Ciphertexte >p oder falls mehr als zwei BigInteger entschlüsselt werden sollen.

static boolean isPrimitiveRoot(BigInteger g, BigInteger p) throws notPrimeException {

// Prüft, ob g eine Primitivwurzel mod p ist.// Muss nur für Primzahlen p mit p=2*q+1, q prim berechnet werden. Andernfalls => RuntimeException
*/
/*
Hinweis zu Existenz und Finden von Primitivwurzeln:
Bei großen Modulen p ist fast jedes zweite Element aus Z_p eine Primitivwurzel. Ob ein zufälliges Element Primitivwurzel ist, kann durch schnelle Tests entschieden werden.
Für den Sonderfall, dass die Primzahl p sich aus p=2*q+1 zusammensetzt (q=prim), lautet der Test:
Es ist g genau dann eine Primitivwurzel, falls beide folgenden Bedingungen erfüllt sind:
1. g^2 ≠ 1 mod p und
2. g^q ≠ 1 mod p
*/
public class ElgamalCipher
{

    public BigInteger p; // Prim number

    public BigInteger g; // Primitivwurzel

    public BigInteger x; // Private Key

    public BigInteger y; // Public Key

    public ElgamalCipher(int bitLength)
    {
        System.out.println("Konstruktor bitlength: " + bitLength);
        BigInteger q;
        BigInteger two = new BigInteger("2");
        do
        {
            this.p = BigInteger.probablePrime(bitLength - 1, new Random());
            q = p.subtract(BigInteger.ONE).divide(two);
        }
        while (!q.isProbablePrime(1));

        // this.g = generatePrimitiveRoot(p);

        for (BigInteger i = p.divide(two); i.compareTo(p) < 0; i = i.add(BigInteger.ONE))
        {
            try
            {
                if (isPrimitiveRoot(i, p))
                {
                    this.g = i;
                    break;
                }

            }
            catch (notPrimeException e)
            {
            }

        }

        System.out.println("konstruktor bitlength, after getPrimitiveRoot(" + p + ")");
        do
        {
            x = new BigInteger(p.bitLength(), new Random());
        }
        while (x.compareTo(p) >= 0); // TODO evtl. abaendern...
        System.out.println("kon. bitlength, after while");
        y = g.modPow(x, p);
        System.out.println("KonsBitLength; p: " + p + " g: " + " x: " + x + " y: " + y);
    }

    public ElgamalCipher(BigInteger p, BigInteger g, BigInteger x) throws notPrimeException, gNotPrimtiveRootException, InvalidPrivateKeyException
    {
        if (!isPrimitiveRoot(g, p))
        {
            throw new gNotPrimtiveRootException("g is not a primitive root");
        }
        if (x.compareTo(new BigInteger("2")) == -1 || x.compareTo(p.subtract(BigInteger.ONE)) == 1)
        {
            throw new InvalidPrivateKeyException("x is an invalide key");
        }

        this.p = p;
        this.g = g;
        this.x = x;
        this.y = g.modPow(x, p);
        System.out.println("Kons3; p: " + p + " g: " + " x: " + x + " y: " + y);
    }

    public BigInteger[] encrypt(BigInteger y, BigInteger m)
    {
        System.out.println("encrypt y: " + y + " m: " + m);
        if (this.y.compareTo(y) != 0 || m.compareTo(p) == 1)
        {
            throw new RuntimeException("parameters not valid");
        }
        else
        {
            BigInteger k;
            do
            {
                k = new BigInteger(p.bitLength(), new Random());
            }
            while (k.compareTo(BigInteger.ZERO) == 1 && k.compareTo(p.subtract(new BigInteger("2"))) == -1);

            return new BigInteger[]
            { g.modPow(k, p), y.modPow(k, p).multiply(m).mod(p) };
        }
    }

    public BigInteger decrypt(BigInteger x, BigInteger[] c)
    {
        System.out.println("decrypt x: " + x + " c: " + c[0] + " " + c[1]);
        if (this.x.compareTo(x) != 0 || c.length > 2 || c[0].compareTo(p) == 1 || c[1].compareTo(p) == 1)
        {
            throw new RuntimeException();
        }
        else
        {
            BigInteger tmp = c[1].multiply(c[0].modPow(x, p).modInverse(p)).mod(p);
            System.out.println("tmp: " + tmp);
            return tmp;
        }

    }

    public static boolean isPrimitiveRoot(BigInteger g, BigInteger p) throws notPrimeException
    {
        // Primzahlen p mit p=2*q+1, q prim berechnet werden. Andernfalls =>
        // RuntimeException
        BigInteger two = new BigInteger("2");
        BigInteger q = p.subtract(BigInteger.ONE).divide(two);

        System.out.println("g: " + g + " p: " + p + " q: " + q);
        if (p.isProbablePrime(1) && q.isProbablePrime(1))
        {

            boolean tmp = (g.compareTo(p) == -1) && (g.modPow(two, p).compareTo(BigInteger.ONE) != 0) && (g.modPow(q, p).compareTo(BigInteger.ONE) != 0);
            System.out.println("isPrimitiveRoot: " + tmp);
            return tmp;
        }
        else
        {
            System.out.println("excpetions p: " + p + " g: " + g + " q: " + q);
            throw new notPrimeException("p or q is not prime; p: " + p + " g: " + g + " q: " + q);
        }

    }

    public static BigInteger generatePrimitiveRoot(BigInteger p)
    {
        BigInteger g;
        boolean running = true;
        do
        {
            g = new BigInteger(p.bitLength() - 1, new Random()).mod(p);
            try
            {
                isPrimitiveRoot(g, p);
                running = false;
            }
            catch (notPrimeException e)
            {
            }
        }
        while (running);
        return g;
    }

    public static void main(String[] args) throws notPrimeException, gNotPrimtiveRootException, InvalidPrivateKeyException
    {
        ElgamalCipher el = new ElgamalCipher(100);
        System.out.println("...");
        System.out.println(el.p.bitLength() < 100);
        System.out.println(".....");
        System.out.println(ElgamalCipher.isPrimitiveRoot(el.g, el.p));
        BigInteger[] c;
        System.out.println(c = el.encrypt(el.y, new BigInteger("12")));
        System.out.println("...");
        System.out.println(el.decrypt(el.x, c));
        System.out.println("pause");

        System.err.println();

        ElgamalCipher el2 = new ElgamalCipher(el.p, el.g, el.x);
        System.out.println("...");
        System.out.println(el2.p.bitLength() < 100);
        System.out.println(".....");
        System.out.println(ElgamalCipher.isPrimitiveRoot(el2.g, el2.p));
        BigInteger[] c2;
        System.out.println(c2 = el2.encrypt(el2.y, new BigInteger("12")));
        System.out.println("...");
        System.out.println(el2.decrypt(el2.x, c2));
        System.out.println("Done");
    }

}
