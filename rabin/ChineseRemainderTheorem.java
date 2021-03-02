package kpp.rabin;

import java.math.BigInteger;

public class ChineseRemainderTheorem
{
    BigInteger commonModul; // => speichert den gemeinsamen Modul gemäß
                            // CRT

    BigInteger commonX; // => speichert das Ergebnis des CRTs

    private BigInteger[] x;

    private BigInteger[] n;

    /*
     * Der Constructor übernimmt die Vektoren, prüft diese auf Zulässigkeit,
     * berechnet das Ergebnis gemäß CRT und speichert das Ergebnis in den beiden
     * Attributen commonModul und commonX. Falls die übergebenen Module nicht
     * paarweise teilerfremd sind, soll die Exception ModuliNotRPrimeException
     * geworfen werden. Falls die Länge der Vektoren x und n ungleich ist, soll
     * die Exception TupelsNotValidException geworfen werden.
     */

    public ChineseRemainderTheorem(BigInteger[] x, BigInteger[] n) throws ModuliNotRPrimeException, TupelsNotValidException, ArrayToShortException
    {
        if (x.length == n.length)
        {
            setCommonModul(BigInteger.ONE);
            setCommonX(BigInteger.ZERO);
            this.x = x;
            this.n = n;
            calcCRT();
        }
        else
        {
            throw new TupelsNotValidException("size of x unequal to size of n");
        }

    }

    /*
     * Diese Methode wird im Constructor aufgerufen und berechnet commonX und
     * commonModul nach dem in der Vorlesung beschriebenen Verfahren.Falls die
     * Module nicht paarweise teilerfremd sind, soll die Exception
     * ModuliNotRPrimeException geworfen werden.
     */

    private void calcCRT() throws ModuliNotRPrimeException, ArrayToShortException
    {
        int lengthOfN = n.length;
        if (lengthOfN > 1)
        {
            for (int i = 0, j = 1; i < lengthOfN; ++i, j = ((i + 1) % lengthOfN))
            {
                if (n[i].gcd(n[j]).compareTo(BigInteger.ONE) != 0)
                {
                    throw new ModuliNotRPrimeException("moduli not pairwise prime to each other");
                }
            }

            for (int i = 0; i < lengthOfN; i++)
            {
                setCommonModul(getCommonModul().multiply(n[i]));
                BigInteger p = BigInteger.ONE;
                for (int j = 0; j < lengthOfN; j++)
                {
                    if (i == j)
                    {
                        continue;
                    }
                    p = p.multiply(n[j]);
                }
                BigInteger result = x[i].multiply(p).multiply(p.modInverse(n[i]));
                setCommonX(getCommonX().add(result));
            }
            setCommonX(getCommonX().mod(getCommonModul()));
        }
        else
        {
            throw new ArrayToShortException("array must be bigger than 1");
        }
    }

    public BigInteger getCommonModul()
    {
        return commonModul;
    }

    public BigInteger getCommonX()
    {
        return commonX;
    }

    public void setCommonModul(BigInteger commonModul)
    {
        this.commonModul = commonModul;
    }

    public void setCommonX(BigInteger commonX)
    {
        this.commonX = commonX;
    }
}
