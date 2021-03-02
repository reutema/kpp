package kpp.ec;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/*
 * 2) ECOverInt.class

Attribute
- int p; // Primzahl als Basis für Fp
- int a; // Parameter zur Definition der ec
- int b; // Parameter zur Definition der ec
- List<PointOnEC> curvePoints; // List of points on curve excluding INFINITY
- int numOfPoint; // number of points on curve incl. INFINITY

Konstruktor
public ECOverInt(int p, int a, int b) throws ECParamsIllegalException, PNotPrimeException
Setzt alle Attribute
Wirft eine ECParamsIllegalException, falls 4a^3+27b^2=0 mod p.
Wirft eine PNotPrimeException, falls p keine Primzahl ist.

Methoden
/
* Check is point is on ec.
* @param Point testPoint
* @return List of all Point on ec
*/

public class ECOverInt
{

    int p; // Primzahl als Basis für Fp

    int a; // Parameter zur Definition der ec

    int b; // Parameter zur Definition der ec

    List<PointOnEC> curvePoints; // List of points on curve excluding INFINITY

    int numOfPoint; // number of points on curve incl. INFINITY

    public enum EC
    {
        ONE, TWO, THREE
    };

    public ECOverInt(int p, int a, int b) throws ECParamsIllegalException, PNotPrimeException, ECNotImplementedException
    {
        System.out.println("\nKonstruktor");
        if (!isPPrime(p))
        {
            throw new PNotPrimeException("p is not prime");
        }
        this.p = p;
        System.out.println("p is valid = " + p);
        if (!isAAndBValid(a, b))
        {
            throw new ECParamsIllegalException("a or b is not valid! a = " + a + ", b = " + b);
        }
        this.a = a;
        this.b = b;
        System.out.println("a and b are valid a = " + a + ", b = " + b);

        this.curvePoints = getPointsOnECList();
        this.numOfPoint = curvePoints.size();
    }

    private boolean isPPrime(int p)
    {
        return BigInteger.valueOf(p).isProbablePrime(1);
    }

    private boolean isAAndBValid(int a, int b)
    {// 4a^3+27b^2=0 mod p
     // 13 -3 2 4 * (-3)^3 + 27 * 2^2 = 36 + 27 * 4 = 0 + 1 * 4 = 4
        return !((4 * (int) Math.pow(a, 3)) + (27 * (int) Math.pow(b, 2)) == 0);
    }

    public List<PointOnEC> getPointsOnEC() throws ECNotImplementedException
    {
        List<PointOnEC> list = new ArrayList<>();

        for (int x = 0; x < p; x++)
        {

            int tmp = getEllipticCurve(EC.THREE, x);

            for (int a = 0; a < p; a++)
            {
                if (modulo(tmp) == (modulo((a * a))))
                {
                    System.out.println("getPointsOnEC: add " + x + " " + a + "\nbecause " + tmp + " == " + (a * a));
                    list.add(new PointOnEC(x, a));
                }
            }
        }

        list.add(new PointOnEC(p + 1));

        return list;
    }

    public List<PointOnEC> getPointsOnECList() throws ECNotImplementedException
    {
        if (curvePoints == null)
        {
            this.curvePoints = getPointsOnEC();
        }
        return curvePoints;
    }

    /*
     * Check is point is on ec.
     * 
     * @param Point testPoint
     * 
     * @return List of all Point on ec
     */
    public boolean checkPointOnEC(PointOnEC testPoint) throws ECNotImplementedException
    {

        for (PointOnEC ecp : getPointsOnECList())
        {
            if (ecp.equals(testPoint))
            {
                return true;
            }
        }
        return false;
    }

    /*
     * Method to add different points on ec. (p+1, p+1) is the INFINITY point
     * 
     * @param Point1 p1
     * 
     * @param Point2 p2
     * 
     * @return Point p3 = p1+p2
     */
    public PointOnEC addPoints(PointOnEC p1, PointOnEC p2)
    {
        System.out.println("addPoints: " + p1.toString() + " " + p2.toString());

        if (isInfinity(p1) || isInfinity(p2))
        {
            return (isInfinity(p1) ? p2 : p1);
        }

        BigInteger x3, y3;
        BigInteger lambda = BigInteger.ZERO;
        BigInteger THREE = new BigInteger("3");
        BigInteger TWO = new BigInteger("2");
        BigInteger p1x = BigInteger.valueOf(p1.x);
        BigInteger p2y = BigInteger.valueOf(p2.y);

        if (p1.x != p2.x)
        {
            System.out.println("addPoints if1");
            lambda = lambda(p1, p2);
        }
        else if ((p1.x == p2.x) && (p1.y == (p2y.negate().mod(BigInteger.valueOf(p))).intValue()))
        /* ((p2.y * (-1) + (p2.y * p) % p)))) */ {
            System.out.println("addPoints if2");
            return new PointOnEC(p + 1);
        }
        else if (p1.equals(p2))
        {
            System.out.println("addPoints if3");
            lambda = lambda(p1);
        }

        x3 = lambda.multiply(lambda).subtract(p1x).subtract(BigInteger.valueOf(p2.x)).mod(BigInteger.valueOf(p));
        y3 = lambda.multiply(p1x.subtract(x3)).subtract(BigInteger.valueOf(p1.y)).mod(BigInteger.valueOf(p));
        System.out.println("addPoints: return " + x3 + " " + y3);
        return new PointOnEC(x3.intValue(), y3.intValue());
    }

    public boolean isInfinity(PointOnEC p1)
    {
        return p1.x == (p + 1) || p1.y == (p + 1);
    }

    public BigInteger lambda(PointOnEC p1)
    {
        BigInteger bip = BigInteger.valueOf(p);
        BigInteger two = BigInteger.valueOf(2);
        BigInteger p1x = BigInteger.valueOf(p1.x);
        BigInteger p1y = BigInteger.valueOf(p1.y);
        BigInteger bia = BigInteger.valueOf(a);

        return ((BigInteger.valueOf(3).multiply(p1x.pow(2))).add(bia)).multiply(((two.multiply(p1y)).modInverse(bip)));

    }

    public BigInteger lambda(PointOnEC p1, PointOnEC p2)
    {

        // hier erweitertetr Euklid implementieren um inverses zu berechnen
        BigInteger p2y = BigInteger.valueOf(p2.y);
        BigInteger p1y = BigInteger.valueOf(p1.y);
        BigInteger p2x = BigInteger.valueOf(p2.x);
        BigInteger p1x = BigInteger.valueOf(p1.x);
        BigInteger bip = BigInteger.valueOf(p);
        return (p2y.subtract(p1y)).multiply((p2x.subtract(p1x)).modInverse(bip));

    }

    /**
     * Get order of point.
     * 
     * @param Point
     *            to check
     * @return Order on Point
     * @throws ECNotImplementedException
     */
    public int getOrderOfPoint(PointOnEC PP)
    {
        System.out.println("getOrderOfPoint: " + PP);
        PointOnEC p3 = PP;
        PointOnEC infinity = new PointOnEC(p + 1);
        int counter = 1;

        while (!(p3.equals(infinity)))
        {
            p3 = addPoints(PP, p3);
            counter++;
        }

        System.out.println("counter = " + counter);

        return counter;
    }

    public int modulo(int value)
    {
        for (; value <= 0; value += p)
        {
        }
        return value % p;
    }

    public int getEllipticCurve(EC ec, int x) throws ECNotImplementedException
    {
        switch (ec)
        {
            case ONE:
                return modulo(((int) Math.pow(x, 3)) + (3 * x) + 9);
            case TWO: // 4a^3+27b^2
                return modulo((4 * ((int) Math.pow(a, 3))) + (27 * ((int) Math.pow(b, 2))));
            case THREE: // x^3 + x + 4 mod 7
                return modulo(((int) Math.pow(x, 3)) + x + 4);
            default:
                throw new ECNotImplementedException("elliptic curve is not implemented");
        }
    }

    public static void main(String[] args)
    {

        // test(13, -3, 2);

        // test(7, 1, 4);

    }

    public static void test(int p, int a, int b)
    {
        System.out.println("_____Start_new_test!_________");
        try
        {
            ECOverInt eco = new ECOverInt(p, a, b);

            System.out.println("p = " + eco.p);
            System.out.println("a = " + eco.a);
            System.out.println("b = " + eco.b);
            System.out.println("curvePoints.size: " + eco.curvePoints.size());
            eco.curvePoints.forEach(e -> System.out.println("curvePoints: " + e));
            System.out.println("numOfPoint: " + eco.numOfPoint);

        }
        catch (ECParamsIllegalException | PNotPrimeException
                        | ECNotImplementedException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        System.out.println("______End_test!____________");
    }
}

class ECNotImplementedException extends Exception
{
    public ECNotImplementedException(String message)
    {
        super(message);
    }
}