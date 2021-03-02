package kpp.otp;

import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

class MyRandom extends Random implements java.io.Serializable
{

    /** use serialVersionUID from JDK 1.1 for interoperability */
    static final long serialVersionUID = 3905348978240129619L;

    /**
     * The internal state associated with this pseudorandom number generator.
     * (The specs for the methods in this class describe the ongoing computation
     * of this value.)
     */
    private final AtomicLong seed;

    private static final long multiplier = 0x5DEECE66DL;

    private static final long addend = 0xBL;

    private static final long mask = (1L << 48) - 1;

    private static final double DOUBLE_UNIT = 0x1.0p-53; // 1.0 / (1L << 53)

    // IllegalArgumentException messages
    static final String BadBound = "bound must be positive";

    static final String BadRange = "bound must be greater than origin";

    static final String BadSize = "size must be non-negative";

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

    public MyRandom(long seed)
    {
        seed = (seedUniquifier() ^ seed);
        if (getClass() == MyRandom.class)
            this.seed = new AtomicLong(initialScramble(seed));
        else
        {
            // subclass might have overriden setSeed
            this.seed = new AtomicLong();
            setSeed(seed);
        }
    }

    /**
     * Generates random bytes and places them into a user-supplied byte array.
     * The number of random bytes produced is equal to the length of the byte
     * array.
     *
     * <p>
     * The method {@code nextBytes} is implemented by class {@code Random} as if
     * by:
     * 
     * <pre>
     *  {@code
     * public void nextBytes(byte[] bytes) {
     *   for (int i = 0; i < bytes.length; )
     *     for (int rnd = nextInt(), n = Math.min(bytes.length - i, 4);
     *          n-- > 0; rnd >>= 8)
     *       bytes[i++] = (byte)rnd;
     * }}
     * </pre>
     *
     * @param bytes
     *            the byte array to fill with random bytes
     * @throws NullPointerException
     *             if the byte array is null
     * @since 1.1
     */
    public void nextBytes(byte[] bytes)
    {
        for (int i = 0, len = bytes.length; i < len;)
            for (int rnd = nextInt(), n = Math.min(len - i, Integer.SIZE / Byte.SIZE); n-- > 0; rnd >>= Byte.SIZE)
                bytes[i++] = (byte) rnd;
    }

    private static long initialScramble(long seed)
    {
        return (seed ^ multiplier) & mask;
    }

    /**
     * Sets the seed of this random number generator using a single {@code long}
     * seed. The general contract of {@code setSeed} is that it alters the state
     * of this random number generator object so as to be in exactly the same
     * state as if it had just been created with the argument {@code seed} as a
     * seed. The method {@code setSeed} is implemented by class {@code Random}
     * by atomically updating the seed to
     * 
     * <pre>
     * {@code (seed ^ 0x5DEECE66DL) & ((1L << 48) - 1)}
     * </pre>
     * 
     * and clearing the {@code haveNextNextGaussian} flag used by
     * {@link #nextGaussian}.
     *
     * <p>
     * The implementation of {@code setSeed} by class {@code Random} happens to
     * use only 48 bits of the given seed. In general, however, an overriding
     * method may use all 64 bits of the {@code long} argument as a seed value.
     *
     * @param seed
     *            the initial seed
     */
    // synchronized public void setSeed(long seed)
    // {
    // this.seed.set(initialScramble(seed));
    // haveNextNextGaussian = false;
    // }
    //
    // private double nextNextGaussian;
    //
    // private boolean haveNextNextGaussian = false;

}