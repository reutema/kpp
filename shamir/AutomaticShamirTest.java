package kpp.shamir;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.Test;

public class AutomaticShamirTest {

	@Test(expected = RuntimeException.class)
	public void testThresholdLargerNumberOfPeers() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 7;

		new ShamirSecretSharer(numberOfPeers, threshold, p);
	}

	@Test(expected = RuntimeException.class)
	public void testNumberOfPeersLargerp() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 25;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(29);

		new ShamirSecretSharer(numberOfPeers, threshold, p, secret);
	}

	@Test(expected = RuntimeException.class)
	public void testSecretLargerp() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(29);

		new ShamirSecretSharer(numberOfPeers, threshold, p, secret);
	}

	// p not prime
	@Test(expected = RuntimeException.class)
	public void testpNotPrime() throws Exception {
		BigInteger p = BigInteger.valueOf(18);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(9);

		new ShamirSecretSharer(numberOfPeers, threshold, p, secret);
	}

	// p negative
	@Test(expected = RuntimeException.class)
	public void testpNegative() throws Exception {
		BigInteger p = BigInteger.valueOf(-29);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(9);

		new ShamirSecretSharer(numberOfPeers, threshold, p, secret);
	}

	// 3 instead of 2 coefficients
	@Test(expected = RuntimeException.class)
	public void testWrongNumberCoeff() throws Exception {

		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(11);
		BigInteger[] coefficients = new BigInteger[] { BigInteger.valueOf(8), BigInteger.valueOf(8),
				BigInteger.valueOf(7) };

		new ShamirSecretSharer(numberOfPeers, threshold, p, secret, coefficients);

	}

	// 1 instead of 2 coefficients
	@Test(expected = RuntimeException.class)
	public void testWrongNumberCoeff2() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(11);
		BigInteger[] coefficients = new BigInteger[] { BigInteger.valueOf(8) };

		new ShamirSecretSharer(numberOfPeers, threshold, p, secret, coefficients);
	}

	@Test(expected = RuntimeException.class)
	public void testDuplicateIndices() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(11);
		BigInteger[] coefficients = new BigInteger[] { BigInteger.valueOf(8), BigInteger.valueOf(7) };

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p, secret, coefficients);

		int[] ind = { 3, 3, 5 };
		BigInteger[] shares = new BigInteger[] { BigInteger.valueOf(3), BigInteger.valueOf(7), BigInteger.valueOf(5) };

		s.recoverSecret(ind, shares);
	}

	// Index negative
	@Test(expected = RuntimeException.class)
	public void testShareInputError1() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(11);
		BigInteger[] coefficients = new BigInteger[] { BigInteger.valueOf(8), BigInteger.valueOf(7) };

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p, secret, coefficients);

		int[] ind = { -1, 3, 5 };
		BigInteger[] shares = new BigInteger[] { BigInteger.valueOf(3), BigInteger.valueOf(7), BigInteger.valueOf(5) };

		s.recoverSecret(ind, shares);
	}

	// One index is 0
	@Test(expected = RuntimeException.class)
	public void testShareInputError2() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(11);
		BigInteger[] coefficients = new BigInteger[] { BigInteger.valueOf(8), BigInteger.valueOf(7) };

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p, secret, coefficients);

		int[] ind = { 0, 3, 7 };
		BigInteger[] shares = new BigInteger[] { BigInteger.valueOf(3), BigInteger.valueOf(7), BigInteger.valueOf(5) };

		s.recoverSecret(ind, shares);
	}

	// Length of indices and shares not equal
	@Test(expected = RuntimeException.class)
	public void testShareInputError3() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(11);
		BigInteger[] coefficients = new BigInteger[] { BigInteger.valueOf(8), BigInteger.valueOf(7) };

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p, secret, coefficients);

		int[] ind = { 0, 3, 4 };
		BigInteger[] shares = new BigInteger[] { BigInteger.valueOf(3), BigInteger.valueOf(5) };

		s.recoverSecret(ind, shares);
	}

	@Test
	public void testSkriptExample1() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(11);
		BigInteger[] coefficients = new BigInteger[] { BigInteger.valueOf(8), BigInteger.valueOf(7) };

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p, secret, coefficients);

		int[] ind = { 2, 3, 5 };
		BigInteger[] shares = new BigInteger[] { BigInteger.valueOf(3), BigInteger.valueOf(7), BigInteger.valueOf(5) };

		BigInteger recoveredSecret = s.recoverSecret(ind, shares);

		assertEquals(secret, recoveredSecret);

	}

	@Test
	public void testSkriptExample2() throws Exception {

		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(11);
		BigInteger[] coefficients = new BigInteger[] { BigInteger.valueOf(8), BigInteger.valueOf(7) };

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p, secret, coefficients);

		int[] ind = { 2, 3, 4 };
		BigInteger[] shares = new BigInteger[] { BigInteger.valueOf(3), BigInteger.valueOf(7), BigInteger.valueOf(12) };

		BigInteger recoveredSecret = s.recoverSecret(ind, shares);

		assertEquals(secret, recoveredSecret);

	}

	// Secret is recovered without passing it to constructor
	@Test
	public void testSkriptExample3() throws Exception {
		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p);

		int[] ind = { 1, 3, 4 };
		BigInteger[] shares = new BigInteger[] { BigInteger.valueOf(0), BigInteger.valueOf(7), BigInteger.valueOf(12) };

		BigInteger recoveredSecret = s.recoverSecret(ind, shares);

		assertEquals(BigInteger.valueOf(11), recoveredSecret);
	}

	// Secret is recovered without passing it to constructor
	@Test
	public void testSkriptExample4TwistedIndices() throws Exception {

		BigInteger p = BigInteger.valueOf(13);
		int numberOfPeers = 5;
		int threshold = 3;

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p);

		int[] ind = { 4, 3, 2 };
		BigInteger[] shares = new BigInteger[] { BigInteger.valueOf(12), BigInteger.valueOf(7), BigInteger.valueOf(3) };

		BigInteger recoveredSecret = s.recoverSecret(ind, shares);

		assertEquals(BigInteger.valueOf(11), recoveredSecret);
	}

	// Aufgabe vom WS2012
	@Test
	public void testMediumSizeScenario() throws Exception {

		BigInteger p = BigInteger.valueOf(1031);
		int numberOfPeers = 10;
		int threshold = 4;

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p);

		int[] ind = { 947618, 949685, 947685, 946757 };
		for (int i = 0; i < ind.length; i++)
			ind[i] = (ind[i] % p.intValue());

		BigInteger[] shares = new BigInteger[] { BigInteger.valueOf(191), BigInteger.valueOf(144),
				BigInteger.valueOf(59), BigInteger.valueOf(662) };

		assertEquals(BigInteger.valueOf(42), s.recoverSecret(ind, shares));

	}

	@Test
	public void testLargeScenario() throws Exception {
		BigInteger p = BigInteger.probablePrime(500, new SecureRandom());
		int numberOfPeers = 10;
		int threshold = 3;
		BigInteger secret = BigInteger.valueOf(29);

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p, secret);
		int[] ind = { 1, 2, 3 };
		BigInteger[] shares = new BigInteger[threshold];
		for (int i = 0; i < threshold; i++)
			shares[i] = s.shares[i];
		System.out
				.println("\n\ntestLargeScenario, secret: " + secret + ", calc secret: " + s.recoverSecret(ind, shares));
		s.printArray("testLargeScenario shares", shares);

		assertEquals(secret, s.recoverSecret(ind, shares));

	}

	@Test
	public void tesHugeScenario() throws Exception {

		BigInteger p = BigInteger.probablePrime(1000, new SecureRandom());
		int numberOfPeers = 100;
		int threshold = 7;
		BigInteger secret = BigInteger.valueOf(29);

		ShamirSecretSharer s = new ShamirSecretSharer(numberOfPeers, threshold, p, secret);
		int[] ind = { 20, 10, 30, 42, 80, 90, 99 };
		BigInteger[] shares = new BigInteger[threshold];

		for (int i = 0; i < threshold; i++) {
			shares[i] = s.shares[ind[i] - 1];
		}
		System.out.println(s.toString());
		assertEquals(secret, s.recoverSecret(ind, shares));

	}

}
