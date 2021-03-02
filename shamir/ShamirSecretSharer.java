/**
 * Aufgabenstellung
 * Implementieren Sie das Secret Sharing nach Shamir nach der in der Vorlesung vorgestellten Weise.
 * Details zu den Attributen, Konstruktoren und Methoden finden Sie im beigefügtem "Klassengerüst".
 * 	
 * Package: kpp.shamir
 * Klassenname: ShamirSecretSharer
 * @author knorr@hochschule-trier.de
 * @date Nov. 2018
 * 
 */

package kpp.shamir;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class ShamirSecretSharer {
	final int numberOfPeers; // Anzahl der Personen, auf die das Geheimnis verteilt wird
	final int threshold; // Anzahl der Personen, die zur Rekonstruktion des Geheimnisses benötigt werden.
	final BigInteger p; // Primzahl, über der gerechnet wird
	private BigInteger secret; // das Geheimnis
	private BigInteger[] coefficients; // Koeffizienten des Polynoms (ohne secret)
	BigInteger[] shares; // die Stützstellen, die verteilt werden

	/**
	 * Constructor without Secret This constructor is used to recover the secret
	 * without knowing the original secret The passed parameters are set as class
	 * attributes.
	 * 
	 * @param numberOfPeers the number of peers among which the secret is shared.
	 * @param threshold     number of peers that must be available for secret
	 *                      reconstruction.
	 * @param p             the prime field representing the group we are operating
	 *                      on.
	 * @throws RuntimeException if not threshold<=numberOfPeers<p or p negative of p
	 *                          not prime
	 */
	public ShamirSecretSharer(int numberOfPeers, int threshold, BigInteger p) {

		checkParameters(numberOfPeers, threshold, p);

		this.numberOfPeers = numberOfPeers;
		this.threshold = threshold;
		this.p = p;

	}

	private void checkParameters(int numberOfPeers, int threshold, BigInteger p) {

		if (numberOfPeers < 1 || threshold < 1 || p.compareTo(BigInteger.ZERO) == -1) {
			throw new RuntimeException("No negative parameters allowed");
		}
		if (threshold > numberOfPeers) {
			throw new RuntimeException("threshold must be a number between 0 and numberOfPeers");
		}
		if (p.compareTo(BigInteger.valueOf(numberOfPeers)) <= 0) {
			throw new RuntimeException("p must be bigger than numberOfPeers");
		}
		if (!p.isProbablePrime(100)) {
			throw new RuntimeException("p must be prime");
		}

	}

	/**
	 * Constructor with knowledge of Secret and Coefficients Creates shares with
	 * createShares() and sets random coefficients The passed parameters are set as
	 * class attributes.
	 *
	 * @param numberOfPeers the number of peers among which the secret is shared.
	 * @param threshold     number of peers that must be available for secret
	 *                      reconstruction.
	 * @param p             the prime field representing the group we are operating
	 *                      on.
	 * @param coefficients  the coefficients of the polynomial
	 * @throws RuntimeException if not threshold<=numberOfPeers<p or p negative of p
	 *                          not prime
	 */
	public ShamirSecretSharer(int numberOfPeers, int threshold, BigInteger p, BigInteger secret,
			BigInteger[] coefficients) {

		this(numberOfPeers, threshold, p);

		this.secret = secret;
		setCoefficients(coefficients);

	}

	/**
	 * Constructor with knowledge of Secret and without Coefficients The
	 * Coefficients will be randomly created. The passed parameters are set as class
	 * attributes. Creates shares with createShares()
	 * 
	 * @param numberOfPeers the number of peers among which the secret is shared.
	 * @param threshold     number of peers that must be available for secret
	 *                      reconstruction.
	 * @param p             the prime field representing the group we are operating
	 *                      on.
	 * @param secret        the secret to be shared
	 * @throws RuntimeException if not threshold<=numberOfPeers<p or p negative of p
	 *                          not prime
	 */
	public ShamirSecretSharer(int numberOfPeers, int threshold, BigInteger p, BigInteger secret) {

		this(numberOfPeers, threshold, p);

		if (secret.compareTo(p) >= 0) {
			throw new RuntimeException("secret can not be bigger than p");
		}
		this.secret = secret;
		createRandomCoefficients();
		createShares();
	}

	private void createRandomCoefficients() {
		BigInteger[] coefficients = new BigInteger[threshold];
		SecureRandom sRandom = new SecureRandom();

		coefficients[0] = secret;
		for (int i = 1; i < coefficients.length; i++) {
			coefficients[i] = new BigInteger(numberOfPeers - 1, sRandom);
		}

		this.coefficients = coefficients;

	}

	/**
	 * Create the shares using the polynomial, secret and coefficients setting the
	 * coefficients attribute of the class The x-coordinates of the shares are
	 * 1,2,3,...
	 */
	void createShares() {

		BigInteger[] shares = new BigInteger[numberOfPeers];

		for (int i = 0; i < shares.length; i++) {

			BigInteger bi = BigInteger.valueOf(i + 1);
			shares[i] = getNewShare(bi);

//			shares[i] = coefficients[i /* % threshold */].multiply(tempValue.modPow(tempValue, p));
		}

		this.shares = shares;

	}

	private BigInteger getNewShare(BigInteger bi) {

		BigInteger result = secret;

		for (int i = 1; i < threshold - 1; i++) {

			result = result.add(bi.pow(i).multiply(coefficients[i]));

		}

		return result;

	}

	/**
	 * Sets coefficients of the polynomial according to values passed to constructor
	 * coefficient[0]=secret The passed coeffs are set to attribute coeffs starting
	 * with index 1.
	 * 
	 * @param coefficients coefficients of polynomial
	 * @throws RuntimeException if length of coeffs does not match.
	 */
	private void setCoefficients(BigInteger[] coeffs) {
		if (coeffs.length <= 1) {
			throw new RuntimeException("number of coefficients must be bigger than 1");
		}
		if (coeffs.length >= threshold) {
			throw new RuntimeException("number of coefficients must be smaller than size of threshold");
		}
		BigInteger[] coefficients;
		if (coeffs[0] == null && coeffs[1] != null) {
			coefficients = new BigInteger[coeffs.length];
			coefficients[0] = secret;
			for (int i = 1; i < coefficients.length; i++) {
				coefficients[i] = coeffs[i];
			}
		} else {
			coefficients = new BigInteger[coeffs.length + 1];
			coefficients[0] = secret;
			for (int i = 1; i < coefficients.length; i++) {
				coefficients[i] = coeffs[i - 1];
			}
		}
		this.coefficients = coefficients;
	}

	/**
	 * Recovers secret using the Lagrange weights
	 * 
	 * @param indices x-values of the shares
	 * @param shares  y-values of the shares
	 * @return recovered secret
	 * @throws RuntimeException if arrays do not match in length, if indices are too
	 *                          small or too large, if the number of indices is too
	 *                          small or too large, if indices are <1 or >p if
	 *                          indices contains duplicate entries
	 */
	BigInteger recoverSecret(int[] indices, BigInteger[] shares) {

		// Ueberpruefung der Parameter auf zulaessige Werte
		if (indices.length != shares.length) {
			throw new RuntimeException("Length of indices not equals to lenght of shares");
		}

		for (int i = 0; i < indices.length; i++) {
			int value = indices[i];
			if (value < 1 || p.compareTo(BigInteger.valueOf(value)) <= 0) {
				throw new RuntimeException("indice " + value + " is not valid");
			}

			for (int j = 0; j < indices.length; j++) {
				if (value == indices[j] && i != j) {
					throw new RuntimeException("indice " + value + " has duplicate on index " + j);
				}
			}
		}

		// Beginn der eigentlichen Berechnung
		BigInteger result = BigInteger.ZERO;
		System.out.println("P = " + p);
		for (int i = 0; i < shares.length; i++) {

			result = result.add(getTempResultWi(indices, i, shares[i])).mod(p);

		}
		System.out.println(">>> secret = " + secret + "\n>>> s = " + result.mod(p));
		return result.mod(p);

	}

	private BigInteger getTempResultWi(int[] indices, int i, BigInteger yi) {

		BigInteger tempResultWi = BigInteger.ONE;
		BigInteger xi = BigInteger.valueOf(indices[i]);

		for (int j = 0; j < indices.length; j++) {

			if (i == j || indices[i] == indices[j]) {
				continue;
			}

			BigInteger xj = BigInteger.valueOf(indices[j]);
			BigInteger tempResultInBrackets = (xj.subtract(xi)).modInverse(p);

			tempResultWi = xj.multiply(tempResultInBrackets).multiply(tempResultWi).mod(p);

		}

		return yi.multiply(tempResultWi).mod(p);

	}

	public <T> void printArray(String name, T[] array) {
		System.out.println("--------------------");
		System.out.println("Print array: " + name);
		for (T t : array) {
			System.out.println(t.toString());
		}
		System.out.println("--------------------");
	}

	@Override
	public String toString() {
		return "ShamirSecretSplitter [numberOfPeers=" + numberOfPeers + ", threshold=" + threshold + ", p=" + p
				+ ", secret=" + secret + ", coefficients=" + Arrays.toString(coefficients) + ", shares="
				+ Arrays.toString(shares) + "]";
	}

}