package kpp.ecdh;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;

import org.bouncycastle.util.encoders.Hex;

public class ECDH {

	private KeyPair keyPair;
	private BigInteger p, a, b;
	int cofactor;
	private ECPoint basePoint;

	public ECDH(BigInteger p, BigInteger a, BigInteger b, BigInteger x, BigInteger y, int cofactor)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		this.p = p;
		this.a = a;
		this.b = b;
		this.basePoint = new ECPoint(x, y);
		this.cofactor = cofactor;

		this.keyPair = generateKeyPair();
	}

	public ECDH(BigInteger p, BigInteger a, BigInteger b, ECPoint basePoint, int cofactor)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		this.p = p;
		this.a = a;
		this.b = b;
		this.basePoint = basePoint;
		this.cofactor = cofactor;

		this.keyPair = generateKeyPair();
	}

	public PublicKey getPublicKey() {
		return keyPair.getPublic();
	}

	private KeyPair generateKeyPair()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDH");
		generator.initialize(getECParameterSpec(), new SecureRandom());
		return generator.generateKeyPair();
	}

	private ECParameterSpec getECParameterSpec() {

		ECFieldFp field = new ECFieldFp(p);

		EllipticCurve eCurve = new EllipticCurve(field, a, b);

		BigInteger n = getOrder(basePoint);

		return new ECParameterSpec(eCurve, basePoint, n, cofactor);
	}

	public void printPublicKey() {
		System.out.println(Hex.toHexString(getPublicKey().getEncoded()) + "\n");
	}

	public static boolean check(byte[] aSecret, byte[] bSecret) {

		System.out.println("Secret A : " + Hex.toHexString(aSecret));
		System.out.println("Secret B : " + Hex.toHexString(bSecret));
		System.out.println();
		return MessageDigest.isEqual(aSecret, bSecret);

	}

	public KeyAgreement getAgreement() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
		KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");

		keyAgree.init(keyPair.getPrivate());
		return keyAgree;
	}

	public byte[] generateSecret(PublicKey otherPersonPublicKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
		KeyAgreement keyAgreement = getAgreement();
		keyAgreement.doPhase(otherPersonPublicKey, true);
		return keyAgreement.generateSecret();
	}

	public static byte[][] generateSecret(KeyAgreement a, PublicKey aPublicKey, KeyAgreement b, PublicKey bPublicKey)
			throws InvalidKeyException, IllegalStateException {
		a.doPhase(bPublicKey, true);
		b.doPhase(aPublicKey, true);

		byte[] aSecret = a.generateSecret();
		byte[] bSecret = b.generateSecret();

		return new byte[][] { aSecret, bSecret };
	}

	public static void main(String[] args) {

		// y^2 = x^3+x+4 mod 41 und dem Base Point (0,2)

		BigInteger p = new BigInteger("41", 10);

		BigInteger a = new BigInteger("1", 10);
		BigInteger b = new BigInteger("4", 10);

		BigInteger x = new BigInteger("0", 10);
		BigInteger y = new BigInteger("2", 10);

		int cofactor = 1;

		try {
			ECDH ecdhA = new ECDH(p, a, b, x, y, cofactor);
			ECDH ecdhB = new ECDH(p, a, b, x, y, cofactor);

			PublicKey publicKeyA = ecdhA.getPublicKey();
			PublicKey publicKeyB = ecdhB.getPublicKey();

			ecdhA.printPublicKey();
			ecdhB.printPublicKey();

			KeyAgreement keyAgreementA = ecdhA.getAgreement();
			KeyAgreement keyAgreementB = ecdhB.getAgreement();

			byte[][] secrets = generateSecret(keyAgreementA, publicKeyA, keyAgreementB, publicKeyB);

			System.out.println("The secrets are " + (check(secrets[0], secrets[1]) ? "valid" : "not valid"));

		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException
				| InvalidKeyException | IllegalStateException e) {
			e.printStackTrace();
		}

	}

	private ECPoint addPoints(ECPoint p1, ECPoint p2) {

		if (p1.equals(ECPoint.POINT_INFINITY) || p2.equals(ECPoint.POINT_INFINITY)) {
			return ((p1.equals(ECPoint.POINT_INFINITY)) ? p2 : p1);
		}

		BigInteger x3, y3;
		BigInteger lambda = BigInteger.ZERO;
		BigInteger two = new BigInteger("2");
		BigInteger p1x = p1.getAffineX();
		BigInteger p2x = p2.getAffineX();
		BigInteger p1y = p1.getAffineY();
		BigInteger p2y = p2.getAffineY();

		if (p1x.compareTo(p2x) != 0) {
			lambda = (p2y.subtract(p1y)).multiply((p2x.subtract(p1x)).modInverse(p));
		} else if ((p1x.compareTo(p2x) == 0) && (p1y.compareTo(p2y.negate().mod(p2y)) == 0)) {
			return ECPoint.POINT_INFINITY;
		} else if (p1.equals(p2)) {
			lambda = ((BigInteger.valueOf(3).multiply(p1x.pow(2))).add(a))
					.multiply(((two.multiply(p1y)).modInverse(p)));
		}

		x3 = lambda.multiply(lambda).subtract(p1x).subtract(p2x).mod(p);
		y3 = lambda.multiply(p1x.subtract(x3)).subtract(p1y).mod(p);
		return new ECPoint(x3, y3);
	}

	private BigInteger getOrder(ECPoint point) {
		List<ECPoint> curvePoints = getCurvePoints();
		BigInteger order = BigInteger.ZERO;
		ECPoint current = new ECPoint(point.getAffineX(), point.getAffineY());
		for (int i = 0; i < curvePoints.size(); i++) {
			order = order.add(BigInteger.ONE);
			current = addPoints(point, current);
			if (current.equals(ECPoint.POINT_INFINITY)) {
				break;
			}
		}
		return order;
	}

	private List<ECPoint> getCurvePoints() {
		List<ECPoint> list = new ArrayList<>();

		for (BigInteger x = BigInteger.ZERO; x.compareTo(p) == -1; x = x.add(BigInteger.ONE)) {

			BigInteger tmp = calcOnEllipticCurve(x).mod(p);

			for (BigInteger a = BigInteger.ZERO; a.compareTo(p) == -1; a = a.add(BigInteger.ONE)) {
				if (tmp.compareTo(a.modPow(BigInteger.valueOf(2), p)) == 0) {
					list.add(new ECPoint(x, a));
				}
			}
		}

		list.add(ECPoint.POINT_INFINITY);

		return list;

	}

	private BigInteger calcOnEllipticCurve(BigInteger x) {
		return x.pow(3).add(a.multiply(x)).add(b).mod(p);
	}

}
