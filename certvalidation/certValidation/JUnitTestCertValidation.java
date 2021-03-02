package kpp.certvalidation.certValidation;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CRLReason;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.junit.BeforeClass;
import org.junit.Test;

import kpp.certvalidation.CertificateGenerator;
import kpp.certvalidation.CertificateRevocationListGenerator;
import kpp.certvalidation.MyCertificateGenerator;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CRLReasonCodeExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class JUnitTestCertValidation {

	private static final long SECOND = 1000;
	private static final long MINUTE = 60 * SECOND;
	private static final long HOUR = 60 * MINUTE;
	private static final long DAY = 24 * HOUR;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		// CertPathValidatorException.BasicReason
		// PKIXReason
		//
		// java.security.cert.CRLReason
		// org.bouncycastle.asn1.x509.CRLReason
		System.out.println(CRLReasonCodeExtension.NAME);
		int r = org.bouncycastle.asn1.x509.CRLReason.AA_COMPROMISE;
		java.security.cert.CRLReason r2 = java.security.cert.CRLReason.AA_COMPROMISE;
		java.security.cert.CRLReason r3 = CRLReason.UNUSED;
	}

	@Test // (expected = PKIXReason.ex)
	public void test_EXPIRED_Reason() throws Exception {

		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();

		// Änderung hier vorgenommen! ODER param.setDate(tomorrow);
		Date tomorrow = new Date(now.getTime());
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		KeyPair fakeRootPair = CertificateGenerator.generateRSAKeyPair();
//		X509Certificate fakeRootCert = CertificateGenerator.generateEndEntityCert(fakeRootPair.getPublic(), caKey, caCert, notBefore, notAfter)
//		TODO hier änderung vornehmen
//x509Certificate fakeCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(), caKey, caCert, notBefore, notAfter)
		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		certChain.add(interCert);
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//			System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//					+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//					// "\n CertPath " + e.getCertPath() +
//					"\n Index of faulty cert: " + e.getIndex());

			assertEquals(CertPathValidatorException.BasicReason.EXPIRED, e.getReason());
		}
	}

	@Test
	public void test_REVOKED_Reason() throws Exception {
		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Generierung der CRLs
		// Änderung hier vorgenommen!
		BigInteger revokedSerialNumber = endCert.getSerialNumber(); // == serialNumber of endCert

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		certChain.add(interCert);
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//			System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//					+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//					// "\n CertPath " + e.getCertPath() +
//					"\n Index of faulty cert: " + e.getIndex());

		}
	}

	@Test
	public void test_NOT_YET_VALID_Reason() throws Exception {

		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		// Änderung hier vorgenommen
		Date tomorrow = new Date(now.getTime() + 2 * DAY);
		Date yesterday = new Date(now.getTime() + DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		certChain.add(interCert);
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//			System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//					+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//					// "\n CertPath " + e.getCertPath() +
//					"\n Index of faulty cert: " + e.getIndex());

			assertEquals(CertPathValidatorException.BasicReason.NOT_YET_VALID, e.getReason());
		}
	}

	@Test
	public void test_UNDETERMINED_REVOCATION_STATUS_Reason() throws Exception {
		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		// Änderung hier vorgenommen! ODER ein Element nicht der Extensionliste
		// hinzufügen ODER param.setDate(yesterday);
		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(interCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		certChain.add(interCert);
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//			System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//					+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//					// "\n CertPath " + e.getCertPath() +
//					"\n Index of faulty cert: " + e.getIndex());

			assertEquals(CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS, e.getReason());

		}
	}

	@Test
	public void test_INVALID_KEY_USAGE_Reason() throws Exception {

		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();

// Hier Änderung vorgenommen!
		for (int i = 0; i < 2; i++) {
			certChain.add(endCert);
			certChain.add(interCert);
		}

		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//			System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//					+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//					// "\n CertPath " + e.getCertPath() +
//					"\n Index of faulty cert: " + e.getIndex());

			assertEquals(PKIXReason.INVALID_KEY_USAGE, e.getReason());
		}
	}

	@Test
	public void test_ALGORITHM_CONSTRAINED_Reason() throws Exception {
		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		// hier Änderung vorgenommen SHA3-512 -> MD5
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = MyCertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, "MD5WithRSAEncryption", yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		certChain.add(interCert);
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//			System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//					+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//					// "\n CertPath " + e.getCertPath() +
//					"\n Index of faulty cert: " + e.getIndex());

			assertEquals(CertPathValidatorException.BasicReason.ALGORITHM_CONSTRAINED, e.getReason());
		}
	}

	@Test
	public void test_INVALID_NAME_Reason() throws Exception {
		try {
			String algorithm = "RSA";
			KeyPair pair = CertificateGenerator.generateRSAKeyPair();

			PrivateKey privkey = pair.getPrivate();
			X509CertInfo info = new X509CertInfo();
			Date from = new Date();
			Date to = new Date(from.getTime() + DAY);
			CertificateValidity interval = new CertificateValidity(from, to);
			BigInteger sn = new BigInteger(64, new SecureRandom());
			X500Name owner = new X500Name("Exception");

			info.set(X509CertInfo.VALIDITY, interval);
			info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
			info.set(X509CertInfo.SUBJECT, owner);
			info.set(X509CertInfo.ISSUER, owner);
			info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
			info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
			AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
			info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

			// Sign the cert to identify the algorithm that's used.
			X509CertImpl cert = new X509CertImpl(info);
			cert.sign(privkey, algorithm);

			// Update the algorith, and resign.
			algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
			info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
			cert = new X509CertImpl(info);
			cert.sign(privkey, algorithm);
		} catch (CertPathValidatorException e) {
			assertEquals(PKIXReason.INVALID_NAME, e.getReason());
		}
	}

	@Test
	public void test_NAME_CHAINING_Reason() throws Exception {
		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Änderung hier vorgenommen
		endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(), endPair.getPrivate(), endCert,
				new Date(yesterday.getTime() + DAY), new Date(tomorrow.getTime() + DAY));

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		certChain.add(interCert);
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//			System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//					+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//					// "\n CertPath " + e.getCertPath() +
//					"\n Index of faulty cert: " + e.getIndex());

			assertEquals(PKIXReason.NAME_CHAINING, e.getReason());

		}
	}

	@Test
	public void test_NO_TRUST_ANCHOR_Reason() throws Exception {
		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		certChain.add(interCert);
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");

		// Hier Änderung vorgenommen!
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(endCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//			System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//					+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//					// "\n CertPath " + e.getCertPath() +
//					"\n Index of faulty cert: " + e.getIndex());

			assertEquals(PKIXReason.NO_TRUST_ANCHOR, e.getReason());
		}

	}

	@Test
	public void test_NOT_CA_CERT_Reason() throws Exception {
		throw new Exception();
	}

	@Test
	public void test_PATH_TOO_LONG_Reason() throws Exception {
		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		// Hier Änderung vorgenommen
		for (int i = 0; i < 1; i++) {
			certChain.add(interCert);
		}
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
			System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
					+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
					// "\n CertPath " + e.getCertPath() +
					"\n Index of faulty cert: " + e.getIndex());

			assertEquals(PKIXReason.PATH_TOO_LONG, e.getReason());

		}
	}

	@Test
	public void test_INVALID_SIGNATURE_Reason() throws Exception {
		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Hier Änderung vorgenommen!
		KeyPair fakePair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);

		// Hier Änderung vorgenommen!
		X509Certificate fake = CertificateGenerator.generateRootCert(fakePair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(), fakePair.getPrivate(),
				interCert, yesterday, tomorrow);

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		certChain.add(interCert);
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//					System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//							+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//							// "\n CertPath " + e.getCertPath() +
//							"\n Index of faulty cert: " + e.getIndex());

			assertEquals(CertPathValidatorException.BasicReason.INVALID_SIGNATURE, e.getReason());

		}
	}

	@Test
	public void test_INVALID_POLICY_Reason() throws Exception {
		throw new Exception();
	}

	@Test
	public void test_UNRECOGNIZED_CRIT_EXT_Reason() throws Exception {
		// Schlüssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten für die Gültigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		// Änderung hier vorgenommen! Eigene Methode aufgerufen
		X509Certificate endCert = MyCertificateGenerator.generateEndEntityCertForUNRECOGNIZED_CRIT_EXT(
				endPair.getPublic(), interPair.getPrivate(), interCert, yesterday, tomorrow);

		// Generierung der CRLs
		BigInteger revokedSerialNumber = BigInteger.valueOf(2);

		X509CRL rootCRL = CertificateRevocationListGenerator.createCRL(rootCert, rootPair.getPrivate(),
				revokedSerialNumber);
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, interPair.getPrivate(),
				revokedSerialNumber);

		// Erstellung des Zertifizierungspfades
		List<X509Extension> list = new ArrayList<X509Extension>();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance("Collection", params);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certChain = new ArrayList<X509Certificate>();
		certChain.add(endCert);
		certChain.add(interCert);
		CertPath certPath = fact.generateCertPath(certChain);

		// Validierung des Zertifizierungspfades
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
//					System.out.println("Validation failed on certificate number " + e.getIndex() + "\n Class = " + e.getClass()
//							+ "\n Details: " + e.getMessage() + "\n Reason: " + e.getReason() +
//							// "\n CertPath " + e.getCertPath() +
//							"\n Index of faulty cert: " + e.getIndex());

			assertEquals(PKIXReason.UNRECOGNIZED_CRIT_EXT, e.getReason());
		}
	}

}
