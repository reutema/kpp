package kpp.certvalidation.certValidation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
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

import org.junit.Test;

import kpp.certvalidation.CertificateGenerator;
import kpp.certvalidation.CertificateRevocationListGenerator;

public class JUnitTests {
	private static final long SECOND = 1000;

	private static final long MINUTE = 60 * SECOND;

	private static final long HOUR = 60 * MINUTE;

	private static final long DAY = 24 * HOUR;

	@Test
	public void trigger_EXPIRED() throws Exception {
		long SECOND = 1000;

		long MINUTE = 60 * SECOND;

		long HOUR = 60 * MINUTE;

		long DAY = 24 * HOUR;
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten f�r die G�ltigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);
		Date theDayBeforeYesterday = new Date(now.getTime() - DAY - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		// Doesnt work with rootCert
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, theDayBeforeYesterday);
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
			assertTrue(BasicReason.EXPIRED.equals(e.getReason()));

		}

	}

	@Test
	public void trigger_NOT_YET_VALID() throws Exception {
		long SECOND = 1000;

		long MINUTE = 60 * SECOND;

		long HOUR = 60 * MINUTE;

		long DAY = 24 * HOUR;
		// Schl�ssel
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten f�r die G�ltigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);
		Date theDayAfterTomorrow = new Date(now.getTime() + DAY + DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, theDayAfterTomorrow, tomorrow);
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
			assertTrue(BasicReason.NOT_YET_VALID.equals(e.getReason()));

		}
	}

	public void trigger_REVOKED() {

	}

	@Test
	public void trigger_UNDETERMINED_REVOCATION_STATUS() throws Exception {
		long SECOND = 1000;

		long MINUTE = 60 * SECOND;

		long HOUR = 60 * MINUTE;

		long DAY = 24 * HOUR;
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten f�r die G�ltigkeitsangaben
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
		// Using the rootPair.getPrivate() instead of the
		// interPair.getPrivate();
		X509CRL interCRL = CertificateRevocationListGenerator.createCRL(interCert, rootPair.getPrivate(),
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
			assertTrue(BasicReason.UNDETERMINED_REVOCATION_STATUS.equals(e.getReason()));
		}
	}

	@Test
	public void trigger_INVALID_SIGNATURE() throws Exception {
		long SECOND = 1000;

		long MINUTE = 60 * SECOND;

		long HOUR = 60 * MINUTE;

		long DAY = 24 * HOUR;
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten f�r die G�ltigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		// change rootPair.getPrivate() to interPair.getPrivate()
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				interPair.getPrivate(), rootCert, yesterday, tomorrow);
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
			assertTrue(BasicReason.INVALID_SIGNATURE.equals(e.getReason()));

		}

	}

	@Test
	public void trigger_ALGORITHM_CONSTRAINT() throws Exception {

		CertificateGenerator.setAlgorithm("MD5WithRSAEncryption");
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten f�r die G�ltigkeitsangaben
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
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");

		} catch (CertPathValidatorException e) {
			assertEquals(BasicReason.ALGORITHM_CONSTRAINED, e.getReason());

		}
	}

	public void trigger_INVALID_KEY_USAGE() {
		// replace | with &

	}

	@Test
	public void trigger_NAME_CHAINING() throws Exception {

		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten f�r die G�ltigkeitsangaben
		Date now = new Date();
		Date tomorrow = new Date(now.getTime() + DAY);
		Date yesterday = new Date(now.getTime() - DAY);

		// Generierung der Zertifikate
		X509Certificate rootCert = CertificateGenerator.generateRootCert(rootPair, yesterday, tomorrow);
		X509Certificate interCert = CertificateGenerator.generateIntermediateCert(interPair.getPublic(),
				rootPair.getPrivate(), rootCert, yesterday, tomorrow);
		// Use rootCert instead of interCert
		X509Certificate endCert = CertificateGenerator.generateEndEntityCert(endPair.getPublic(),
				interPair.getPrivate(), rootCert, yesterday, tomorrow);

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
			assertTrue(PKIXReason.NAME_CHAINING.equals(e.getReason()));

		}
	}

	@Test
	public void trigger_NO_TRUST_ANCHOR() throws Exception {
		long SECOND = 1000;

		long MINUTE = 60 * SECOND;

		long HOUR = 60 * MINUTE;

		long DAY = 24 * HOUR;
		KeyPair rootPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair interPair = CertificateGenerator.generateRSAKeyPair();
		KeyPair endPair = CertificateGenerator.generateRSAKeyPair();

		// Zeiten f�r die G�ltigkeitsangaben
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
		// Set interCert instead of rootCert
		Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(interCert, null));
		PKIXParameters param = new PKIXParameters(trust);
		// param.setRevocationEnabled(false);
		param.addCertStore(store);
		param.setDate(new Date());

		try {
			validator.validate(certPath, param);
			System.out.println("Certificate path successfully validated.");
		} catch (CertPathValidatorException e) {
			assertTrue(PKIXReason.NO_TRUST_ANCHOR.equals(e.getReason()));
		}

	}
}
