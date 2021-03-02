package kpp.certvalidation;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

public class CertificatePathValidationTest {
	private static final long SECOND = 1000;
	private static final long MINUTE = 60 * SECOND;
	private static final long HOUR = 60 * MINUTE;
	private static final long DAY = 24 * HOUR;

	public static void main(String[] args) throws Exception {
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

		}
	}
}
