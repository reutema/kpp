package kpp.certvalidation;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class MyCertificateGenerator {

	final static int KEY_LENGTH = 2048;

	public static X509Certificate generateRootCert(KeyPair pair, String sig_algo, Date notBefore, Date notAfter)
			throws Exception {
		X500NameBuilder subjectBuilder = new X500NameBuilder(RFC4519Style.INSTANCE);
		subjectBuilder.addRDN(RFC4519Style.cn, "Hochschule Trier Root CA");
		subjectBuilder.addRDN(RFC4519Style.c, "DE");
		subjectBuilder.addRDN(RFC4519Style.o, "Hochschule Trier");
		subjectBuilder.addRDN(RFC4519Style.l, "Trier");
		subjectBuilder.addRDN(RFC4519Style.st, "Rheinland-Pfalz");
		subjectBuilder.addRDN(RFC4519Style.description, "KPP Test-Root-Zertifikat");
		X500Name subject = subjectBuilder.build();

		ContentSigner sigGen = new JcaContentSignerBuilder(sig_algo).build(pair.getPrivate());
		X509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(subject,
				BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, subject, pair.getPublic());
		return new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
	}

	public static X509Certificate generateIntermediateCert(PublicKey intermediateKey, PrivateKey caKey,
			X509Certificate caCert, String sig_algo, Date notBefore, Date notAfter) throws Exception {
		X500NameBuilder subjectBuilder = new X500NameBuilder(RFC4519Style.INSTANCE);
		subjectBuilder.addRDN(RFC4519Style.cn, "Fachbereich Informatik CA");
		subjectBuilder.addRDN(RFC4519Style.c, "DE");
		subjectBuilder.addRDN(RFC4519Style.o, "Hochschule Trier");
		subjectBuilder.addRDN(RFC4519Style.l, "Trier");
		subjectBuilder.addRDN(RFC4519Style.st, "Rheinland-Pfalz");
		subjectBuilder.addRDN(RFC4519Style.description, "KPP Test-Intermediate Zertifikat");
		X500Name subject = subjectBuilder.build();

		ContentSigner sigGen = new JcaContentSignerBuilder(sig_algo).build(caKey);
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(caCert,
				BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, subject, intermediateKey)
						.addExtension(Extension.authorityKeyIdentifier, false,
								extUtils.createAuthorityKeyIdentifier(caCert))
						.addExtension(Extension.subjectKeyIdentifier, false,
								extUtils.createSubjectKeyIdentifier(intermediateKey))
						.addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
						.addExtension(Extension.keyUsage, true,
								new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
		return new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
	}

	public static X509Certificate generateEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert,
			String sig_algo, Date notBefore, Date notAfter) throws Exception {
		X500NameBuilder subjectBuilder = new X500NameBuilder(RFC4519Style.INSTANCE);
		subjectBuilder.addRDN(RFC4519Style.cn, "Kryptologisches Programmierpraktikum");
		subjectBuilder.addRDN(RFC4519Style.c, "DE");
		subjectBuilder.addRDN(RFC4519Style.o, "Hochschule Trier");
		subjectBuilder.addRDN(RFC4519Style.l, "Trier");
		subjectBuilder.addRDN(RFC4519Style.st, "Rheinland-Pfalz");
		subjectBuilder.addRDN(RFC4519Style.description, "KPP-Test End Zertifikat");
		X500Name subject = subjectBuilder.build();

		ContentSigner sigGen = new JcaContentSignerBuilder(sig_algo).build(caKey);
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(caCert,
				BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, subject, entityKey)
						.addExtension(Extension.authorityKeyIdentifier, false,
								extUtils.createAuthorityKeyIdentifier(caCert))
						.addExtension(Extension.subjectKeyIdentifier, false,
								extUtils.createSubjectKeyIdentifier(entityKey))
						.addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
						.addExtension(Extension.keyUsage, true,
								new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
		return new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
	}

	public static KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
		kpGen.initialize(KEY_LENGTH, new SecureRandom());
		return kpGen.generateKeyPair();
	}

	public static X509Certificate generateEndEntityCertForUNRECOGNIZED_CRIT_EXT(PublicKey entityKey, PrivateKey caKey,
			X509Certificate caCert, Date notBefore, Date notAfter) throws Exception {

		String SIG_ALGO = "SHA3-512WithRSAEncryption";
		X500NameBuilder subjectBuilder = new X500NameBuilder(RFC4519Style.INSTANCE);
		subjectBuilder.addRDN(RFC4519Style.cn, "Kryptologisches Programmierpraktikum");
		subjectBuilder.addRDN(RFC4519Style.c, "DE");
		subjectBuilder.addRDN(RFC4519Style.o, "Hochschule Trier");
		subjectBuilder.addRDN(RFC4519Style.l, "Trier");
		subjectBuilder.addRDN(RFC4519Style.st, "Rheinland-Pfalz");
		subjectBuilder.addRDN(RFC4519Style.description, "KPP-Test End Zertifikat");
		X500Name subject = subjectBuilder.build();

		ContentSigner sigGen = new JcaContentSignerBuilder(SIG_ALGO).build(caKey);
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(caCert,
				BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, subject, entityKey)
						.addExtension(Extension.authorityKeyIdentifier, false,
								extUtils.createAuthorityKeyIdentifier(caCert))
						.addExtension(Extension.subjectKeyIdentifier, false,
								extUtils.createSubjectKeyIdentifier(entityKey))
						.addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
						.addExtension(Extension.keyUsage, true,
								new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment))
						// Änderung hier vorgenommen! für UNRECOGNIZED_CRIT_EXT
						.addExtension(Extension.auditIdentity, true, extUtils.createAuthorityKeyIdentifier(entityKey));
		return new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
	}

}
