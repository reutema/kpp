package kpp.certvalidation;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateRevocationListGenerator {
	public static X509CRL createCRL(X509Certificate caCert, PrivateKey caKey, BigInteger revokedSerialNumber)
			throws Exception {
		Date now = new Date();
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(
				X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded()), now);
		crlGen.setNextUpdate(new Date(now.getTime() + 100000));
		crlGen.addCRLEntry(revokedSerialNumber, now, CRLReason.privilegeWithdrawn);

		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		crlGen.addExtension(Extension.authorityKeyIdentifier, false,
				extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));
		crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));
		X509CRLHolder crl = crlGen.build(new JcaContentSignerBuilder("SHA256withRSAEncryption").build(caKey));

		return new JcaX509CRLConverter().getCRL(crl);
	}
}
