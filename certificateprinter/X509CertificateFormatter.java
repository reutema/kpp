package kpp.certificateprinter;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

public abstract class X509CertificateFormatter {

	protected final String xv3 = "X509v3 ";
	protected X509Certificate certificate;
	protected Blank blank;
	protected StringBuilder sb;
	protected final int spaces = 4;
	protected HashMap<String, Integer> oidList;

	public X509CertificateFormatter(String path) throws CertificateException, FileNotFoundException, IOException {

		CertificateFactory cFactory = CertificateFactory.getInstance("X.509");

		BufferedInputStream input = new BufferedInputStream(new FileInputStream(path));
		this.certificate = (X509Certificate) cFactory.generateCertificate(input);

		this.blank = new Blank();
		this.sb = new StringBuilder();

	}

	protected abstract void add(String text);

	protected abstract HashMap<String, Integer> getOID();

	protected void formatAndAddPublicKey(PublicKey publicKey) throws InvalidAlgorithmParameterException {
		PublicKey pKey = certificate.getPublicKey();

		if (pKey.getAlgorithm().equals("EC")) {
			// TODO
			ECPublicKey ec = (ECPublicKey) pKey;
			add(ec.getParams().getCurve().toString());
			add(ec.getW().toString());
		} else if (pKey.getAlgorithm().equals("RSA")) {
			// TODO
			RSAPublicKey rsaPuK = (RSAPublicKey) publicKey;
			add("Public-Key: (" + rsaPuK.getModulus().bitLength() + " bit)");

			add("Modulus:");
			blank.update(spaces);
			add(Helper.formatHex(rsaPuK.getModulus().toByteArray(), 15));
			blank.update(-spaces);
			add("Exponent: " + rsaPuK.getPublicExponent().toString() + "  (0x" + rsaPuK.getPublicExponent().toString(16)
					+ ")");
		} else {
			throw new InvalidAlgorithmParameterException("Algorithm of public key is not supported!");
		}

	}

	protected void formatAndAddOIDs()
			throws UnimplementedExcepetion, UnknownExtensionException, UnknownDistributionPointNameException {

		if (certificate.getCriticalExtensionOIDs() != null) {

			for (String oid : certificate.getCriticalExtensionOIDs()) {
				formatAndAddOID(oid);
			}
			for (String oid : certificate.getNonCriticalExtensionOIDs()) {
				formatAndAddOID(oid);
			}
		}
	}

	protected void formatAndAddOID(String oid)
			throws UnimplementedExcepetion, UnknownExtensionException, UnknownDistributionPointNameException {

		int value = oidList.get(oid);

		switch (value) {
		case 0:
			throw new UnimplementedExcepetion("Unimlemented Extension");
		case 1:
			formatSubjectKeyIdentifier();
			break;
		case 2:
			formatKeyUsage();
			break;
		case 3:
			formatX509v3Extension("Subject Alternative Name:", Extension.subjectAlternativeName);
			break;
		case 4:
			formatX509v3Extension("Issuer Alternative Name:", Extension.issuerAlternativeName);
			break;
		case 5:
			formatX509v3Extension("Basic Constraints:", Extension.basicConstraints);
			break;
		case 6:
			formatCRLDistributionPoints();
			break;
		case 7:
			formatCertificatePolicies();
			break;
		case 8:
			formatAuthorityKeyIdentifier();
			break;
		case 9:
			formatExtendedKeyUsage();
			break;
		case 10:
			formatAuthorityInfoAccess();
			break;

		default:
			throw new UnknownExtensionException("Unkown Extension!");
		}
	}

	protected void formatSubjectKeyIdentifier() {
		add(xv3 + "Subject Key Identifier: ");
		blank.update(spaces);
		byte[] ski = SubjectKeyIdentifier.getInstance(getASN1OctetString(Extension.subjectKeyIdentifier))
				.getKeyIdentifier();
		add(Helper.toHex(ski));
		blank.update(-spaces);
	}

	protected void formatKeyUsage() {
		add("X509.v3 Key Usage:");
		blank.update(spaces);

		KeyUsage kUsage = KeyUsage.getInstance(getASN1OctetString(Extension.keyUsage));

		if (kUsage.hasUsages(KeyUsage.cRLSign)) {
			add("CRL Signing, ");
		}
		if (kUsage.hasUsages(KeyUsage.dataEncipherment)) {
			add("Data Encipherment, ");
		}
		if (kUsage.hasUsages(KeyUsage.decipherOnly)) {
			add("Decipher Only, ");
		}
		if (kUsage.hasUsages(KeyUsage.digitalSignature)) {
			add("Digital Signature, ");
		}
		if (kUsage.hasUsages(KeyUsage.encipherOnly)) {
			add("Encipher Only, ");
		}
		if (kUsage.hasUsages(KeyUsage.keyAgreement)) {
			add("Key Agreement, ");
		}
		if (kUsage.hasUsages(KeyUsage.keyCertSign)) {
			add("Certificate Signing, ");
		}
		if (kUsage.hasUsages(KeyUsage.keyEncipherment)) {
			add("Key Encipherment, ");
		}
		if (kUsage.hasUsages(KeyUsage.nonRepudiation)) {
			add("Non Repudiation, ");
		}
		blank.update(-spaces);
	}

	protected byte[] getASN1OctetString(ASN1ObjectIdentifier extension) {
		return ASN1OctetString.getInstance(certificate.getExtensionValue(extension.getId())).getOctets();

	}

	protected void formatX509v3Extension(String name, ASN1ObjectIdentifier asn10OI) {
		add(xv3 + name);
		GeneralNames gns = GeneralNames.getInstance(getASN1OctetString(asn10OI));
		forEachGN(gns);
	}

	protected void formatCRLDistributionPoints() throws UnknownDistributionPointNameException {
		add(xv3 + "CRL Distribution Points:");
		blank.update(spaces);
		CRLDistPoint crldp = CRLDistPoint.getInstance(getASN1OctetString(Extension.cRLDistributionPoints));

		for (DistributionPoint dp : crldp.getDistributionPoints()) {
			add(getDistributionPointType(dp.getDistributionPoint()));

			if (dp.getCRLIssuer() != null) {
				forEachGN(dp.getCRLIssuer());
			}
			forEachGN(GeneralNames.getInstance(dp.getDistributionPoint().getName()));
		}

		blank.update(-spaces);
	}

	protected void formatCertificatePolicies() {
		add(xv3 + "xCertificate Policies:");
		blank.update(spaces);
		CertificatePolicies cp = CertificatePolicies.getInstance(getASN1OctetString(Extension.certificatePolicies));

		for (PolicyInformation policyInfo : cp.getPolicyInformation()) {
			add(policyInfo.toString());
		}

		blank.update(-spaces);
	}

	private void forEachGN(GeneralNames gns) {
		blank.update(spaces);
		// TODO evtl. StringBuilder einfügen
		for (GeneralName gn : gns.getNames()) {
			add(getGN(gn) + ", ");
		}
		blank.update(-spaces);
	}

	protected void formatAuthorityKeyIdentifier() {
		add(xv3 + "Authority Key Identifier:");
		blank.update(spaces);
		AuthorityKeyIdentifier aki = AuthorityKeyIdentifier
				.getInstance(getASN1OctetString(Extension.authorityKeyIdentifier));

		add(Helper.toHex(aki.getKeyIdentifier()));
		blank.update(-spaces);
	}

	protected boolean hasKPID(ExtendedKeyUsage eku, KeyPurposeId kpID) {
		return eku.hasKeyPurposeId(kpID);
	}

	protected void formatExtendedKeyUsage() {
		add(xv3 + "Extended Key Usage:");
		blank.update(spaces);
		ExtendedKeyUsage extKeyUsage = ExtendedKeyUsage.getInstance(getASN1OctetString(Extension.extendedKeyUsage));

		if (hasKPID(extKeyUsage, KeyPurposeId.anyExtendedKeyUsage)) {
			add("Any Extended Key Usage, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_capwapAC)) {
			add("capwapAC, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_capwapWTP)) {
			add("capwapWTP, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_clientAuth)) {
			add("TLS Web Client Authentication, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_codeSigning)) {
			add("Code Signing, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_dvcs)) {
			add("dvcs, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_eapOverLAN)) {
			add("eapOverLAN, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_eapOverPPP)) {
			add("eapOverPPP, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_emailProtection)) {
			add("Email Protection, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_ipsecEndSystem)) {
			add("IPSec End System, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_ipsecIKE)) {
			add("IPSec IKE, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_ipsecTunnel)) {
			add("IPSec Tunnel, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_ipsecUser)) {
			add("IPSec User, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_OCSPSigning)) {
			add("OCSP Signing, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_sbgpCertAAServerAuth)) {
			add("sbgpCertAAServerAuth, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_scvp_responder)) {
			add("scvp_responder, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_scvpClient)) {
			add("scvpClient, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_scvpServer)) {
			add("scvpServer, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_serverAuth)) {
			add("TLS Web Server Authentication, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_smartcardlogon)) {
			add("Smartcard Logon, ");
		}
		if (hasKPID(extKeyUsage, KeyPurposeId.id_kp_timeStamping)) {
			add("Time Stamping, ");
		}

		blank.update(-spaces);
	}

	protected void formatAuthorityInfoAccess() {
		add(xv3 + "Authority Information Access:");
		blank.update(spaces);
		AuthorityInformationAccess authInfoAccess = AuthorityInformationAccess
				.getInstance(getASN1OctetString(Extension.authorityInfoAccess));
		AccessDescription[] ads = authInfoAccess.getAccessDescriptions();

		for (AccessDescription ad : ads) {
			ASN1ObjectIdentifier adam = ad.getAccessMethod();
			if (adam.equals(AccessDescription.id_ad_caIssuers)) {
				add("CA Issuers - " + ad.getAccessLocation().getName().toString());
				continue;
			} else if (adam.equals(AccessDescription.id_ad_ocsp)) {
				add("OCSP - " + ad.getAccessLocation().getName().toString());
				continue;
			} else {
				add("Unknown - " + ad.getAccessLocation().getName().toString());
				continue;
			}
		}

		blank.update(-spaces);
	}

	protected String getDistributionPointType(DistributionPointName dpn) throws UnknownDistributionPointNameException {
		if (dpn.getType() == DistributionPointName.FULL_NAME) {
			return "Full Name:";
		} else if (dpn.getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER) {
			return "Relative Name:";
		} else {
			throw new UnknownDistributionPointNameException();
		}
	}

	public String getGN(GeneralName gn) {
		int tagNo = gn.getTagNo();
		String postString = ":" + gn.getName();

		if (tagNo == GeneralName.directoryName) {
			return "DN" + postString;
		} else if (tagNo == GeneralName.dNSName) {
			return "DNS" + postString;
		} else if (tagNo == GeneralName.ediPartyName) {
			return "EDI" + postString;
		} else if (tagNo == GeneralName.iPAddress) {
			return "IP" + postString;
		} else if (tagNo == GeneralName.otherName) {
			return "Other" + postString;
		} else if (tagNo == GeneralName.registeredID) {
			return "ID" + postString;
		} else if (tagNo == GeneralName.rfc822Name) {
			return "RFC822" + postString;
		} else if (tagNo == GeneralName.uniformResourceIdentifier) {
			return "URI" + postString;
		} else if (tagNo == GeneralName.x400Address) {
			return "X400" + postString;
		} else {
			return "Unknown" + postString;
		}
	}

}
