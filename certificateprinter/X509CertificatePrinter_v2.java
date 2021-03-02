package kpp.certificateprinter;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Base64;
import java.util.HashMap;

public class X509CertificatePrinter_v2 extends X509CertificateFormatter {

	public X509CertificatePrinter_v2(String path)
			throws CertificateException, FileNotFoundException, IOException, UnimplementedExcepetion,
			UnknownExtensionException, InvalidAlgorithmParameterException, UnknownDistributionPointNameException {

		super(path);

		this.oidList = getOID();
		printCertificate();
	}

	public HashMap<String, Integer> getOID() {
		HashMap<String, Integer> hm = new HashMap<>();

		// hm.put(key, value);
		hm.put("2.5.29.14", 1); // subjectKeyIdentifier -> formatSubjectKeyIdentifier();

		hm.put("2.5.29.15", 2); // keyUsage -> formatKeyUsage();

		hm.put("2.5.29.17", 3); // subjectAlternativeName -> formatSubjectAlternativeName();

		hm.put("2.5.29.18", 4); // issuerAlternativeName -> formatIssuerAlternativeName();

		hm.put("2.5.29.19", 5); // basicConstraints -> formatBasicConstraints();

		hm.put("2.5.29.31", 6); // cRLDistributionPoints -> formatCRLDistributionPoints();

		hm.put("2.5.29.32", 7); // certificatePolicies -> formatCertificatePolicies();

		hm.put("2.5.29.35", 8); // authorityKeyIdentifier -> formatAuthorityKeyIdentifier();

		hm.put("2.5.29.37", 9); // extendedKeyUsage -> formatExtendedKeyUsage();

		hm.put("1.3.6.1.5.5.7.1.1", 10); // authorityInfoAccess -> formatAuthorityInfoAccess();

		/*
		 * Known but not implemented
		 */
		hm.put("2.5.29.9", 0); // subjectDirectoryAttributes -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.16", 0); // privateKeyUsagePeriod -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.20", 0); // cRLNumber -> throw new UnimplementedExcepetion("Unimlemented Extension");
		hm.put("2.5.29.21", 0); // reasonCode -> throw new UnimplementedExcepetion("Unimlemented Extension");
		hm.put("2.5.29.23", 0); // instructionCode -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.24", 0); // invalidityDate -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.27", 0); // deltaCRLIndicator -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.28", 0); // issuingDistributionPoint -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.29", 0); // certificateIssuer -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.30", 0); // nameConstraints -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.33", 0); // policyMappings -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.36", 0); // policyConstraints -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.46", 0); // freshestCRL -> throw new UnimplementedExcepetion("Unimlemented Extension");
		hm.put("2.5.29.54", 0); // inhibitAnyPolicy -> throw new UnimplementedExcepetion("Unimlemented
								// Extension");
		hm.put("2.5.29.55", 0); // targetInformation -> throw new UnimplementedExcepetion("Unimlemented
		// Extension");
		hm.put("2.5.29.56", 0); // noRevAvail -> throw new UnimplementedExcepetion("Unimlemented Extension");
		hm.put("1.3.6.1.5.5.7.1.2", 0); // biometricInfo -> throw new UnimplementedExcepetion("Unimlemented Extension");
		hm.put("1.3.6.1.5.5.7.1.3", 0); // qCStatements -> throw new UnimplementedExcepetion("Unimlemented Extension");
		hm.put("1.3.6.1.5.5.7.1.4", 0); // auditIdentity -> throw new UnimplementedExcepetion("Unimlemented Extension");
		hm.put("1.3.6.1.5.5.7.1.11", 0); // subjectInfoAccess -> throw new UnimplementedExcepetion("Unimlemented
											// Extension");
		hm.put("1.3.6.1.5.5.7.1.12", 0); // logoType -> throw new UnimplementedExcepetion("Unimlemented Extension");

		return hm;
	}

	private void printCertificate() throws IOException, UnimplementedExcepetion, UnknownExtensionException,
			InvalidAlgorithmParameterException, UnknownDistributionPointNameException, CertificateEncodingException {

		// System.out.println("0");
		addCertificate();

		// System.out.println("1");
		addData();

		// System.out.println("2");
		addVersion();

		// System.out.println("3");
		addSerialNumber();

		// System.out.println("4");
		addSignatureAlgorithm();

		// System.out.println("5");
		addIssuer();

		// System.out.println("6");
		addValidity();

		// System.out.println("7");
		addNotBefore();
		addNotAfter();

		// System.out.println("8");
		addSubject();

		// System.out.println("9");
		addPublicKeyAlgorithm();

		// System.out.println("10");
		addPublicKey();

		// System.out.println("11");
		addExtensionHeader();

		// System.out.println("12");
		addOID();

		// System.out.println("13");
		addSignatureAlgorithm();

		// System.out.println("14");
		addSignature();

		// System.out.println("15");
		addCertificateEncoded();

		// System.out.println("16");
		addFingerPrints();

		printBuilder();
		/*
		 * 
		 * 
		 * 
		 * 
		 * 
		 */

	}

//	public void add(String line) {
//		System.out.println(this.blank.toString() + line.toString().replaceAll("\n", "\n" + this.blank.toString()));
//	}

	protected void add(String text) {
		System.out.println(this.blank.getLine() + text.toString().replaceAll("\n", "\n" + this.blank.getLine()));

//		text = text.replace("\n", "\n" + blank.getLine());
//		sb.append(blank.getLine() + text + "\n");
	}

	private void addCertificate() {
		add("Certificate:");
		blank.update(spaces);
	}

	private void addData() {
		add("Data:");
		blank.update(spaces);
	}

	private void addVersion() {
		add("Version: " + certificate.getVersion() + "  (" + Helper.toHex(certificate.getVersion()) + ")");
	}

	private void addSerialNumber() {
		add("Serial Number:");
		blank.update(spaces);
		add(Helper.addDots(certificate.getSerialNumber().toString(16), -1));
		blank.update(-(2 * spaces));
	}

	private void addSignatureAlgorithm() {
		add("Signature Algorithm: " + certificate.getSigAlgName());
		blank.update(spaces);
	}

	private void addIssuer() {
		// C=DE, O=Regionales Hochschulrechenzentrum Kaiserslautern, CN=RHRK-CA -
		// G02/emailAddress=ca@rhrk.uni-kl.de
		add("Issuer: " + certificate.getIssuerDN().toString());
		blank.update(-spaces);
	}

	private void addValidity() {
		blank.update(spaces);
		String isValid = "valid";
		try {
			certificate.checkValidity();
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			isValid = "invalid - " + e.getMessage();
		}
		add("Validity: (" + isValid + ")");
		blank.update(spaces);
	}

	@SuppressWarnings("deprecation")
	private void addNotBefore() {
		add("Not Before: " + certificate.getNotBefore().toGMTString());
	}

	@SuppressWarnings("deprecation")
	private void addNotAfter() {
		add("Not After: " + certificate.getNotAfter().toGMTString());
		blank.update(-spaces);
	}

	private void addSubject() {
		add("Subject: " + certificate.getSubjectDN().toString());
		add("Subject Public Key Info:");
		blank.update(spaces);
	}

	private void addPublicKeyAlgorithm() {
		add("Public Key Algorithm: " + certificate.getPublicKey().getAlgorithm());
		blank.update(spaces);
	}

	private void addPublicKey() throws InvalidAlgorithmParameterException {
		formatAndAddPublicKey(certificate.getPublicKey());
		blank.update(-(2 * spaces));
	}

	private void addExtensionHeader() {
		add(xv3 + "extensions:");
		blank.update(spaces);
	}

	private void addOID()
			throws UnimplementedExcepetion, UnknownExtensionException, UnknownDistributionPointNameException {
		formatAndAddOIDs();
		blank.update(-2 * spaces);
	}

	private void addSignature() {
		add(Helper.formatHex(certificate.getSignature(), 18)); // TODO möglicherweise Problem (true fehlt)
		blank.update(-spaces);
	}

	private void addFingerPrints() {
		add("\n\n");
		try {
			MessageDigest mdMD5 = MessageDigest.getInstance("MD5");
			MessageDigest mdSHA1 = MessageDigest.getInstance("SHA1");
			MessageDigest mdSHA256 = MessageDigest.getInstance("SHA256");

			mdMD5.update(certificate.getEncoded());
			mdSHA1.update(certificate.getEncoded());
			mdSHA256.update(certificate.getEncoded());

			add("MD5-Fingerprint: " + Helper.toHex(mdMD5.digest()));
			add("SHA1-Fingerprint: " + Helper.toHex(mdSHA1.digest()));
			add("SHA256-Fingerprint:");
			blank.update(spaces);
			add(Helper.toHex(mdSHA256.digest())); // TODO könnte Probleme geben (true fehlt)
		} catch (CertificateEncodingException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		add("\n");
	}

	private void addCertificateEncoded() throws CertificateEncodingException {
		blank.update(-spaces);
		add("-----BEGIN CERTIFICATE-----");
		add(Helper.nextLineAfter(Base64.getEncoder().encodeToString(certificate.getEncoded()), 65));
		add("-----END CERTIFICATE-----");
	}

	private void printBuilder() {
		System.out.println(sb.toString());
	}

	public static void main(String[] args) {
		String path = args[0];

		try {

			X509CertificatePrinter_v2 printer = new X509CertificatePrinter_v2(path);

		} catch (CertificateException | IOException | UnimplementedExcepetion | UnknownExtensionException
				| InvalidAlgorithmParameterException | UnknownDistributionPointNameException e) {
			e.printStackTrace();
		}
	}

}
