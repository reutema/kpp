package kpp.keystore;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*
  Aufgabenstellung: KeyStoreReader

Name der Klasse = KeyStoreReader.class
Package = kpp.keystore

Schreiben Sie eine Java-Klasse namens KeyStoreReader, die aus einem gegebenen JCKS-Keystore Werte ausliest.
*/

/*Attribute

    String[] aliases;
    byte[][] secretKeys;
    KeyStore store;
    String password;
    String[] DNs;
    static final String STORE_TYPE = "JCEKS";
*/
/*Konstruktor
KeyStoreReader(String fileName, String password)
Der Konstruktor liest den Keystore aus der Datei fileName. Es wird das angegebene Password zum Öffnen des Keystores verwendet.
Es werden alle Attribute oben gesetzt - direkt oder über die Methoden unten.
*/
/*Methoden:

    public String[] getAliases(KeyStore store) => Setzt die Aliase aus dem Keystore für das Attribute String[] aliases.
    public List<byte[]> getSecretKeys() => Liest alle secretKeys aus dem Keystore aus und setzt das Attribut byte[][] secretKeys passend zu den ausgelesenen Werten.
    public List<String> getDNs() => Liest die DNs aus allen Zertifikaten im Keystore aus und speichert sie als Strings im Attribut List<String> DNs.
    public void addAESKey(String alias, byte[] keyBytes) => Ergänzt die angegebenen keyBytes als AES-Schlüssel unter dem angegebenen Alias im Keystore.
*/
/*Anmerkungen:

    Lösen Sie die Aufgabe mit dem beigefügten Keystore testkeystore.
    Es wurde das Password 123456 für den Keystore und alle Einträge verwendet.
 * 
 */

public class KeyStoreReader {

	public String[] aliases;

	public List<byte[]> secretKeys;

	public KeyStore store;

	public String password, fileName;

	public List<String> DNs;

	public static final String STORE_TYPE = "JCEKS";

	public KeyStoreReader(String fileName, String password) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
		// Der Konstruktor liest den Keystore aus der Datei fileName. Es wird
		// das angegebene Password zum Öffnen des Keystores verwendet.
		// Es werden alle Attribute oben gesetzt - direkt oder über die Methoden
		// unten.

		this.password = password;
		this.fileName = fileName;
		this.store = KeyStore.getInstance(STORE_TYPE);

		store.load(new FileInputStream(fileName), password.toCharArray());

		update();

	}

	public String[] getAliases(KeyStore store) throws KeyStoreException {
		// => Setzt die Aliase aus dem Keystore für das Attribute String[] aliases.
		System.out.println("Start getAlias");
		Enumeration<?> en = store.aliases();
		ArrayList<String> list = new ArrayList<>();
		while (en.hasMoreElements()) {
			list.add((String) en.nextElement());
			System.out.println("Aliases: " + list.get(list.size() - 1));
			// System.out.println("Found " + alias + ", isCertificate? " +
			// store.isCertificateEntry(alias) + ", secret key entry? " +
			// store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class));
		}
		return list.toArray(new String[list.size()]);

	}

	public List<byte[]> getSecretKeys() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		// => Liest alle secretKeys aus dem Keystore aus und setzt das Attribut byte[][]
		// secretKeys passend zu den ausgelesenen Werten.
		System.out.println("Start getSecretKey");
		List<byte[]> list = new ArrayList<>();

		for (String alias : aliases) {
			System.out.println("_" + alias);
			if (store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
				System.out
						.println("-SecretKey " + alias + ": " + store.getKey(alias, password.toCharArray()).toString());
				list.add(store.getKey(alias, password.toCharArray()).getEncoded());
			}
		}

		return list;
	}

	public List<String> getDNs() throws KeyStoreException {
		// => Liest die DNs aus allen Zertifikaten im Keystore aus und speichert sie als
		// Strings im Attribut List<String> DNs.

		List<String> list = new ArrayList<>();

		for (String alias : aliases) {
			if (store.isCertificateEntry(alias)) {
				X509Certificate cert = (X509Certificate) store.getCertificate(alias);
				list.add(cert.getSubjectDN().toString());
			}
		}

		return list;

	}

	public void addAESKey(String alias, byte[] keyBytes) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableKeyException {
		// => Ergänzt die angegebenen keyBytes als AES-Schlüssel unter dem angegebenen
		// Alias im Keystore.

		SecretKey ks = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
		KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(ks);
		store.setEntry(alias, secretKeyEntry, new KeyStore.PasswordProtection(password.toCharArray()));

		update();

		// FileOutputStream outputStream = new FileOutputStream(fileName);
		// store.store(outputStream, password.toCharArray());
	}

	public void update() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		this.aliases = getAliases(store);
		List<byte[]> array = getSecretKeys();
		this.secretKeys = array;
//		this.secretKeys = array.toArray(new byte[array.size()][]);
		List<String> list = getDNs();
		this.DNs = list;
//		this.DNs = getDNs().toArray(new String[list.size()]);
	}

	public static void main(String[] args) {
		try {
			KeyStoreReader ksr = new KeyStoreReader(
					"C:\\Users\\DW-Laptop\\Desktop\\Dropbox_Studium_backup\\Studium_Info\\W18-19\\KPP-Kryptologisches_Programmierpraktikum\\testkeystore",
					"123456");

			SecretKey sk = KeyGenerator.getInstance("AES").generateKey();

			ksr.addAESKey("MYAESKEY", sk.getEncoded());
			System.out.println("\n<0>---------------------------------------\n");

			for (String s : ksr.aliases) {
				System.out.println("> " + s);
			}
			System.out.println("\n<1>---------------------------------------\n");

			for (byte[] b : ksr.secretKeys) {
				System.out.println(">> " + new String(b));
			}
			System.out.println("\n<2>---------------------------------------\n");

			ksr.aliases = ksr.getAliases(ksr.store);

			for (String s : ksr.aliases) {
				System.out.println("> " + s);
			}
			System.out.println("\n<3>---------------------------------------\n");

			for (byte[] b : ksr.getSecretKeys()) {
				System.out.println(">> " + new String(b));
			}
			System.out.println("\n<4>---------------------------------------\n");

		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
