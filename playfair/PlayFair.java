package kpp.playfair;

public class PlayFair {
	private final char forbidden = 'J';

	private final char padding = 'X';

	private final int n = 5;

	private final int faktor = 100;

	private char[][] charTable = new char[n][n];

	String key;

	String cleartext;

	String ciphertext;

	PlayFair(String key, String text, boolean encrypt) {
		// Schluessel filtern und upperCase
		this.key = key.replaceAll("[^a-zA-Z]+", "").toUpperCase();
		// System.out.println("encrypt: " + encrypt + " Key: " + key + " Text: "
		// + text);

		createCharTable();
		// System.out.println("\nTable:");
		// printCharTable();

		if (encrypt) {
			this.cleartext = prepareText(text.replaceAll("[^a-zA-Z]+", "").toUpperCase());
			ciphertext = encrypt(cleartext);
		} else {
			this.ciphertext = text.replaceAll("[^a-zA-Z]+", "").toUpperCase();
			cleartext = decrypt(ciphertext);
		}
		// System.out.println("cleartext: " + cleartext + "\nciphertext: " +
		// ciphertext);
		// System.out.println("\n");
	}

	private String encrypt(String text) {
		StringBuilder sb = new StringBuilder();

		for (int i = 1; i < text.length(); i += 2) {
			int firstCharPosition = getPositionOf(text.charAt(i - 1));
			int secondCharPosition = getPositionOf(text.charAt(i));

			if (((firstCharPosition % faktor) % n) == ((secondCharPosition % faktor) % n)) {

				sb.append(charTable[((firstCharPosition / faktor) + 1) % n][firstCharPosition % faktor]);
				sb.append(charTable[((secondCharPosition / faktor) + 1) % n][secondCharPosition % faktor]);

			} else if ((firstCharPosition / faktor) == (secondCharPosition / faktor)) {

				sb.append(charTable[firstCharPosition / faktor][((firstCharPosition % faktor) + 1) % n]);
				sb.append(charTable[secondCharPosition / faktor][((secondCharPosition % faktor) + 1) % n]);

			} else {

				sb.append(charTable[firstCharPosition / faktor][secondCharPosition % n]);
				sb.append(charTable[secondCharPosition / faktor][firstCharPosition % n]);

			}

		}

		return sb.toString();
	}

	private String decrypt(String text) {
		StringBuilder sb = new StringBuilder();

		for (int i = 1; i < text.length(); i += 2) {
			int firstCharPosition = getPositionOf(text.charAt(i - 1));
			int secondCharPosition = getPositionOf(text.charAt(i));

			if (((firstCharPosition % faktor) % n) == ((secondCharPosition % faktor) % n)) {

				sb.append(charTable[((firstCharPosition / faktor) - 1 + n) % n][firstCharPosition % faktor]);
				sb.append(charTable[((secondCharPosition / faktor) - 1 + n) % n][secondCharPosition % faktor]);

			} else if ((firstCharPosition / faktor) == (secondCharPosition / faktor)) {

				sb.append(charTable[firstCharPosition / faktor][((firstCharPosition % faktor) - 1 + n) % n]);
				sb.append(charTable[secondCharPosition / faktor][((secondCharPosition % faktor) - 1 + n) % n]);

			} else {

				sb.append(charTable[firstCharPosition / faktor][secondCharPosition % n]);
				sb.append(charTable[secondCharPosition / faktor][firstCharPosition % n]);

			}

		}

		return sb.toString();
	}

	private int getPositionOf(char c) {
		if (c == 'J') {
			c = 'I';
		}
		for (int i = 0; i < n; ++i) {
			for (int j = 0; j < n; ++j) {
				if (charTable[i][j] == c) {
					return ((i * faktor) + j);
				}
			}
		}

		return -1;
	}

	private void createCharTable() {
		// createCharTable zum Erstellen des Playfair-Quadrats
		boolean[] alphabet = new boolean[n * n + 1];
		StringBuilder sb = new StringBuilder(key);
		alphabet['J' - 'A'] = true;

		int j = 0;
		int k = 0;

		for (int i = 0; i < sb.length(); ++i) {
			char c = sb.charAt(i);

			c = (c == forbidden ? 'I' : c);

			if (!alphabet[c - 'A']) {
				j = i / n;
				charTable[j][k % n] = c;
				k++;
				alphabet[c - 'A'] = true;
			}
		}

		for (int i = 0; i < (n * n + 1); ++i) {

			if (!alphabet[i] && !('J' == (i + 'A'))) {
				j = k / n;
				char c = (char) (i + 'A');
				charTable[j][k % n] = c;
				alphabet[i] = true;
				k++;
			}
		}

	}

	private String prepareText(String text) {
		// prepareText zum Padden, Austausch von J durch I und zum Einfügen von
		// X zwischen gleichen Buchstaben
		StringBuilder sb = new StringBuilder(text);
		for (int i = sb.length() - 1; i > 0; --i) {
			char first = sb.charAt(i - 1);
			char second = sb.charAt(i);
			if (first == second) {
				sb.insert(i, padding);
			}
		}

		return (((sb.length() % 2) != 0) ? sb.append(padding) : sb).toString();
	}

	private void printCharTable() {
		StringBuilder sb;

		System.out.println("\n----------\n");
		for (int i = 0; i < n; i++) {
			sb = new StringBuilder();

			for (int j = 0; j < n; j++) {
				sb.append(charTable[i][j]);
			}

			System.out.println(sb.toString());
		}
		System.out.println("\n----------\n");
	}

	public static void main(String[] args) {
		PlayFair pfe0 = new PlayFair("Schluessel", "Wasser", true);

//        PlayFair pfe = new PlayFair("DEath", "WELle", true);
//        PlayFair pfd = new PlayFair("deaTH", "ecmwqc", false);
//
//        PlayFair pfe1 = new PlayFair("HSTrier", "feiertee", true);
//        PlayFair pfd1 = new PlayFair("HstRier", "nfhDIRBvbv", false);
//
//        PlayFair pfe2 = new PlayFair("hst", "FSociety", true);
//        PlayFair pfd2 = new PlayFair("HST", "DavilCAX", false);
//
//        PlayFair pfe3 = new PlayFair("Süden", "+Lde#sfe2", true);
//        PlayFair pfd3 = new PlayFair("Süden", "Ke.ndlf!", false);
//
//        PlayFair pfe4 = new PlayFair("KEY", "JJNACHRICHT", true);
//        PlayFair pfd4 = new PlayFair("key", "NULOKGFTPIOZ", false);

	}

}
