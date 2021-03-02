package kpp.kppsigner;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;

import kpp.kppsigner.data.Data;
import kpp.kppsigner.data.DataManager;

/*Erstellen Sie ein Java-Programm, das eine Signatur zu einer Datei oder zu einem eingegebenen Text

(1) generieren und
(2) diese verifizieren kann.

Davor sollen über das Programm geeignete Schlüssel generiert und als Datei abgespeichert werden können.Die folgenden Signatur-Verfahren sollen unterstützt werden:

RSA
DSA
ECDSA
*/
/*Anmerkungen:

Verwenden Sie bestehende Implementierungen z.B. von JCA oder BC für die Signatur-Erstellung und Verifikation. Verwenden Sie dabei geeignete Schlüssellängen, Padding-Verfahren und Hash-Verfahren. Sie können eine bekannte elliptische Kurve (Named Curve) verwenden, brauchen als die Kurven-Parameter nicht selbst finden.
Überlegen Sie sich, in welchem Format Sie die Schlüssel in der Datei speichern. Vorteilhaft ist es, das verwendete Kryptoverfahren mitzuspeichern.
Überlegen Sie sich auch, wie Sie sich merken, welche Signatur mit welchem Schlüssel erstellt wurde und welche Signatur zu welcher Datei gehört.
*/
/*Optionale Erweiterungen:

In der Praxis werden die öffentlich Schlüssel zum Prüfen von Signaturen aus X.509-Zertifikaten verwendet. Das kommt später im Praktikum. Sie können optional schon mit X.509-Zertifikaten arbeiten.
PKCS8 kann zur Speicherung privater Schlüssel verwendet werden, vgl. https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
Professioneller ist die Speicherung der Schlüssel im einem Java Key Store. Auch das kommt später im Praktikum. Sie können optional aber schon einen Key Store verwenden.
Sie können optional noch weitere Signaturverfahren einbauen, wie z.B.
    DSA with Edwards Curves (EdDSA) => Signature.getInstance("EdDSA", "BC")
    Ukrainian Standrard DSTU 4145 => Signature.getInstance("DSTU4145", "BC")
    GOST R 34.10-2012 => Signature.getInstance("ECGOST3410-2012", "BC")
    Chinese Standard SM2 => Signature.getInstance("SM3withSM2", "BC");
*/
//https://stackoverflow.com/questions/16662408/correct-way-to-sign-and-verify-signature-using-bouncycastle
public class KPPSigner
{
    private static final String path = "./src/kpp/kppsigner/signatures.txt";

    private static DataManager manager;

    private static BufferedReader buf;

    public static byte[] encryptPrivateKey(KeyPair keyPair)
    {
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        return pkcs8Spec.getEncoded();
    }

    public static byte[] encodePublicKey(KeyPair keyPair)
    {
        return keyPair.getPublic().getEncoded();
        // PKCS8EncodedKeySpec pkcs8Spec = new
        // PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        // return pkcs8Spec.getEncoded();
    }

    public static PrivateKey decryptPrivateKey(String cryptoMethod, byte[] encryptPrivateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(encryptPrivateKey);
        KeyFactory keyFact = KeyFactory.getInstance(cryptoMethod, "BC");
        return keyFact.generatePrivate(pkcs8Spec);
    }

    public static PublicKey decodePublicKey(String cryptoMethod, byte[] encPublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException
    {
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(encPublicKey);
        KeyFactory keyFact = KeyFactory.getInstance(cryptoMethod, "BC");
        return keyFact.generatePublic(pkcs8Spec);
    }

    private static void generateRSA() throws GeneralSecurityException, IOException
    {
        String input = getInput("sign");
        RSASigner rsa = new RSASigner();
        manager.add("RSA", input, RSASigner.generateSignature(rsa.getKeyPair().getPrivate(), input.getBytes()), rsa.getKeyPair());
        System.out.println("RSA done");
    }

    private static void generateDSA() throws GeneralSecurityException, IOException
    {
        String input = getInput("sign");
        DSASigner dsa = new DSASigner();
        manager.add("DSA", input, DSASigner.generateSignature(dsa.getKeyPair().getPrivate(), input.getBytes()), dsa.getKeyPair());
        System.out.println("DSA done");
    }

    private static void generateECDSA() throws GeneralSecurityException, IOException
    {
        String input = getInput("sign");
        ECDSASigner ecdsa = new ECDSASigner();
        manager.add("ECDSA", input, ECDSASigner.generateSignature(ecdsa.getKeyPair().getPrivate(), input.getBytes()), ecdsa.getKeyPair());
        System.out.println("ECDSA done");
    }

    private static boolean verifyRSA() throws IOException, GeneralSecurityException
    {
        String k = getInput("enter public key: ");
        PublicKey publicKey = KPPSigner.decodePublicKey("RSA", k.getBytes());

        String i = getInput("enter data to verify: ");
        byte[] input = i.getBytes();

        byte[] encSignature = manager.getSignatureFrom("RSA", input, publicKey);

        return RSASigner.verifySignature(publicKey, input, encSignature);
    }

    private static boolean verifyDSA() throws IOException, GeneralSecurityException
    {
        String k = getInput("enter public key: ");
        PublicKey publicKey = KPPSigner.decodePublicKey("DSA", k.getBytes());

        String i = getInput("enter data to verify: ");
        byte[] input = i.getBytes();

        byte[] encSignature = manager.getSignatureFrom("DSA", input, publicKey);

        return DSASigner.verifySignature(publicKey, input, encSignature);
    }

    private static boolean verifyECDSA() throws IOException, GeneralSecurityException
    {
        String k = getInput("enter public key: ");
        PublicKey publicKey = KPPSigner.decodePublicKey("ECDSA", k.getBytes());

        String i = getInput("enter data to verify: ");
        byte[] input = i.getBytes();

        byte[] encSignature = manager.getSignatureFrom("ECDSA", input, publicKey);

        return ECDSASigner.verifySignature(publicKey, input, encSignature);
    }
    // public void loadKeyStore()
    // {
    //
    // KeyStore store = JKSStoreExample.createKeyStore();
    //
    // store.store(new FileOutputStream("keystore.jks"), password);
    //
    // KeyStore ks = KeyStore.getInstance(KEYSTORE_INSTANCE);
    // ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PWD.toCharArray());
    // Key key = ks.getKey(KEYSTORE_ALIAS, KEYSTORE_PWD.toCharArray());
    //
    // }

    public static int readInputInt(String message, int from, int to)
    {
        int number = -1;
        System.out.println(message);
        while (number < 0 || !(number >= from && number <= to))
        {
            try
            {
                number = Integer.parseInt(buf.readLine());
            }
            catch (Exception e)
            {
                System.out.println("only numbers allowed!");
            }
        }
        return number;

    }

    public static String getInput(String method) throws IOException
    {
        System.out.println("What should be " + method + "?");
        int input = readInputInt("1 File\n2 Message", 0, 2);
        String s = null;
        String result = null;

        while (s == null || !s.equals("cancel"))
        {
            System.out.println("Enter path or message \nenter 'cancel' for break");
            s = buf.readLine();
            if (input == 0)
            {
                break;
            }
            else if (input == 1)
            {
                try
                {
                    FileReader file = new FileReader(s);

                    result = file.getEncoding();
                    break;
                }
                catch (FileNotFoundException e)
                {
                    continue;
                }
            }
            else if (input == 2)
            {
                result = s;
                break;
            }
        }
        return result;
    }

    public static void writeToFile() throws IOException
    {
        ArrayList<Data> dataList = manager.getDatas();
        File f = new File(path);
        BufferedWriter bw = new BufferedWriter(new FileWriter(f));

        for (Data d : dataList)
        {
            bw.write(d.toString() + "\n");
        }
        bw.close();
    }

    private static void readFromFile() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException
    {
        File f = new File(path);
        BufferedReader br = new BufferedReader(new FileReader(f));
        String line;

        while ((line = br.readLine()) != null)
        {
            manager.decode(line);
        }
        br.close();
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException
    {
        manager = new DataManager();
        readFromFile();
        buf = new BufferedReader(new InputStreamReader(System.in));

        do
        {
            int inputGenVer = readInputInt("1 generieren\n2 verifizieren", 0, 2);
            int inputMethod = readInputInt("1 RSA\n2 DSA\n3 ECDSA", 0, 3);
            if (inputGenVer == 0)
            {
                break;
            }
            else if (inputGenVer == 1)
            {
                switch (inputMethod)
                {
                    case 1:
                        generateRSA();
                        break;
                    case 2:
                        generateDSA();
                        break;
                    case 3:
                        generateECDSA();
                        break;
                    case 0:
                    default:
                        continue;
                }
                writeToFile();
            }
            else if (inputGenVer == 2)
            {
                switch (inputMethod)
                {
                    case 1:
                        System.out.println("Verfication: " + verifyRSA());
                        break;
                    case 2:
                        System.out.println("Verfication: " + verifyDSA());
                        break;
                    case 3:
                        System.out.println("Verfication: " + verifyECDSA());
                        break;
                    case 0:
                    default:
                        continue;
                }
            }
        }
        while (true);
        writeToFile();
        System.out.println("DONE");
    }

}
