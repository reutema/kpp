package kpp.kppsigner;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.security.auth.x500.X500PrivateCredential;

public class MyKeyStore
{
    private String path;

    private KeyStore store;

    private KeyPair keyPair;

    private char[] keyPassword;

    public MyKeyStore(String path, char[] keyPassword) throws Exception
    {
        this.path = path;
        this.keyPassword = keyPassword;

        if (path.equals(""))
        {
            createKeyStore();
        }
        else
        {
            loadKeyStore();
        }
    }

    private void createKeyStore() throws Exception
    {
        this.store = KeyStore.getInstance("JKS");

        // initialize
        store.load(null, null);
    }

    private void loadKeyStore() throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException
    {

        store.load(new FileInputStream(path), keyPassword);
        Random random = new Random();

        for (int i = 0; i < keyPassword.length; i++)
        {
            this.keyPassword[i] = (char) random.nextInt();
        }

    }

    public void saveSignature(Signature sign) throws Exception
    {
        if(keyPair == null) {
            throw new NoKeyPairException();
        }

        X509Certificate rootCert =
        
        X500PrivateCredential rootCredential =  new X500PrivateCredential(rootCert, keyPair.getPrivate()

        X500PrivateCredential interCredential = Utils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());

        X500PrivateCredential endCredential = Utils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());

        Certificate[] chain = new Certificate[3];

        chain[0] = endCredential.getCertificate();
        chain[1] = interCredential.getCertificate();
        chain[2] = rootCredential.getCertificate();

        // set the entries
        store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
        store.setKeyEntry(endCredential.getAlias(), endCredential.getPrivateKey(), keyPassword, chain);

    }

}

class NoKeyPairException extends Exception
{

}
