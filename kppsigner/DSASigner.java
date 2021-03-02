package kpp.kppsigner;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

public class DSASigner
{
    private KeyPair keyPair;

    public DSASigner() throws NoSuchAlgorithmException, NoSuchProviderException
    {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");

        keyGen.initialize(512, new SecureRandom());

        this.keyPair = keyGen.generateKeyPair();

    }

    public KeyPair getKeyPair()
    {
        return keyPair;
    }

    public static byte[] generateSignature(PrivateKey privateKey, byte[] message) throws SignatureException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {

        Signature signature = Signature.getInstance("DSA", "BC");

        // generate a signature
        signature.initSign(privateKey);

        signature.update(message);

        return signature.sign();
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] input, byte[] encSignature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
    {// KeyStore store =KeyStore.getInstance("BKS");

        Signature signature = Signature.getInstance("DSA", "BC");

        signature.initVerify(publicKey);

        signature.update(input);

        return signature.verify(encSignature);

    }

}
