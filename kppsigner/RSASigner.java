package kpp.kppsigner;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;

public class RSASigner
{
    private KeyPair keyPair;

    public RSASigner() throws GeneralSecurityException
    {
        this.keyPair = generateRSAKeyPair();

    }

    public KeyPair getKeyPair()
    {
        return keyPair;
    }

    private KeyPair generateRSAKeyPair() throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");

        keyPair.initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4));

        return keyPair.generateKeyPair();
    }

    public static byte[] generateSignature(PrivateKey privateKey, byte[] input) throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("RSA", "BC");

        signature.initSign(privateKey);

        signature.update(input);

        return signature.sign();
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] input, byte[] encSignature) throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("RSA", "BC");

        signature.initVerify(publicKey);

        signature.update(input);

        return signature.verify(encSignature);
    }
}
