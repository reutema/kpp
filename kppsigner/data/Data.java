package kpp.kppsigner.data;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

import kpp.kppsigner.KPPSigner;

public class Data
{
    public final static String seperator = "|----|";

    private String cryptoMethod;

    private String nameOfData;

    private byte[] signature;

    private KeyPair keys;

    public Data(String cryptoMethod, String nameOfData, byte[] signature, KeyPair keys)
    {
        this.cryptoMethod = cryptoMethod;
        this.nameOfData = nameOfData;
        this.signature = signature;
        this.keys = keys;
    }

    public boolean equalsTo(String cryptoMethod, String nameOfData, PublicKey publicKey)
    {
        return this.cryptoMethod.equals(cryptoMethod) && this.nameOfData.equals(nameOfData) && this.keys.getPublic().equals(publicKey);
    }

    public String toString()
    {
        return cryptoMethod + seperator + nameOfData + seperator + new String(Base64.getEncoder().encode(signature)) + seperator + new String(Base64.getEncoder().encode(KPPSigner.encodePublicKey(keys))) + seperator + new String(Base64.getEncoder().encode(KPPSigner.encryptPrivateKey(keys))) + seperator;
    }

    public byte[] getSignature()
    {
        return signature;
    }
}
