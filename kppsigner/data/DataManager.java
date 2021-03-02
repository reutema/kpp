package kpp.kppsigner.data;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

import org.bouncycastle.util.encoders.Base64;

import kpp.kppsigner.KPPSigner;

public class DataManager
{
    private ArrayList<Data> list;

    public DataManager()
    {
        this.list = new ArrayList<>();
    }

    public void add(String cryptoMethod, String nameOfData, byte[] signature, KeyPair keys)
    {
        this.list.add(new Data(cryptoMethod, nameOfData, signature, keys));
    }

    public void decode(String line) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException
    {
        System.out.println(">: " + line);
        String[] container = new String[5];
        int seperator2Start;
        int seperator2End;

        container[0] = line.substring(0, line.indexOf(Data.seperator));
        seperator2Start = line.indexOf(Data.seperator) + 1;
        System.out.println("> " + container[0]);
        for (int i = 1; i < 5; i++)
        {

            seperator2End = line.indexOf(Data.seperator, seperator2Start);
            container[i] = line.substring(seperator2Start, seperator2Start);
            System.out.println("> " + container[i]);
            seperator2Start = line.indexOf(Data.seperator, seperator2End) + 1;
        }

        byte[] publicBytes = Base64.decode(container[3]);
        byte[] privateBytes = Base64.decode(container[4]);

        PublicKey pubKey = KPPSigner.decodePublicKey(container[0], publicBytes);
        PrivateKey privKey = KPPSigner.decryptPrivateKey(container[0], privateBytes);

        KeyPair keys = new KeyPair(pubKey, privKey);
        add(container[0], container[1], container[2].getBytes(), keys);
    }

    public ArrayList<Data> getDatas()
    {
        return list;
    }

    public byte[] getSignatureFrom(String cryptoMethod, byte[] input, PublicKey publicKey)
    {
        for (Data d : list)
        {
            if (d.equalsTo(cryptoMethod, new String(input), publicKey))
            {
                return d.getSignature();
            }
        }
        return null;
    }
}
