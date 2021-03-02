package kpp.cbcMac;

import static org.junit.Assert.fail;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.CFBBlockCipherMac;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class CBC_Mac
{
    /*
     * I do not own any code from this class! Source:
     * https://programtalk.com/java-api-usage-examples/org.bouncycastle.crypto.
     * macs.CBCBlockCipherMac/
     */

    public static void main(String[] args)
    {

        KeyParameter key = new KeyParameter(keyBytes);
        BlockCipher cipher = new DESEngine();
        Mac mac = new CBCBlockCipherMac(cipher);
        //
        // standard DAC - zero IV
        //
        mac.init(key);
        mac.update(input1, 0, input1.length);
        byte[] out = new byte[4];
        mac.doFinal(out, 0);
        if (!areEqual(out, output1))
        {
            fail("Failed - expected " + new String(Hex.encode(output1)) + " got " + new String(Hex.encode(out)));
        }
        //
        // mac with IV.
        //
        ParametersWithIV param = new ParametersWithIV(key, ivBytes);
        mac.init(param);
        mac.update(input1, 0, input1.length);
        out = new byte[4];
        mac.doFinal(out, 0);
        if (!areEqual(out, output2))
        {
            fail("Failed - expected " + new String(Hex.encode(output2)) + " got " + new String(Hex.encode(out)));
        }
        //
        // CFB mac with IV - 8 bit CFB mode
        //
        param = new ParametersWithIV(key, ivBytes);
        mac = new CFBBlockCipherMac(cipher);
        mac.init(param);
        mac.update(input1, 0, input1.length);
        out = new byte[4];
        mac.doFinal(out, 0);
        if (!areEqual(out, output3))
        {
            fail("Failed - expected " + new String(Hex.encode(output3)) + " got " + new String(Hex.encode(out)));
        }
        //
        // word aligned data - zero IV
        //
        mac.init(key);
        mac.update(input2, 0, input2.length);
        out = new byte[4];
        mac.doFinal(out, 0);
        if (!areEqual(out, output4))
        {
            fail("Failed - expected " + new String(Hex.encode(output4)) + " got " + new String(Hex.encode(out)));
        }
        //
        // word aligned data - zero IV - CBC padding
        //
        mac = new CBCBlockCipherMac(cipher, new PKCS7Padding());
        mac.init(key);
        mac.update(input2, 0, input2.length);
        out = new byte[4];
        mac.doFinal(out, 0);
        if (!areEqual(out, output5))
        {
            fail("Failed - expected " + new String(Hex.encode(output5)) + " got " + new String(Hex.encode(out)));
        }
        //
        // non-word aligned data - zero IV - CBC padding
        //
        mac.reset();
        mac.update(input1, 0, input1.length);
        out = new byte[4];
        mac.doFinal(out, 0);
        if (!areEqual(out, output6))
        {
            fail("Failed - expected " + new String(Hex.encode(output6)) + " got " + new String(Hex.encode(out)));
        }
        //
        // non-word aligned data - zero IV - CBC padding
        //
        mac.init(key);
        mac.update(input1, 0, input1.length);
        out = new byte[4];
        mac.doFinal(out, 0);
        if (!areEqual(out, output6))
        {
            fail("Failed - expected " + new String(Hex.encode(output6)) + " got " + new String(Hex.encode(out)));
        }

    }
}
