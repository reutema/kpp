package kpp.otp;

public class OTP_Test
{
    private static long knownKey = 492432919399082l;

    public static void main(String[] args)
    {
        try
        {

            verschluesseln();
            entschluesseln();
        }
        catch (Exception e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static void verschluesseln() throws Exception
    {

        // String s =
        // "5hYOBsQLb476eVv/vwNw93rP2ZSAjRoji/OJ4A3wyBtpWty/VEipd9wCBpMRMZUcTSWZp3jGPMr9yd5Kx37eYKQiihYc6PqQxOQXJUO5CznDgOXwiyKMZ9ar54ngwmJLNH0CeDSWh3aZReRBfjowW1x86pbKE1eatWJWvGhcdtt41HsEbWT1fCZnWmSSktH18C1NwANhJWSQxrQ2e2jNSgQDypg11/bOuaKYz/2bGW2QtXOaH1qyHbCSkzxAGztehg2jfimxpbQFeQ2kjmapxQEPz1+AqzSDRMAoVqxRYZQh0boAu6U=";
        String s = "HelloWorld";
        long time1 = System.nanoTime(); // Start des Benchmarks
        OTP_Cipher cipher = new OTP_Cipher();
        cipher.setPlaintextByString(s); // setzen des Klartextes
        cipher.setRandomKey();
        // cipher.setKnownKeyEnc(knownKey);

        // cipher.setRandomKey(); // zufälligen Schlüssel generieren
        System.out.println("time 1.5 " + System.nanoTime());
        cipher.encrypt(); // verschlüsseln
        long time2 = System.nanoTime(); // Ende des Benchmarks
        /*
         * Ausgabe
         */
        System.out.println("Plaintext: " + new String(cipher.getPlaintext()) + "\n" + "Ciphertext: " + new String(cipher.getCiphertext()) + "\n" + "Key: " + new String(cipher.getKey()) + "\n" + "Key (Base64): " + cipher.getEncodedKey() + "Ciphertext (Base64): " + cipher.getEncodedCiphertext() + "--- Benchmark ---" + "\n" + "Nano-Zeit vor Verschlüsselung: " + time1 + "\n" + "Nano-Zeit nach Verschlüsselung: " + time2 + "\n" + "Benötigte Zeit: " + (double) (time2 - time1) / 1000000 + " Millisekunden" + "\n");
        System.out.println("Key2: " + new String(cipher.getKey()));
    }

    public static void entschluesseln() throws Exception
    {
        OTP_Cipher cipher = new OTP_Cipher();

        // String s =
        // "q04b4lnLBpZhD47nEa+9vSU4wB3KAOWOK8ZSwctJzvT9QVaSbIPZxK5QTVZbBRnHXXQRMAmrszXN8wWWSm+lgFumwZE+iBNXlu0L6kAeWj75n2vrDZChVEO7zq9Ldf9bocjoOtKyS/+BVk3Ubnz3fRLHxyjs1qdtUu+MVaXETdMBQJ5Rt51ifRr9Zt59hHyI9vZzILdr9zaA84W8+c3f15aeVNhp6JUv1FsWArGKvQ3ILG6+g5Uj9arZ1d45W2TEogORItUahKNBSGmKDx/g2e+UTT9NhrOjauSoy6E+Pqb7nt8Qfygr+QGl6iHGmQewDNW8Xu08RL4t9j8ukdCXTwVgEZ2TEe5Fp9om1xY50kzUQ0oUoAGdw6wYEkMYOIVQqilVmvXkvjwwZMAQEYeoLEOPWI0=";
        // String k =
        // "niZCrRu4V9oDO7nRdPnLklNPjmrzM5feGZwBgKEboZ6UbhnYWMLqs9cSOSYMcWDoCzF4QG2SxHaPg0jEBzXw4w/1lstOu3kQxqB50zl6b3WBrFyOVNvwPSrTl8x9JY4K2Ye5YpjnBMrCLCOQCTOvCnu+jGW278YfZ9viMtKpB59PCK4S0tkxKnLOB4Qv4S7KkJwcV+Bajw62g+f3vPy6tuLJHo8fr/1MsC9iNoDCzkiqezqP5dZ5m/20ho1SLyz1mkCgbKJbyssLHzrbd22x64qmJ3Ee4eLnE5TP+pARXOmO/5RJBQcZm0by2HCywUjRROTNJ6VeB+1GjEdv1qrjKm0HI/f1eIM917h3kXNo4Ce+Litk2FDYk9YpOQJpQtYU+GQU9aOVxm5pPpF4IeXHbTa5DbA=";

        String s = "pesMhOUUX+XV3A==";
        String k = "7Y5g6IpDMJe5uA==";

        cipher.setCiphertextByBase64(s); // setzen des Chiffretextes
        // cipher.setKeyByBase64(k);
        cipher.setKnownKey(knownKey);

        // cipher.setKeyByBase64(k); // setzen
        // des
        // Schlüssels
        cipher.decrypt(); // entschlüsseln
        /*
         * Ausgabe
         */
        System.out.println("Ciphertext: " + new String(cipher.getCiphertext()) + "\n" + "Key: " + new String(cipher.getKey()) + "\n" + "Plaintext: " + new String(cipher.getPlaintext()) + "\nBase64 Plaintext: " + cipher.getEncodedPlaintext());

    }

}
