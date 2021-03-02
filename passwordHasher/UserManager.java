package kpp.passwordHasher;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

public class UserManager
{

    private HashMap<String, UserObject> map;

    public UserManager()
    {
        map = new HashMap();
    }

    public void add(UserObject uO)
    {
        map.put(uO.getUser(), uO);
    }

    public void add(String user, UserObject uO)
    {
        map.put(user, uO);
    }

    public void add(String user, int encoding, String salt, String hPassword)
    {
        UserObject uO = new UserObject(user, encoding, salt, hPassword);
        map.put(user, uO);
    }

    public HashMap<String, UserObject> getHashMap()
    {
        return map;
    }

    public UserObject getUserObject(String user)
    {
        return map.get(user);
    }

    public boolean checkUserExist(String user)
    {
        return map.containsKey(user);
    }

    public void createUser(String user, String password, int encoding) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        byte[] salt = generateSalt();
        add(user, encoding, new String(salt), generatePasswordHashString(password, encoding, salt));
    }

    public void replaceHPassword(String user, String hPassword, int encoding, byte[] salt)
    {
        UserObject uO = map.get(user);
        uO.replaceHPassword(hPassword);
        uO.replaceEncoding(encoding);
        uO.replaceSalt(new String(salt));
    }

    public List<String> getUserObjects()
    {
        List<String> list = new ArrayList<String>();
        Set<String> set = map.keySet();

        for (String s : set)
        {
            list.add(map.get(s).toString());
        }

        return list;
    }

    public byte[] generateSalt() throws NoSuchAlgorithmException
    {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    public boolean userExist(String user)
    {
        return map.containsKey(user);
    }

    public String generatePasswordHashString(String password, int encoding, byte[] salt) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        return new String(generatePasswordHash(password, encoding, salt));
    }

    public byte[] generatePasswordHash(String password, int encoding, byte[] salt) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        System.out.print("Create data, this may take a while ... ");
        Hasher hasher = new Hasher();
        byte[] result = null;
        long time1 = System.currentTimeMillis();
        switch (encoding)
        {
            case 0:
                result = hasher.getMD5(salt, password);
                break;
            case 1:
                result = hasher.getSHA1(salt, password);
                break;
            case 2:
                result = hasher.getSHA2_512(salt, password);
                break;
            case 3:
                result = hasher.getSHA3_512(salt, password);
                break;
            case 4:
                result = hasher.getPBKDF2WithHmacSHA1(salt, password);
                break;
            case 5:
                result = hasher.getPBKDF2WithHmacSHA512(salt, password);
                break;
            case 6:
                result = hasher.getScrypt(salt, password);
                break;
            case 7:
                result = hasher.getBcrypt(salt, password);
                break;
        }
        long time2 = System.currentTimeMillis();
        System.out.println(" ... done!");
        System.out.println(((time2 - time1) / 1000) + "," + ((time2 - time1) % 1000) + " seconds");
        return result;
    }

    public boolean validateAccount(String user, String password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        if (checkUserExist(user))
        {
            UserObject uo = getUserObject(user);

            byte[] currentPw = generatePasswordHash(password, uo.getEncoding(), uo.getSaltBytes());
            byte[] knownPw = uo.getHPasswordBytes();

            if (knownPw.length != currentPw.length)
            {
                return false;
            }
            int diff = knownPw.length ^ currentPw.length;
            for (int i = 0; i < knownPw.length && i < currentPw.length; i++)
            {
                diff |= knownPw[i] ^ currentPw[i];
            }
            return diff == 0;

        }
        return false;
    }

    public void printMap()
    {
        map.forEach((e, uo) -> System.out.println(uo.toString()));
    }
}
