package kpp.passwordHasher;

import java.util.Base64;

public class UserObject
{
    public final static String seperator1 = ":";

    public final static String seperator2 = "$";

    private String user;

    private String hPassword;

    private int encoding;

    private String salt;

    public UserObject(String user, int encoding, String salt, String hPassword)
    {
        this.user = user;
        this.encoding = encoding;
        this.salt = salt;
        this.hPassword = hPassword;
    }

    public String getUser()
    {
        return user;
    }

    public String gethPassword()
    {
        return hPassword;
    }

    public int getEncoding()
    {
        return encoding;
    }

    public String getSalt()
    {
        return salt;
    }

    public byte[] getSaltBytes()
    {
        return salt.getBytes();
    }

    public byte[] getHPasswordBytes()
    {
        return hPassword.getBytes();
    }

    public void replaceHPassword(String hPassword)
    {
        this.hPassword = hPassword;
    }

    public void replaceEncoding(int encoding)
    {
        this.encoding = encoding;
    }

    public void replaceSalt(String salt)
    {
        this.salt = salt;
    }

    public String toString()
    {
        // <Benutzername>:$<Funktion-ID>$<Salt>$F(Salt,Passwort)
        return user + seperator1 + seperator2 + encoding + seperator2 + new String(Base64.getEncoder().encode(getSaltBytes())) + seperator2 + new String(Base64.getEncoder().encode(getHPasswordBytes()));
    }
}
