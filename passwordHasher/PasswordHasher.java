package kpp.passwordHasher;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

public class PasswordHasher
{
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException
    {
        PasswordHasher pwh = new PasswordHasher();

    }

    private UserObject currentUser;

    private UserManager userManager;

    private BufferedReader buf;

    private String shadow = "shadow.txt";

    private String wp = "weakPasswords.txt";

    private List<String> weakPw;

    public PasswordHasher() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException
    {

        boolean inputIsRunning = true;
        userManager = new UserManager();
        buf = new BufferedReader(new InputStreamReader(System.in));
        try
        {
            loadPasswords();
        }
        catch (NumberFormatException | IOException e1)
        {
            System.err.println("broken shadow.txt");
            e1.printStackTrace();
        }
        while (inputIsRunning)
        {
            System.out.println("\n0: Beenden \n1: Neuer Benutzer anlegen \n2: Password ändern \n3: Authentifizierung \n4: schwache Passwörter finden\n");

            int in;
            try
            {
                in = Integer.parseInt(buf.readLine());
            }
            catch (Exception e)
            {
                System.out.println("Ihre Eingabe hatte nicht das richtige Format");
                continue;
            }

            if (0 == in)
            {
                inputIsRunning = false;
            }
            else if (1 == in)
            {
                // add user
                createAccount();

            }
            else if (2 == in)
            {
                // change password
                changePassword();
            }
            else if (3 == in)
            { // authentification
                authentificateAccount();
            }
            else if (4 == in)
            { // find weakp passwords
                findWeakPasswords();
            }

        }
        try
        {
            writeToFile(shadow);
        }
        catch (IOException e)
        {
            System.err.println("could not write data");
        }
        buf.close();
        System.out.println("done");
    }

    public void findWeakPasswords() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        Set<String> keys = userManager.getHashMap().keySet();
        if (weakPw == null)
        {
            try
            {
                weakPw = loadWeakPasswords();
            }
            catch (NumberFormatException | IOException e)
            {
                System.err.println("weak password file corrupted");
                return;
            }
        }
        System.out.println("");

        List<String> list = new ArrayList<>();
        for (String user : keys)
        {
            for (String weakPassword : weakPw)
            {
                if (userManager.validateAccount(user, weakPassword))
                {
                    list.add("\n------------------------\nUser " + user + " has the weak password: " + weakPassword + "\n------------------------\n");

                }
            }
        }
        list.forEach(s -> System.out.println(s));
    }

    public boolean authentificateAccount()
    {
        String user = readUsername();
        String pw = readPassword();
        try
        {
            if (!userManager.validateAccount(user, pw))
            {
                System.err.println("authentification failed!");
                return false;
            }
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException
                        | InvalidKeySpecException e)
        {
            System.err.println("authentification failed!");
            return false;
        }
        this.currentUser = userManager.getUserObject(user);
        return true;
    }

    public boolean createAccount()
    {

        String user = readUsername();
        if (!userManager.checkUserExist(user))
        {
            String password = readPassword();

            int encoding = readEncoding();

            try
            {
                System.out.println("create new account...");
                userManager.createUser(user, password, encoding);
            }
            catch (NoSuchAlgorithmException | NoSuchProviderException
                            | InvalidKeySpecException e)
            {
                System.err.println("create account failure");
                e.printStackTrace();
                return false;
            }
            currentUser = userManager.getUserObject(user);
            System.out.println("new account created!");
            return true;
        }
        System.out.println("user already exist!\n");
        return false;
    }

    public boolean changePassword()
    {
        String user;
        if (currentUser == null)
        {
            int tries = 5;
            do
            {
                System.out.print("user: ");
                user = readInputString();
                System.out.println();
                tries--;
                if (tries <= 0)
                {
                    System.out.println("you are not yourself!\n");
                    return false;
                }
            }
            while (!userManager.userExist(user));

            String password = readPassword();
            try
            {
                if (userManager.validateAccount(user, password))
                {
                    System.out.println("Account valid");
                }
                else
                {
                    System.out.println("Accound not valid");
                    return false;
                }
            }
            catch (NoSuchAlgorithmException | NoSuchProviderException
                            | InvalidKeySpecException e1)
            {
                System.err.println("account not valide");
                return false;
            }
        }
        else
        {
            user = currentUser.getUser();
        }
        System.out.println("Current account: " + user);
        String newPassword = readNewPassword();
        int encoding = readEncoding();

        try
        {
            byte[] salt = userManager.generateSalt();
            userManager.replaceHPassword(user, userManager.generatePasswordHashString(newPassword, encoding, salt), encoding, salt);
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException
                        | InvalidKeySpecException e)
        {
            return false;
        }

        return true;

    }

    public String readUsername()
    {
        System.out.print("Enter username: ");
        String user;
        // do
        // {
        user = readInputString();

        user = user.trim().toLowerCase();
        // }
        // while (userManager.userExist(user));
        System.out.println();
        return user;
    }

    public String readPassword()
    {
        System.out.print("Enter password: ");
        String pw = readInputString();
        pw = pw.trim();

        System.out.println();
        return pw;
    }

    public String readNewPassword()
    {
        System.out.print("Enter new password: ");
        String pw = readInputString();
        pw = pw.trim();
        System.out.println();
        System.out.print("Confirm new password: ");
        String pw2 = readInputString();
        pw2 = pw2.trim();
        System.out.println();
        if (pw.equals(pw2))
        {
            return pw;
        }
        else
        {
            return readNewPassword();
        }
    }

    public int readEncoding()
    {
        boolean notright = true;
        int input = 0;
        System.out.println("0: MD5 \n1: SHA1 \n2: SHA2_512 \n3: SHA3_512 \n4: PBKDF2WithHmacSHA1 \n5: PBKDF2WithHmacSHA512 \n6: Scrypt \n7: Bcrypt");
        while (notright)
        {
            input = readInputInt();
            if (input >= 0 && input < 8)
            {
                notright = false;
            }
        }
        return input;
    }

    public String readInputString()
    {
        // Scanner input = new Scanner(System.in);
        // String s = input.nextLine();
        try
        {
            return buf.readLine();
        }
        catch (IOException e)
        {
            System.err.println("wrong input, try again");
            return readInputString();
        }
    }

    public int readInputInt()
    {
        boolean tmp = true;
        int number = -1;
        while (tmp)
        {
            try
            {
                number = Integer.parseInt(buf.readLine());
                tmp = false;
            }
            catch (Exception e)
            {
                System.out.println("only numbers allowed!");
                tmp = true;
            }
        }
        return number;

    }

    public void loadPasswords() throws NumberFormatException, IOException
    {
        BufferedReader bf = readFromFile(shadow);

        String line;
        int count = 0;
        System.out.println("loading password(s)");
        while ((line = bf.readLine()) != null)
        {
            String user = line.substring(0, line.indexOf(UserObject.seperator1));
            int seperator2Start = line.indexOf(UserObject.seperator2) + 1;

            int seperator2End = line.indexOf(UserObject.seperator2, seperator2Start);
            int encoding = Integer.parseInt(line.substring(seperator2Start, seperator2End));
            seperator2Start = seperator2End + 1;
            seperator2End = line.indexOf(UserObject.seperator2, seperator2Start);

            String salty = line.substring(seperator2Start, seperator2End);
            seperator2Start = seperator2End + 1;

            String hPasswordTmp = line.substring(seperator2Start, line.length());

            String salt = new String(Base64.getDecoder().decode(salty.getBytes()));
            String hPassword = new String(Base64.getDecoder().decode(hPasswordTmp.getBytes()));
            userManager.add(user, encoding, salt, hPassword);
            count++;
        }
        bf.close();
        System.out.println(">" + count);
    }

    public List<String> loadWeakPasswords() throws NumberFormatException, IOException
    {
        BufferedReader bf = readFromFile(wp);

        String line;
        List<String> list = new ArrayList<>();

        while ((line = bf.readLine()) != null)
        {
            list.add(line.trim());
        }
        bf.close();
        System.out.println(list.size() + " weak password(s) loaded\n");
        return list;
    }

    private BufferedReader readFromFile(String file) throws FileNotFoundException
    {
        URL path = PasswordHasher.class.getResource(file);
        File f = new File(path.getFile());
        return new BufferedReader(new FileReader(f));

    }

    public void writeToFile(String data) throws IOException
    {
        List<String> userList = userManager.getUserObjects();
        System.out.println(">" + userList.size());
        // <Benutzername>:$<Funktion-ID>$<Salt>$F(Salt,Passwort)
        String path = "./src/kpp/passwordHasher/shadow.txt";
        // URL path = PasswordHasher.class.getResource(data);
        File f = new File(path);
        BufferedWriter bw = new BufferedWriter(new FileWriter(f));
        // hier schleife einfuegen
        for (String s : userList)
        {
            bw.write(s + "\n");
        }
        bw.close();
    }

    private void loadUser() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        System.out.println("loading intern users");
        for (int i = 0; i < 8; i++)
        {
            byte[] salt = userManager.generateSalt();
            String hPassword = userManager.generatePasswordHashString("passwort", i % 8, salt);
            userManager.add("user" + i, i % 8, new String(salt), hPassword);
        }
    }

}
