package kpp.jaegerzaun;

public class JaegerzaunCipher
{
    int[] perm;

    int[] invPerm;

    int key; // Tiefe

    public JaegerzaunCipher(int key) throws IllegalKeyLengthException
    {
        if (key <= 1)
        {
            throw new IllegalKeyLengthException("Small key, get a bigger one!");
        }
        else
        {
            this.key = key;
        }
    }

    public String encrypt(String txt)
    {
        perm = getPerm(key, txt.length());
        invPerm = getInvPerm(perm);

        StringBuilder sb = new StringBuilder();

        for (int i : perm)
        {
            sb.append(txt.charAt(i));
        }

        return sb.toString();
    }

    public String decrypt(String txt)
    {
        if (perm == null)
        {
            perm = getPerm(key, txt.length());
        }

        invPerm = getInvPerm(perm);

        StringBuilder sb = new StringBuilder();

        for (int i : invPerm)
        {
            sb.append(txt.charAt(i));
        }

        return sb.toString();
    }

    public int[] getPerm(int key, int length)
    {
        boolean[][] p = new boolean[key][length];

        int[] perm = new int[length];
        boolean change = true;

        for (int i = 0, j = 0; i < length; i++)
        {
            p[j][i] = true;

            if (change)
            {
                if (j >= key - 1)
                {
                    j--;
                    change = false;
                    continue;
                }
                else
                    j++;
            }
            else
            {
                if (j > 0)
                    j--;
                else
                {
                    change = true;
                    j++;
                    continue;
                }
            }
        }

        for (int j = 0, k = 0; j < key; j++)
        {
            for (int i = 0; i < length; ++i)
            {

                if (p[j][i])
                {
                    perm[k] = i;
                    k++;
                }
            }
        }

        return perm;
    }

    public int[] getInvPerm(int[] perm)
    {
        invPerm = new int[perm.length];

        for (int i = 0; i < perm.length; ++i)
        {
            int tmp = perm[i];
            invPerm[tmp] = i;
        }

        return invPerm;
    }

    public void printPerm()
    {
        if (perm == null)
        {
            return;
        }

        for (int i = 0; i < perm.length; ++i)
        {
            System.out.print(perm[i]);
        }
        System.out.println();

    }

    public static void main(String[] args) throws IllegalKeyLengthException
    {
        JaegerzaunCipher jc = new JaegerzaunCipher(4);
        jc.printPerm();
        System.out.println(jc.encrypt("DASISTDASHAUSVOMNIKOLAUS"));
        System.out.println(jc.decrypt(jc.encrypt("DASISTDASHAUSVOMNIKOLAUS")));
    }
}

class IllegalKeyLengthException extends Exception
{
    public IllegalKeyLengthException(String s)
    {
        super(s);
    }

}
