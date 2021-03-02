package kpp.certificateprinter;

public class Helper
{

    public static String toHex(byte[] array)
    {
        return Utils.bytesToHex(array);
    }

    public static String toHex(int value)
    {
        return "0x" + Integer.toHexString(value - 1);
    }

    public static String formatHex(byte[] array, int columns)
    {

        return addDots(toHex(array), columns);
    }

    public static String addDots(String text, int columns)
    {
        StringBuilder builder = new StringBuilder();

        for (int i = 0, counter = 1; i < text.length(); counter++)
        {
            if (text.length() < i + 2)
            {
                break;
            }
            builder.append(text.charAt(i++));
            builder.append(text.charAt(i++));
            if (i < text.length())
            {
                builder.append(":");
            }
            if (!(counter < columns || columns < 0))
            {
                builder.append("\n");
                counter = 0;
            }
        }

        return builder.toString();
    }

    public static String nextLineAfter(String text, int value)
    {
        StringBuilder builder = new StringBuilder(text);
        for (int i = value - 1; i < text.length(); i += value)
        {
            builder.insert(i, "\n");
        }

        return builder.toString();
    }

}

class Blank
{
    private int blank;

    private String line;

    public Blank()
    {
        update(0);
    }

    public void update(int value)
    {
        blank += value;
        char[] cs = new char[blank];
        for (char c : cs)
        {
            c = ' ';
        }
        line = new String(cs);
    }

    public String getLine()
    {
        return line;
    }

    @Override
    public String toString()
    {
        return this.line;
    }

}