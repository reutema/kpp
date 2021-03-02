package kpp.rsa;

class PrivateKeyNotSetException extends Exception
{
    public PrivateKeyNotSetException(String message)
    {
        super(message);
    }
}

class MessageTooLongException extends Exception
{
    public MessageTooLongException(String message)
    {
        super(message);
    }
}
