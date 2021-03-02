package kpp.elgamal;

/*
Exceptions

notPrimeException wird geworfen, wenn p nicht prim ist.
gNotPrimtiveRootException wird geworfen, wenn g keine Primitivwurzel mod p ist.
InvalidPrivateKeyException wird geworfen, falls x<2 oder x>p-1.
*/

class notPrimeException extends Exception
{

    public notPrimeException(String message)
    {
        super(message);
    }
}

class gNotPrimtiveRootException extends Exception
{
    public gNotPrimtiveRootException(String message)
    {
        super(message);
    }
}

class InvalidPrivateKeyException extends Exception
{
    public InvalidPrivateKeyException(String message)
    {
        super(message);
    }
}
