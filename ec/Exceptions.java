package kpp.ec;

class ECParamsIllegalException extends Exception {

	public ECParamsIllegalException(String message) {
		super(message);
	}
}

class PNotPrimeException extends Exception {
	public PNotPrimeException(String message) {
		super(message);
	}
}