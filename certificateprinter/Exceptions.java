package kpp.certificateprinter;

class UnimplementedExcepetion extends Exception {
	public UnimplementedExcepetion(String message) {
		super(message);
	}

}

class UnknownExtensionException extends Exception {
	public UnknownExtensionException(String message) {
		super(message);
	}
}

class UnknownDistributionPointNameException extends Exception {
}
