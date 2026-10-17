package io.sypt.sdk.exception;

/**
 * Error raised by the SDK. The status code follows HTTP semantics: 4xx for invalid input,
 * 5xx for local failures, or the status returned by the sypt.io API.
 */
public class SyptException extends Exception {
	
	private static final long serialVersionUID = -5983138098327261258L;
	
	private final int statusCode;

	public SyptException(String msg) {
		this(500, msg);
	}

	public SyptException(int statusCode, String msg) {
		super(msg);
		this.statusCode = statusCode;
	}

	public SyptException(String msg, Throwable e) {
		this(500, msg, e);
	}

	public SyptException(int statusCode, String msg, Throwable e) {
		super(msg, e);
		this.statusCode = statusCode;
	}
	
	public int getStatusCode() {
		return statusCode;
	}

}
