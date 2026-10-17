package io.sypt.sdk.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

import io.sypt.sdk.exception.SyptException;

public final class DigestUtils {

	private DigestUtils() {
	}

	/**
	 * Compute the RFC 9530 {@code Content-Digest} value of a payload.
	 */
	public static Optional<String> computeSha256Digest(byte[] payload) throws SyptException {
		if (payload == null || payload.length == 0) {
			return Optional.empty();
		}
		
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(payload);
			return Optional.of("sha-256=:" + Base64.getEncoder().encodeToString(hash) + ":");
		} catch (NoSuchAlgorithmException e) {
			throw new SyptException("Algorithm SHA-256 is unavailable", e);
		}
	}

}
