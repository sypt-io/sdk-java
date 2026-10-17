package io.sypt.sdk.signature;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import com.authlete.hms.HttpSigner;

public final class HttpSigners {

	private HttpSigners() {
	}

	/**
	 * Adapt a JCA {@link Signature} to an authlete {@link HttpSigner}, applying the algorithm
	 * parameters when there are some (RSA-PSS).
	 */
	public static HttpSigner create(HttpSignatureAlgorithm algorithm, PrivateKey privateKey) {
		return baseBytes -> {
			try {
				Signature signature = Signature.getInstance(algorithm.getJcaName());
				if (algorithm.getSpec() != null) {
					signature.setParameter(algorithm.getSpec());
				}

				signature.initSign(privateKey);
				signature.update(baseBytes);
				return signature.sign();
			} catch (GeneralSecurityException e) {
				throw new SignatureException("Unable to sign (" + algorithm.getRfcName() + ")", e);
			}
		};
	}

}
