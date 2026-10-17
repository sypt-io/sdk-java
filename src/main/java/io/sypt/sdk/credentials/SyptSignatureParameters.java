package io.sypt.sdk.credentials;

import java.security.PrivateKey;

import io.sypt.sdk.exception.SyptException;
import io.sypt.sdk.signature.HttpSignatureAlgorithm;

/**
 * Credentials used to sign the requests sent to sypt.io: the private key matching the
 * certificate registered on the platform, its Key ID and the RFC 9421 algorithm.
 */
public interface SyptSignatureParameters {
	
	/**
	 * @return RFC 9421 algorithm name (ex: ecdsa-p256-sha256)
	 */
	public String alg() throws SyptException;
	
	public String keyId();
	
	public PrivateKey privateKey() throws SyptException;
	
	default String keyAlgorithm() throws SyptException {
		return HttpSignatureAlgorithm.fromRfcName(alg()).getJcaName();
	}

}
