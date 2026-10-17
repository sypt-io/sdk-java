package io.sypt.sdk.credentials;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import io.sypt.sdk.entity.KeyAgent;
import io.sypt.sdk.entity.KeyAlgorithm;
import io.sypt.sdk.entity.KeyCertificateId;
import io.sypt.sdk.exception.SyptException;
import io.sypt.sdk.signature.HttpSignatureAlgorithm;

/**
 * Unencrypted PKCS#8 private key in PEM format (ex: the private key of an agent).
 */
public record SyptSignatureParametersPrivateKey(
		
	KeyCertificateId keyCertificateId,
	KeyAgent keyAgent,
	KeyAlgorithm algorithm
	
) implements SyptSignatureParameters {
	
	/**
	 * The signature algorithm can be given by its RFC 9421 name or by its JCA name
	 * (ex: SHA256withECDSA): it is always sent with its RFC 9421 name.
	 */
	@Override
	public String alg() throws SyptException {
		return HttpSignatureAlgorithm.resolve(algorithm.algorithmHash()).getRfcName();
	}

	@Override
	public String keyId() {
		return keyCertificateId.val();
	}

	@Override
	public PrivateKey privateKey() throws SyptException {
		String base64 = keyAgent.val()
			.replace("-----BEGIN PRIVATE KEY-----", "")
			.replace("-----END PRIVATE KEY-----", "")
			.replaceAll("\\s", "");

		try {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64));
			return KeyFactory.getInstance(algorithm.algorithm()).generatePrivate(keySpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | IllegalArgumentException e) {
			throw new SyptException(400, "Cannot obtain PrivateKey", e);
		}
	}

}
