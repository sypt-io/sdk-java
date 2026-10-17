package io.sypt.sdk.keys;

import java.security.cert.Certificate;

import io.sypt.core.keystore.factory.KSMType;

/**
 * Response of {@code GET /{domain}/keys/{keyMaterialId}}.
 */
public record SyptKeyMaterialResponse(

	String keyId,
	KSMType keyType,
	Certificate verificationCertificate,
	String signingAlgorithm,
	String signingAlgorithmHash,
	Certificate encryptionCertificate,
	String decryptionAlgorithm,
	String decryptionAlgorithmHash,
	String status

) {

}
