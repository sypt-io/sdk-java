package io.sypt.sdk.keys;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import io.sypt.core.keystore.factory.KSMType;
import io.sypt.sdk.exception.SyptException;
import io.sypt.sdk.util.JsonUtils;

/**
 * Parse the response of {@code GET /{domain}/keys/{keyMaterialId}}. Certificates are Base64 DER.
 */
public final class KeyMaterialParser {

	private static final Set<String> FIELDS = Set.of(
		"keyId", 
		"keyType",
		"verificationCertificate", 
		"signingAlgorithm", 
		"signingAlgorithmHash",
		"encryptionCertificate", 
		"decryptionAlgorithm", 
		"decryptionAlgorithmHash",
		"status"
	);

	private KeyMaterialParser() {
	}

	public static SyptKeyMaterialResponse parse(String payload) throws SyptException {
		Map<String, String> values = JsonUtils.readStringFields(
			payload == null ? null : payload.getBytes(StandardCharsets.UTF_8),
			FIELDS
		);

		return new SyptKeyMaterialResponse(
			values.get("keyId"),
			keyType(JsonUtils.requireField(values, "keyType")),
			certificate(JsonUtils.requireField(values, "verificationCertificate")),
			values.get("signingAlgorithm"),
			values.get("signingAlgorithmHash"),
			certificate(JsonUtils.requireField(values, "encryptionCertificate")),
			values.get("decryptionAlgorithm"),
			values.get("decryptionAlgorithmHash"),
			values.get("status")
		);
	}

	private static KSMType keyType(String value) throws SyptException {
		try {
			return KSMType.valueOf(value);
		} catch (IllegalArgumentException e) {
			throw new SyptException(502, "Unknown key type: " + value, e);
		}
	}

	private static Certificate certificate(String base64Der) throws SyptException {
		try {
			return CertificateFactory.getInstance("X.509").generateCertificate(
				new ByteArrayInputStream(Base64.getDecoder().decode(base64Der))
			);
		} catch (CertificateException | IllegalArgumentException e) {
			throw new SyptException(502, "Invalid certificate in key material", e);
		}
	}
}
