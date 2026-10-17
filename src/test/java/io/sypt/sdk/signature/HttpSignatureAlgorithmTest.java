package io.sypt.sdk.signature;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.sypt.sdk.exception.SyptException;

class HttpSignatureAlgorithmTest {

	@ParameterizedTest
	@CsvSource({
		"ecdsa-p256-sha256,				ECDSA_P256_SHA256",
		"SHA256withECDSA,				ECDSA_P256_SHA256",
		"SHA256withECDSAinP1363Format,	ECDSA_P256_SHA256",
		"sha384withecdsa,				ECDSA_P384_SHA384",
		"rsa-pss-sha512,				RSA_PSS_SHA512",
		"RSASSA-PSS,					RSA_PSS_SHA512",
		"SHA512withRSA/PSS,				RSA_PSS_SHA512",
		"rsa-v1_5-sha256,				RSA_V1_5_SHA256",
		"SHA256WithRSA,					RSA_V1_5_SHA256",
		"ed25519,						ED25519",
		"Ed25519,						ED25519",
		"EdDSA,							ED25519"
	})
	void resolveAcceptsRfcAndJcaNames(String name, HttpSignatureAlgorithm expected) throws SyptException {
		assertThat(HttpSignatureAlgorithm.resolve(name)).isEqualTo(expected);
	}

	@ParameterizedTest
	@ValueSource(strings = { "", " ", "SHA1withRSA", "hmac-sha256" })
	void resolveRejectsUnsupportedAlgorithms(String name) {
		assertThatThrownBy(() -> HttpSignatureAlgorithm.resolve(name))
			.isInstanceOf(SyptException.class)
			.extracting(e -> ((SyptException) e).getStatusCode())
			.isEqualTo(400);
	}

	@ParameterizedTest
	@ValueSource(strings = { "SHA256withRSA", "ED25519", "unknown" })
	void fromRfcNameOnlyAcceptsRfcNames(String name) {
		assertThatThrownBy(() -> HttpSignatureAlgorithm.fromRfcName(name))
			.isInstanceOf(SyptException.class)
			.hasMessageContaining(name);
	}
}
