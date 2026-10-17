package io.sypt.sdk.credentials;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URISyntaxException;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import io.sypt.sdk.TestKeys;
import io.sypt.sdk.entity.KeyAgent;
import io.sypt.sdk.entity.KeyAlg;
import io.sypt.sdk.entity.KeyAlgorithm;
import io.sypt.sdk.entity.KeyAlias;
import io.sypt.sdk.entity.KeyCertificateId;
import io.sypt.sdk.entity.KeystorePassword;
import io.sypt.sdk.entity.KeystorePath;
import io.sypt.sdk.exception.SyptException;

class SyptSignatureParametersTest {

	/**
	 * Regression: alg() used to return the JCA name given on the command line (ex: SHA256withECDSA),
	 * which was then rejected as an unknown RFC 9421 algorithm.
	 */
	@ParameterizedTest
	@CsvSource({
		"EC,		SHA256withECDSA,	ecdsa-p256.pem,	ecdsa-p256-sha256",
		"EC,		ecdsa-p256-sha256,	ecdsa-p256.pem,	ecdsa-p256-sha256",
		"EC,		SHA384withECDSA,	ecdsa-p384.pem,	ecdsa-p384-sha384",
		"RSA,		SHA256withRSA,		rsa-2048.pem,	rsa-v1_5-sha256",
		"Ed25519,	Ed25519,			ed25519.pem,	ed25519"
	})
	void pemKeyAcceptsRfcAndJcaAlgorithmNames(String keyAlgorithm, String algorithmHash, String pem, String expectedAlg) throws SyptException {
		SyptSignatureParametersPrivateKey parameters = new SyptSignatureParametersPrivateKey(
			new KeyCertificateId("kc"),
			new KeyAgent(TestKeys.resource("vectors/keys/" + pem)),
			new KeyAlgorithm(keyAlgorithm, algorithmHash)
		);

		assertThat(parameters.alg()).isEqualTo(expectedAlg);
		assertThat(parameters.keyId()).isEqualTo("kc");
		assertThat(parameters.privateKey().getAlgorithm()).isIn(keyAlgorithm, "EdDSA");
	}

	@Test
	void invalidPemIsRejected() {
		SyptSignatureParametersPrivateKey parameters = new SyptSignatureParametersPrivateKey(
			new KeyCertificateId("kc"),
			new KeyAgent("-----BEGIN PRIVATE KEY-----\nnot base64!\n-----END PRIVATE KEY-----"),
			new KeyAlgorithm("EC", "ecdsa-p256-sha256")
		);

		assertThatThrownBy(parameters::privateKey)
			.isInstanceOf(SyptException.class)
			.extracting(e -> ((SyptException) e).getStatusCode())
			.isEqualTo(400);
	}

	@Test
	void keystoreKeyIsLoaded() throws Exception {
		SyptSignatureParametersKeystore parameters = keystore("caller");

		assertThat(parameters.alg()).isEqualTo("ecdsa-p256-sha256");
		assertThat(parameters.keyId()).isEqualTo("kc");
		assertThat(parameters.privateKey().getAlgorithm()).isEqualTo("EC");
	}

	@Test
	void unknownKeystoreAliasIsRejected() throws Exception {
		SyptSignatureParametersKeystore parameters = keystore("missing");

		assertThatThrownBy(parameters::privateKey)
			.isInstanceOf(SyptException.class)
			.hasMessageContaining("missing")
			.extracting(e -> ((SyptException) e).getStatusCode())
			.isEqualTo(400);
	}

	private static SyptSignatureParametersKeystore keystore(String alias) throws URISyntaxException {
		String path = Path.of(SyptSignatureParametersTest.class.getResource("/keystore/caller-ec.p12").toURI()).toString();

		return new SyptSignatureParametersKeystore(
			new KeyCertificateId("kc"),
			new KeystorePath(path),
			new KeystorePassword(TestKeys.CALLER_KEYSTORE_PASSWORD),
			new KeyAlias(alias),
			new KeyAlg("ecdsa-p256-sha256")
		);
	}
}
