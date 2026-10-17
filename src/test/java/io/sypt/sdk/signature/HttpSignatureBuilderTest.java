package io.sypt.sdk.signature;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.Test;

import io.sypt.sdk.TestKeys;
import io.sypt.sdk.exception.SyptException;

class HttpSignatureBuilderTest {

	private static final byte[] BODY = "{\"keyId\":\"k\",\"digest\":\"d\",\"context\":\"c\"}".getBytes(StandardCharsets.UTF_8);

	@Test
	void dateAndCreatedComeFromTheSameInstant() throws Exception {
		PrivateKey key = TestKeys.privateKey("vectors/keys/ed25519.pem", HttpSignatureAlgorithm.ED25519);

		// Just before a second boundary: two separate calls to now() could straddle it
		SyptSignatureHttpHeaders headers = HttpSignatureBuilder.newBuilder()
			.url("https://api.sypt.io/v1/example.com/sign")
			.payload(BODY)
			.parameters(TestKeys.parameters(HttpSignatureAlgorithm.ED25519, "kc", key))
			.clock(Clock.fixed(Instant.parse("2026-10-16T08:00:00.999Z"), ZoneOffset.UTC))
			.nonceGenerator(() -> "n")
			.build();

		assertThat(headers.date()).isEqualTo("Fri, 16 Oct 2026 08:00:00 GMT");
		assertThat(headers.signatureInput()).contains(";created=1792137600;");
	}

	@ParameterizedTest
	@EnumSource(HttpSignatureAlgorithm.class)
	void everyAlgorithmProducesAVerifiableSignature(HttpSignatureAlgorithm algorithm) throws Exception {
		String file = switch (algorithm) {
			case ECDSA_P256_SHA256 -> "ecdsa-p256";
			case ECDSA_P384_SHA384 -> "ecdsa-p384";
			case RSA_PSS_SHA512, RSA_V1_5_SHA256 -> "rsa-2048";
			case ED25519 -> "ed25519";
		};
		PrivateKey privateKey = TestKeys.privateKey("vectors/keys/" + file + ".pem", algorithm);
		PublicKey publicKey = TestKeys.publicKey("vectors/keys/" + file + ".pub.pem", algorithm);

		HttpSignatureBuilder builder = HttpSignatureBuilder.newBuilder()
			.url("https://api.sypt.io/v1/example.com/sign")
			.payload(BODY)
			.parameters(TestKeys.parameters(algorithm, "kc", privateKey))
			.clock(Clock.fixed(Instant.parse("2026-10-16T08:00:00Z"), ZoneOffset.UTC))
			.nonceGenerator(() -> "n");

		SyptSignatureHttpHeaders headers = builder.build();
		byte[] base = builder.signatureBase().signatureBase().serialize().getBytes(StandardCharsets.US_ASCII);
		String value = headers.signature().substring("sig1=:".length(), headers.signature().length() - 1);

		// Regression: rsa-pss-sha512 used to fail because the PSS parameters were never applied
		assertThat(TestKeys.verify(algorithm, publicKey, base, java.util.Base64.getDecoder().decode(value))).isTrue();
		assertThat(builder.signatureBase().signatureBase()
			.verify((data, signature) -> {
				try {
					return TestKeys.verify(algorithm, publicKey, data, signature);
				} catch (java.security.GeneralSecurityException e) {
					throw new java.security.SignatureException(e);
				}
			}, java.util.Base64.getDecoder().decode(value)))
			.isTrue();
	}

	@Test
	void emptyPayloadIsRejected() throws Exception {
		PrivateKey key = TestKeys.privateKey("vectors/keys/ed25519.pem", HttpSignatureAlgorithm.ED25519);

		assertThatThrownBy(() -> HttpSignatureBuilder.newBuilder()
				.url("https://api.sypt.io/v1/example.com/sign")
				.payload(new byte[0])
				.parameters(TestKeys.parameters(HttpSignatureAlgorithm.ED25519, "kc", key))
				.build())
			.isInstanceOf(SyptException.class)
			.extracting(e -> ((SyptException) e).getStatusCode())
			.isEqualTo(400);
	}

	@Test
	void unknownAlgorithmIsRejectedBeforeSigning() throws Exception {
		PrivateKey key = TestKeys.privateKey("vectors/keys/ed25519.pem", HttpSignatureAlgorithm.ED25519);
		var parameters = TestKeys.parameters(HttpSignatureAlgorithm.ED25519, "kc", key);
		var unknown = new io.sypt.sdk.credentials.SyptSignatureParameters() {
			@Override public String alg() { return "SHA1withRSA"; }
			@Override public String keyId() { return parameters.keyId(); }
			@Override public PrivateKey privateKey() { return key; }
		};

		assertThatThrownBy(() -> HttpSignatureBuilder.newBuilder()
				.url("https://api.sypt.io/v1/example.com/sign")
				.payload(BODY)
				.parameters(unknown)
				.build())
			.isInstanceOf(SyptException.class)
			.hasMessageContaining("SHA1withRSA");
	}
}
