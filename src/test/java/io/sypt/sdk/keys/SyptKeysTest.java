package io.sypt.sdk.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

import io.sypt.core.crypter.factory.CrypterFactory;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMType;
import io.sypt.core.signer.factory.SignerFactory;
import io.sypt.sdk.StubServer;
import io.sypt.sdk.SyptClient;
import io.sypt.sdk.TestKeys;
import io.sypt.sdk.entity.Domain;
import io.sypt.sdk.entity.KeyMaterialId;
import io.sypt.sdk.exception.SyptException;

/**
 * Local verification and encryption with the certificates served by the API. The keystores
 * stand for the key materials held by sypt.io (test keystores of sypt-core).
 */
class SyptKeysTest {

	private static final String ALIAS = "sypt-crypto-data";
	private static final Domain DOMAIN = new Domain("example.com");

	private StubServer server;
	private SyptKeys keys;

	@BeforeAll
	static void bouncyCastle() {
		// ECIES (EC encryption) is provided by BouncyCastle, which the application registers (as the CLI does)
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@BeforeEach
	void setUp() {
		server = new StubServer();
		keys = new SyptKeys(SyptClient.newBuilder().baseUri(server.baseUri()).build());
	}

	@AfterEach
	void tearDown() {
		server.close();
	}

	/**
	 * Regression: the certificates were stored under the keyId returned by the API but looked up
	 * under the requested ID, so the verification failed whenever both differed.
	 */
	@ParameterizedTest
	@CsvSource({ "sypt-crypto-data-ec.p12, EC_384", "sypt-crypto-data-pqc.p12, PQC_L5" })
	void verifiesSignaturesProducedWithTheKeyMaterial(String keystore, KSMType type) throws Exception {
		try (KSM ksm = new FileKSM("classpath:keystore/" + keystore, TestKeys.KEYSTORE_PASSWORD.toCharArray())) {
			serveKeyMaterial("km-requested", "km-returned-by-the-api", type, ksm);

			byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes(StandardCharsets.UTF_8));
			String signature = SignerFactory.getSigner(type, ksm, ALIAS).sign(digest);
			String encodedDigest = Base64.getEncoder().encodeToString(digest);

			assertThat(keys.verify(DOMAIN, new KeyMaterialId("km-requested"), encodedDigest, signature)).isTrue();

			byte[] otherDigest = MessageDigest.getInstance("SHA-256").digest("other".getBytes(StandardCharsets.UTF_8));
			assertThat(keys.verify(DOMAIN, new KeyMaterialId("km-requested"), Base64.getEncoder().encodeToString(otherDigest), signature)).isFalse();

			// Certificates are fetched once
			assertThat(server.requests()).hasSize(1);
		}
	}

	@ParameterizedTest
	@CsvSource({ "sypt-crypto-data-ec.p12, EC_384", "sypt-crypto-data-pqc.p12, PQC_L5" })
	void encryptsDataThatTheKeyMaterialCanDecrypt(String keystore, KSMType type) throws Exception {
		try (KSM ksm = new FileKSM("classpath:keystore/" + keystore, TestKeys.KEYSTORE_PASSWORD.toCharArray())) {
			serveKeyMaterial("km-1", "km-1", type, ksm);
			byte[] data = "secret data".getBytes(StandardCharsets.UTF_8);

			AsymmetricSypterObject encrypted = keys.encrypt(DOMAIN, new KeyMaterialId("km-1"), data);

			assertThat(CrypterFactory.getCrypter(type, ksm, ALIAS).decrypt(encrypted)).isEqualTo(data);
		}
	}

	@Test
	void invalidKeyMaterialResponsesAreRejected() {
		server.respond("/v1/example.com/keys/km-1", 200, "{\"keyId\":\"km-1\",\"keyType\":\"EC_384\"}");

		assertThatThrownBy(() -> keys.verify(DOMAIN, new KeyMaterialId("km-1"), "ZA==", "c2ln"))
			.isInstanceOf(SyptException.class)
			.hasMessageContaining("verificationCertificate");
	}

	@Test
	void unknownKeyTypeIsRejected() {
		server.respond("/v1/example.com/keys/km-1", 200,
			"{\"keyId\":\"km-1\",\"keyType\":\"DSA\",\"verificationCertificate\":\"x\",\"encryptionCertificate\":\"x\"}");

		assertThatThrownBy(() -> keys.verify(DOMAIN, new KeyMaterialId("km-1"), "ZA==", "c2ln"))
			.isInstanceOf(SyptException.class)
			.hasMessageContaining("DSA")
			.extracting(e -> ((SyptException) e).getStatusCode())
			.isEqualTo(502);
	}

	private void serveKeyMaterial(String requestedId, String returnedId, KSMType type, KSM ksm) throws Exception {
		Base64.Encoder base64 = Base64.getEncoder();
		server.respond("/v1/example.com/keys/" + requestedId, 200, "{"
			+ "\"keyId\":\"" + returnedId + "\","
			+ "\"keyType\":\"" + type.name() + "\","
			+ "\"verificationCertificate\":\"" + base64.encodeToString(ksm.getVerificationCertificate(ALIAS).getEncoded()) + "\","
			+ "\"signingAlgorithm\":\"" + type.signatureSpec().keyPairGenerator() + "\","
			+ "\"signingAlgorithmHash\":\"" + type.signatureSpec().contentSigner() + "\","
			+ "\"encryptionCertificate\":\"" + base64.encodeToString(ksm.getEncryptionCertificate(ALIAS).getEncoded()) + "\","
			+ "\"decryptionAlgorithm\":\"" + type.encryptionSpec().keyPairGenerator() + "\","
			+ "\"decryptionAlgorithmHash\":null,"
			+ "\"status\":\"ACTIVE\","
			+ "\"createdAt\":\"2026-10-16T08:00:00Z\""
			+ "}");
	}
}
