package io.sypt.sdk;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import io.sypt.sdk.credentials.SyptSignatureParameters;
import io.sypt.sdk.signature.HttpSignatureAlgorithm;

/**
 * Test keys of {@code src/test/resources/vectors/keys} (PKCS#8 / SPKI PEM).
 */
public final class TestKeys {

	public static final String KEYSTORE_PASSWORD = "sypt-crypto-data-pass";
	public static final String CALLER_KEYSTORE_PASSWORD = "caller-test-pass";

	private TestKeys() {
	}

	public static String resource(String path) {
		try (InputStream is = TestKeys.class.getResourceAsStream("/" + path)) {
			if (is == null) {
				throw new IllegalArgumentException("Missing test resource " + path);
			}

			return new String(is.readAllBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	public static String keyAlgorithm(HttpSignatureAlgorithm algorithm) {
		return switch (algorithm) {
			case ECDSA_P256_SHA256, ECDSA_P384_SHA384 -> "EC";
			case RSA_PSS_SHA512, RSA_V1_5_SHA256 -> "RSA";
			case ED25519 -> "Ed25519";
		};
	}

	public static PrivateKey privateKey(String pemPath, HttpSignatureAlgorithm algorithm) throws GeneralSecurityException {
		return KeyFactory.getInstance(keyAlgorithm(algorithm)).generatePrivate(new PKCS8EncodedKeySpec(der(resource(pemPath))));
	}

	public static PublicKey publicKey(String pemPath, HttpSignatureAlgorithm algorithm) throws GeneralSecurityException {
		return KeyFactory.getInstance(keyAlgorithm(algorithm)).generatePublic(new X509EncodedKeySpec(der(resource(pemPath))));
	}

	/**
	 * Verify a signature with the JCA only, independently of the authlete library.
	 */
	public static boolean verify(HttpSignatureAlgorithm algorithm, PublicKey publicKey, byte[] data, byte[] signature) throws GeneralSecurityException {
		Signature verifier = Signature.getInstance(algorithm.getJcaName());
		if (algorithm.getSpec() != null) {
			verifier.setParameter(algorithm.getSpec());
		}

		verifier.initVerify(publicKey);
		verifier.update(data);
		return verifier.verify(signature);
	}

	public static SyptSignatureParameters parameters(HttpSignatureAlgorithm algorithm, String keyId, PrivateKey privateKey) {
		return new SyptSignatureParameters() {

			@Override
			public String alg() {
				return algorithm.getRfcName();
			}

			@Override
			public String keyId() {
				return keyId;
			}

			@Override
			public PrivateKey privateKey() {
				return privateKey;
			}
		};
	}

	private static byte[] der(String pem) {
		return Base64.getDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", ""));
	}
}
