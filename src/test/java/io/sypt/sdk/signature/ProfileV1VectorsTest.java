package io.sypt.sdk.signature;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.sypt.sdk.TestKeys;
import io.sypt.sdk.signature.HttpSignatureBuilder.PreparedSignature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Shared test vectors of the "sypt profile v1" ({@code src/test/resources/vectors/profile-v1}).
 * The same files must be passed by the SDKs written in other languages.
 *
 * <p>Regenerate them with {@code mvn test -Dtest=ProfileV1VectorsTest -Dsypt.vectors.generate=true}.</p>
 */
class ProfileV1VectorsTest {

	private static final ObjectMapper MAPPER = JsonMapper.builder().build();
	private static final Path VECTORS = Path.of("src/test/resources/vectors/profile-v1");
	private static final Instant CREATED = Instant.parse("2026-10-16T08:00:00Z");
	private static final String DIGEST = "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";

	private record Input(String name, String description, HttpSignatureAlgorithm alg, String key, String method, String url, String body, String nonce, Instant created) {

		Input(String name, String description, HttpSignatureAlgorithm alg, String key, String method, String url, String body, String nonce) {
			this(name, description, alg, key, method, url, body, nonce, CREATED);
		}
	}

	private static final List<Input> INPUTS = List.of(
		new Input("ed25519-sign", "Ed25519 (RFC 9421 B.1.4 test key), POST /sign", HttpSignatureAlgorithm.ED25519, "ed25519",
			"POST", "https://api.sypt.io/v1/example.com/sign",
			"{\"keyId\":\"sypt_km_test\",\"digest\":\"" + DIGEST + "\",\"context\":\"invoice-42\"}",
			"7f3c2a1e-0b4d-4e6f-9a8b-1c2d3e4f5a6b"),
		new Input("ecdsa-p256-sign", "ECDSA P-256 / SHA-256, POST /sign", HttpSignatureAlgorithm.ECDSA_P256_SHA256, "ecdsa-p256",
			"POST", "https://api.sypt.io/v1/example.com/sign",
			"{\"keyId\":\"sypt_km_test\",\"digest\":\"" + DIGEST + "\",\"context\":\"invoice-42\"}",
			"0e1d2c3b-4a59-4687-b6c5-d4e3f2a1b0c9"),
		new Input("ecdsa-p384-decrypt", "ECDSA P-384 / SHA-384, POST /decrypt", HttpSignatureAlgorithm.ECDSA_P384_SHA384, "ecdsa-p384",
			"POST", "https://api.sypt.io/v1/sub.example.com/decrypt",
			"{\"keyId\":\"sypt_km_test\",\"digest\":\"" + DIGEST + "\",\"context\":\"\"}",
			"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"),
		new Input("rsa-pss-sha512-agents", "RSA-PSS / SHA-512, POST /agents", HttpSignatureAlgorithm.RSA_PSS_SHA512, "rsa-2048",
			"POST", "https://api.sypt.io/v1/example.com/agents",
			"{\"name\":\"billing-bot\",\"context\":\"ligne 1\\nligne 2 \\\"quote\\\" é\"}",
			"5d4c3b2a-1908-4f7e-8d6c-5b4a39281706"),
		new Input("rsa-v1_5-sha256-sign", "RSA PKCS#1 v1.5 / SHA-256, POST /sign", HttpSignatureAlgorithm.RSA_V1_5_SHA256, "rsa-2048",
			"POST", "https://api.sypt.io/v1/example.com/sign",
			"{\"keyId\":\"sypt_km_test\",\"digest\":\"" + DIGEST + "\",\"context\":\"invoice-42\"}",
			"c0ffee00-1234-4abc-8def-0123456789ab"),
		// The Date header has no leading zero for days 1 to 9 (RFC_1123_DATE_TIME): "Tue, 6 Oct 2026"
		new Input("ed25519-sign-single-digit-day", "Ed25519, Date header of a day below 10 (no leading zero)", HttpSignatureAlgorithm.ED25519, "ed25519",
			"POST", "https://api.sypt.io/v1/example.com/sign",
			"{\"keyId\":\"sypt_km_test\",\"digest\":\"" + DIGEST + "\",\"context\":\"invoice-6\"}",
			"0a1b2c3d-4e5f-4061-8273-94a5b6c7d8e9", Instant.parse("2026-10-06T07:05:09Z"))
	);

	static Stream<Path> vectors() throws IOException {
		try (Stream<Path> files = Files.list(VECTORS)) {
			return files.filter(path -> path.toString().endsWith(".json")).sorted().toList().stream();
		}
	}

	@Test
	void allVectorsArePresent() throws IOException {
		assertThat(vectors().map(path -> path.getFileName().toString()))
			.containsExactlyInAnyOrderElementsOf(INPUTS.stream().map(input -> input.name() + ".json").toList());
	}

	@ParameterizedTest
	@MethodSource("vectors")
	void vector(Path file) throws Exception {
		JsonNode vector = MAPPER.readTree(Files.readString(file, StandardCharsets.UTF_8));
		JsonNode expected = vector.get("expected");
		HttpSignatureAlgorithm algorithm = HttpSignatureAlgorithm.fromRfcName(vector.get("alg").asString());
		PrivateKey privateKey = TestKeys.privateKey("vectors/" + vector.get("privateKey").asString(), algorithm);
		PublicKey publicKey = TestKeys.publicKey("vectors/" + vector.get("publicKey").asString(), algorithm);
		byte[] body = vector.get("body").asString().getBytes(StandardCharsets.UTF_8);

		HttpSignatureBuilder builder = builder(vector, algorithm, privateKey, body);
		PreparedSignature prepared = builder.signatureBase();
		String signatureBase = prepared.signatureBase().serialize();

		// 1. Signature base: expected value, and value rebuilt by hand from the inputs (independent of authlete)
		assertThat(signatureBase)
			.as("expected signature base").isEqualTo(expected.get("signatureBase").asString())
			.as("signature base rebuilt by hand").isEqualTo(manualSignatureBase(vector, body));

		// 2. Headers, except the signature itself
		SyptSignatureHttpHeaders headers = builder.build();
		JsonNode expectedHeaders = expected.get("headers");
		headers.toHeaderMap().forEach((name, value) -> {
			if (!"Signature".equals(name)) {
				assertThat(value).as(name).isEqualTo(expectedHeaders.get(name).asString());
			}
		});

		// 3. Signatures: the expected one and a fresh one both verify with the public key
		byte[] base = signatureBase.getBytes(StandardCharsets.US_ASCII);
		String expectedSignature = expectedHeaders.get("Signature").asString();
		assertThat(TestKeys.verify(algorithm, publicKey, base, signatureBytes(expectedSignature))).isTrue();
		assertThat(TestKeys.verify(algorithm, publicKey, base, signatureBytes(headers.signature()))).isTrue();

		if (expected.get("signatureIsDeterministic").asBoolean()) {
			assertThat(headers.signature()).isEqualTo(expectedSignature);
		}
	}

	@Test
	@EnabledIfSystemProperty(named = "sypt.vectors.generate", matches = "true")
	void generate() throws Exception {
		Files.createDirectories(VECTORS);

		for (Input input : INPUTS) {
			String keyFile = "keys/" + input.key() + ".pem";
			String publicKeyFile = "keys/" + input.key() + ".pub.pem";
			PrivateKey privateKey = TestKeys.privateKey("vectors/" + keyFile, input.alg());
			byte[] body = input.body().getBytes(StandardCharsets.UTF_8);

			ObjectNode vector = MAPPER.createObjectNode();
			vector.put("profile", "sypt-v1");
			vector.put("description", input.description());
			vector.put("alg", input.alg().getRfcName());
			vector.put("keyId", "sypt_kc_test_" + input.key());
			vector.put("privateKey", keyFile);
			vector.put("publicKey", publicKeyFile);
			vector.put("method", input.method());
			vector.put("url", input.url());
			vector.put("body", input.body());
			vector.put("created", input.created().getEpochSecond());
			vector.put("nonce", input.nonce());

			HttpSignatureBuilder builder = builder(vector, input.alg(), privateKey, body);
			SyptSignatureHttpHeaders headers = builder.build();

			ObjectNode expected = vector.putObject("expected");
			expected.put("signatureBase", builder.signatureBase().signatureBase().serialize());
			ObjectNode expectedHeaders = expected.putObject("headers");
			headers.toHeaderMap().forEach(expectedHeaders::put);
			expected.put("signatureIsDeterministic",
				input.alg() == HttpSignatureAlgorithm.ED25519 || input.alg() == HttpSignatureAlgorithm.RSA_V1_5_SHA256);

			Path written = Files.writeString(
				VECTORS.resolve(input.name() + ".json"),
				MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(vector) + "\n",
				StandardCharsets.UTF_8
			);

			// The generated vector must pass the same checks as the committed ones
			vector(written);
		}

		assertThat(vectors().map(path -> path.getFileName().toString()))
			.containsExactlyInAnyOrderElementsOf(INPUTS.stream().map(input -> input.name() + ".json").toList());
	}

	private static HttpSignatureBuilder builder(JsonNode vector, HttpSignatureAlgorithm algorithm, PrivateKey privateKey, byte[] body) {
		return HttpSignatureBuilder.newBuilder()
			.method(vector.get("method").asString())
			.url(vector.get("url").asString())
			.payload(body)
			.parameters(TestKeys.parameters(algorithm, vector.get("keyId").asString(), privateKey))
			.clock(Clock.fixed(Instant.ofEpochSecond(vector.get("created").asLong()), ZoneOffset.UTC))
			.nonceGenerator(() -> vector.get("nonce").asString());
	}

	/**
	 * Signature base of the "sypt profile v1", written by hand from RFC 9421 section 2.5.
	 */
	private static String manualSignatureBase(JsonNode vector, byte[] body) throws Exception {
		String digest = "sha-256=:" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(body)) + ":";
		String date = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME
			.format(Instant.ofEpochSecond(vector.get("created").asLong()).atZone(ZoneOffset.UTC));
		String params = "(\"@method\" \"@path\" \"date\" \"content-digest\")"
			+ ";alg=\"" + vector.get("alg").asString() + "\""
			+ ";created=" + vector.get("created").asLong()
			+ ";nonce=\"" + vector.get("nonce").asString() + "\""
			+ ";keyid=\"" + vector.get("keyId").asString() + "\"";

		return "\"@method\": " + vector.get("method").asString() + "\n"
			+ "\"@path\": " + path(vector.get("url").asString()) + "\n"
			+ "\"date\": " + date + "\n"
			+ "\"content-digest\": " + digest + "\n"
			+ "\"@signature-params\": " + params;
	}

	private static String path(String url) throws URISyntaxException {
		return new URI(url).getRawPath();
	}

	private static byte[] signatureBytes(String header) {
		// sig1=:<base64>:
		String value = header.substring(header.indexOf('=') + 1);
		return Base64.getDecoder().decode(value.substring(1, value.length() - 1));
	}
}
