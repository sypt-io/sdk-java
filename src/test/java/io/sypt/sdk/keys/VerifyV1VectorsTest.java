package io.sypt.sdk.keys;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.factory.KSMType;
import io.sypt.core.signer.factory.SignerFactory;
import io.sypt.sdk.StubServer;
import io.sypt.sdk.SyptClient;
import io.sypt.sdk.TestKeys;
import io.sypt.sdk.entity.Domain;
import io.sypt.sdk.entity.KeyMaterialId;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Shared vectors for the local verification of the signatures produced by sypt.io
 * ({@code src/test/resources/vectors/verify-v1}): certificate of a key material, digest and
 * signature computed by sypt-core. The same files must be passed by the SDKs written in other languages.
 *
 * <p>Regenerate them with {@code mvn test -Dtest=VerifyV1VectorsTest -Dsypt.vectors.generate=true}.</p>
 */
class VerifyV1VectorsTest {

	private static final ObjectMapper MAPPER = JsonMapper.builder().build();
	private static final Path VECTORS = Path.of("src/test/resources/vectors/verify-v1");
	private static final String ALIAS = "sypt-crypto-data";

	private record Input(String name, String keystore, KSMType type) {
	}

	private static final List<Input> INPUTS = List.of(
		new Input("ec-384", "sypt-crypto-data-ec.p12", KSMType.EC_384),
		new Input("rsa-4096", "sypt-crypto-data-rsa.p12", KSMType.RSA_4096),
		new Input("pqc-l5", "sypt-crypto-data-pqc.p12", KSMType.PQC_L5)
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

		try (StubServer server = new StubServer()) {
			server.respond("/v1/example.com/keys/km-1", 200, "{"
				+ "\"keyId\":\"km-1\","
				+ "\"keyType\":\"" + vector.get("keyType").asString() + "\","
				+ "\"verificationCertificate\":\"" + vector.get("verificationCertificate").asString() + "\","
				+ "\"encryptionCertificate\":\"" + vector.get("encryptionCertificate").asString() + "\""
				+ "}");
			SyptKeys keys = new SyptKeys(SyptClient.newBuilder().baseUri(server.baseUri()).build());

			for (JsonNode test : vector.get("cases")) {
				boolean verified = keys.verify(new Domain("example.com"), new KeyMaterialId("km-1"),
					test.get("digest").asString(), test.get("signature").asString());

				assertThat(verified).as(test.get("description").asString()).isEqualTo(test.get("valid").asBoolean());
			}
		}
	}

	@Test
	@EnabledIfSystemProperty(named = "sypt.vectors.generate", matches = "true")
	void generate() throws Exception {
		Files.createDirectories(VECTORS);
		Base64.Encoder base64 = Base64.getEncoder();
		byte[] digest = MessageDigest.getInstance("SHA-256").digest("hello".getBytes(StandardCharsets.UTF_8));
		byte[] otherDigest = MessageDigest.getInstance("SHA-256").digest("other".getBytes(StandardCharsets.UTF_8));

		for (Input input : INPUTS) {
			try (KSM ksm = new FileKSM("classpath:keystore/" + input.keystore(), TestKeys.KEYSTORE_PASSWORD.toCharArray())) {
				String signature = SignerFactory.getSigner(input.type(), ksm, ALIAS).sign(digest);

				ObjectNode vector = MAPPER.createObjectNode();
				vector.put("profile", "sypt-v1");
				vector.put("description", "Signature of a digest by a " + input.type() + " key material ("
					+ input.type().signatureSpec().contentSigner() + "), as returned by POST /{domain}/sign");
				vector.put("keyType", input.type().name());
				vector.put("signatureAlgorithm", input.type().signatureSpec().contentSigner());
				vector.put("verificationCertificate", base64.encodeToString(ksm.getVerificationCertificate(ALIAS).getEncoded()));
				vector.put("encryptionCertificate", base64.encodeToString(ksm.getEncryptionCertificate(ALIAS).getEncoded()));

				ArrayNode cases = vector.putArray("cases");
				cases.addObject()
					.put("description", "signature of the digest")
					.put("digest", base64.encodeToString(digest))
					.put("signature", signature)
					.put("valid", true);
				cases.addObject()
					.put("description", "same signature, other digest")
					.put("digest", base64.encodeToString(otherDigest))
					.put("signature", signature)
					.put("valid", false);

				Path written = Files.writeString(
					VECTORS.resolve(input.name() + ".json"),
					MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(vector) + "\n",
					StandardCharsets.UTF_8
				);

				// The generated vector must pass the same checks as the committed ones
				vector(written);
			}
		}

		assertThat(vectors().map(path -> path.getFileName().toString()))
			.containsExactlyInAnyOrderElementsOf(INPUTS.stream().map(input -> input.name() + ".json").toList());
	}
}
