package io.sypt.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.sypt.sdk.StubServer.Request;
import io.sypt.sdk.credentials.SyptSignatureParameters;
import io.sypt.sdk.entity.Domain;
import io.sypt.sdk.entity.KeyMaterialId;
import io.sypt.sdk.exception.SyptException;
import io.sypt.sdk.request.SyptRequest;
import io.sypt.sdk.signature.HttpSignatureAlgorithm;

class SyptClientTest {

	private static final Domain DOMAIN = new Domain("example.com");

	private StubServer server;
	private SyptClient client;
	private SyptSignatureParameters parameters;
	private PublicKey publicKey;

	@BeforeEach
	void setUp() throws Exception {
		server = new StubServer();
		client = SyptClient.newBuilder()
			.baseUri(server.baseUri())
			.userAgent("SyptTest", "1.2.3")
			.clock(Clock.fixed(Instant.parse("2026-10-16T08:00:00Z"), ZoneOffset.UTC))
			.nonceGenerator(() -> "fixed-nonce")
			.build();
		parameters = TestKeys.parameters(HttpSignatureAlgorithm.ED25519, "sypt_kc_test",
			TestKeys.privateKey("vectors/keys/ed25519.pem", HttpSignatureAlgorithm.ED25519));
		publicKey = TestKeys.publicKey("vectors/keys/ed25519.pub.pem", HttpSignatureAlgorithm.ED25519);
	}

	@AfterEach
	void tearDown() {
		server.close();
	}

	@Test
	void signSendsASignedRequest() throws Exception {
		server.respond("/v1/example.com/sign", 200, "{\"signature\":\"abc\"}");

		var response = client.sign(DOMAIN, SyptRequest.sign("sypt_km_1", "ZGlnZXN0", "ctx"), parameters);

		assertThat(response.body()).isEqualTo("{\"signature\":\"abc\"}");

		Request request = server.lastRequest();
		assertThat(request.method()).isEqualTo("POST");
		assertThat(request.path()).isEqualTo("/v1/example.com/sign");
		assertThat(request.bodyAsString()).isEqualTo("{\"keyId\":\"sypt_km_1\",\"digest\":\"ZGlnZXN0\",\"context\":\"ctx\"}");
		assertThat(request.header("User-Agent")).isEqualTo("SyptTest/1.2.3 (" + SyptClient.platform() + ")");
		assertThat(request.header("Content-Type")).isEqualTo("application/json");
		assertThat(request.header("Want-Content-Digest")).isEqualTo("sha-256=10");
		assertThat(request.header("Date")).isEqualTo("Fri, 16 Oct 2026 08:00:00 GMT");
		assertThat(request.header("Content-Digest")).isEqualTo(
			"sha-256=:" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(request.body())) + ":");
		assertThat(request.header("Signature-Input")).isEqualTo(
			"sig1=(\"@method\" \"@path\" \"date\" \"content-digest\");alg=\"ed25519\";created=1792137600;nonce=\"fixed-nonce\";keyid=\"sypt_kc_test\"");

		assertThat(verifyAsServer(request)).isTrue();
	}

	@Test
	void eachOperationUsesItsPath() throws Exception {
		server.respond("/v1/example.com/decrypt", 200, "{}").respond("/v1/example.com/agents", 200, "{}");

		client.decrypt(DOMAIN, SyptRequest.decrypt("k", "d", "c"), parameters);
		assertThat(server.lastRequest().path()).isEqualTo("/v1/example.com/decrypt");

		client.createAgent(DOMAIN, SyptRequest.agent("bot", "c"), parameters);
		assertThat(server.lastRequest().path()).isEqualTo("/v1/example.com/agents");
		assertThat(server.lastRequest().bodyAsString()).isEqualTo("{\"name\":\"bot\",\"context\":\"c\"}");
	}

	@Test
	void getKeyIsNotSigned() throws Exception {
		server.respond("/v1/example.com/keys/sypt_km_1", 200, "{\"keyId\":\"sypt_km_1\"}");

		var response = client.getKey(DOMAIN, new KeyMaterialId("sypt_km_1"));

		assertThat(response.body()).isEqualTo("{\"keyId\":\"sypt_km_1\"}");
		assertThat(server.lastRequest().method()).isEqualTo("GET");
		assertThat(server.lastRequest().header("Signature")).isNull();
		assertThat(server.lastRequest().header("User-Agent")).startsWith("SyptTest/1.2.3 (");
	}

	@Test
	void errorStatusAndBodyAreReported() {
		server.respond("/v1/example.com/sign", 403, "{\"error\":\"forbidden\"}");

		assertThatThrownBy(() -> client.sign(DOMAIN, SyptRequest.sign("k", "d", "c"), parameters))
			.isInstanceOf(SyptException.class)
			.hasMessage("{\"error\":\"forbidden\"}")
			.extracting(e -> ((SyptException) e).getStatusCode())
			.isEqualTo(403);
	}

	@Test
	void domainWithSlashesIsRejected() {
		assertThatThrownBy(() -> client.sign(new Domain("/example.com"), SyptRequest.sign("k", "d", "c"), parameters))
			.isInstanceOf(SyptException.class)
			.extracting(e -> ((SyptException) e).getStatusCode())
			.isEqualTo(400);
		assertThat(server.requests()).isEmpty();
	}

	/**
	 * Regression: a client built without operation used to fail with a NullPointerException.
	 */
	@Test
	void defaultClientTargetsTheProductionApi() {
		SyptClient defaultClient = SyptClient.newBuilder().build();

		assertThat(defaultClient).isNotNull();
		assertThat(SyptClient.API_URL).isEqualTo("https://api.sypt.io/v1/");
	}

	/**
	 * Rebuild the signature base from the received request only, as the sypt.io server does.
	 */
	private boolean verifyAsServer(Request request) throws Exception {
		String signatureParams = request.header("Signature-Input").substring("sig1=".length());
		String base = "\"@method\": " + request.method() + "\n"
			+ "\"@path\": " + request.path() + "\n"
			+ "\"date\": " + request.header("Date") + "\n"
			+ "\"content-digest\": " + request.header("Content-Digest") + "\n"
			+ "\"@signature-params\": " + signatureParams;
		String signature = request.header("Signature");
		byte[] value = Base64.getDecoder().decode(signature.substring("sig1=:".length(), signature.length() - 1));

		return TestKeys.verify(HttpSignatureAlgorithm.ED25519, publicKey, base.getBytes(StandardCharsets.US_ASCII), value);
	}
}
