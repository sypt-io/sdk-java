package io.sypt.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

import io.sypt.sdk.credentials.SyptSignatureParameters;
import io.sypt.sdk.entity.Domain;
import io.sypt.sdk.entity.KeyMaterialId;
import io.sypt.sdk.exception.SyptException;
import io.sypt.sdk.request.SyptRequest;
import io.sypt.sdk.signature.HttpSignatureBuilder;
import io.sypt.sdk.signature.SyptSignatureHttpHeaders;
import io.sypt.sdk.util.JsonUtils;

/**
 * Client of the sypt.io API. Every operation request is signed according to RFC 9421
 * ("sypt profile v1", see {@link HttpSignatureBuilder}).
 */
public class SyptClient {

	public static final String API_URL = "https://api.sypt.io/v1/";

	private final String baseUri;
	private final HttpClient httpClient;
	private final Duration timeout;
	private final String userAgent;
	private final Clock clock;
	private final Supplier<String> nonceGenerator;

	private SyptClient(Builder builder) {
		this.baseUri = builder.baseUri;
		this.httpClient = builder.httpClient;
		this.timeout = builder.timeout;
		this.userAgent = builder.product + "/" + builder.version + " (" + platform() + ")";
		this.clock = builder.clock;
		this.nonceGenerator = builder.nonceGenerator;
	}

	public static Builder newBuilder() {
		return new Builder();
	}

	/**
	 * {@code GET /{domain}/keys/{keyMaterialId}}: public certificates of a key material (not signed).
	 */
	public HttpResponse<String> getKey(Domain domain, KeyMaterialId keyMaterialId) throws SyptException {
		Objects.requireNonNull(keyMaterialId, "keyMaterialId cannot be null");
		validateDomain(domain);

		String url = baseUri + domain.val() + "/keys/" + keyMaterialId.val();

		HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().uri(URI.create(url)).timeout(timeout);
		requestBuilder.header("User-Agent", userAgent);
		requestBuilder.GET();

		return send(requestBuilder.build());
	}

	/**
	 * {@code POST /{domain}/sign}
	 */
	public HttpResponse<String> sign(Domain domain, SyptRequest body, SyptSignatureParameters params) throws SyptException {
		return exec(Operation.SIGN, domain, body, params);
	}

	/**
	 * {@code POST /{domain}/decrypt}
	 */
	public HttpResponse<String> decrypt(Domain domain, SyptRequest body, SyptSignatureParameters params) throws SyptException {
		return exec(Operation.DECRYPT, domain, body, params);
	}

	/**
	 * {@code POST /{domain}/agents}
	 */
	public HttpResponse<String> createAgent(Domain domain, SyptRequest body, SyptSignatureParameters params) throws SyptException {
		return exec(Operation.AGENT, domain, body, params);
	}

	/**
	 * Send a signed {@code POST} request for the given operation.
	 *
	 * @return the response, when its status is 200
	 * @throws SyptException with the HTTP status and the body of the response otherwise
	 */
	public HttpResponse<String> exec(Operation op, Domain domain, SyptRequest body, SyptSignatureParameters params) throws SyptException {
		Objects.requireNonNull(op, "operation cannot be null");
		Objects.requireNonNull(body, "body cannot be null");
		Objects.requireNonNull(params, "params cannot be null");
		validateDomain(domain);

		String url = baseUri + domain.val() + op.getOp();
		byte[] payload = JsonUtils.toJsonBytes(body.elements());

		SyptSignatureHttpHeaders signature = HttpSignatureBuilder.newBuilder()
			.method("POST")
			.url(url)
			.payload(payload)
			.parameters(params)
			.clock(clock)
			.nonceGenerator(nonceGenerator)
			.build();

		HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().uri(URI.create(url)).timeout(timeout);
		requestBuilder.header("User-Agent", userAgent);
		signature.toHeaderMap().forEach(requestBuilder::header);
		requestBuilder.POST(HttpRequest.BodyPublishers.ofByteArray(payload));

		return send(requestBuilder.build());
	}

	private HttpResponse<String> send(HttpRequest request) throws SyptException {
		try {
			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() == 200) {
				return response;
			}

			throw new SyptException(response.statusCode(), response.body());
		} catch (IOException e) {
			throw new SyptException("Unexpected error occurred during Sypt request: " + e.getMessage(), e);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new SyptException("Unexpected interruption during Sypt request", e);
		}
	}

	private static void validateDomain(Domain domain) throws SyptException {
		Objects.requireNonNull(domain, "domain cannot be null");

		if (domain.val().startsWith("/") || domain.val().endsWith("/")) {
			throw new SyptException(400, "domain must not start nor end with '/'");
		}
	}

	/**
	 * Platform part of the User-Agent, ex: "linux; x86_64".
	 */
	static String platform() {
		String os = System.getProperty("os.name", "unknown");
		if (os.regionMatches(true, 0, "windows", 0, 7)) {
			os = "windows";
		} else if (os.regionMatches(true, 0, "mac", 0, 3)) {
			os = "macos";
		} else if (os.equalsIgnoreCase("linux")) {
			os = "linux";
		}

		String arch = System.getProperty("os.arch", "unknown");
		if ("amd64".equalsIgnoreCase(arch)) {
			arch = "x86_64";
		}

		return os + "; " + arch;
	}

	public static final class Builder {

		private String baseUri = API_URL;
		private HttpClient httpClient;
		private Duration timeout = Duration.ofSeconds(10);
		private String product = "SyptSDK";
		private String version = SyptSdkVersion.get();
		private Clock clock = Clock.systemUTC();
		private Supplier<String> nonceGenerator = () -> UUID.randomUUID().toString();

		private Builder() {}

		public Builder baseUri(String baseUri) {
			this.baseUri = Objects.requireNonNull(baseUri, "baseUri cannot be null");
			if (!this.baseUri.endsWith("/")) {
				this.baseUri += "/";
			}

			return this;
		}

		public Builder httpClient(HttpClient httpClient) {
			this.httpClient = Objects.requireNonNull(httpClient, "httpClient cannot be null");
			return this;
		}

		public Builder timeout(Duration timeout) {
			this.timeout = Objects.requireNonNull(timeout, "timeout cannot be null");
			return this;
		}

		/**
		 * Product sent in the User-Agent, ex: {@code userAgent("SyptCLI", "0.1.5")}. Default: SyptSDK/{sdk version}.
		 */
		public Builder userAgent(String product, String version) {
			this.product = Objects.requireNonNull(product, "product cannot be null");
			this.version = Objects.requireNonNull(version, "version cannot be null");
			return this;
		}

		/**
		 * Clock used for the {@code Date} header and the {@code created} parameter of the signature.
		 */
		public Builder clock(Clock clock) {
			this.clock = Objects.requireNonNull(clock, "clock cannot be null");
			return this;
		}

		/**
		 * Generator of the {@code nonce} parameter of the signature. Default: random UUID.
		 */
		public Builder nonceGenerator(Supplier<String> nonceGenerator) {
			this.nonceGenerator = Objects.requireNonNull(nonceGenerator, "nonceGenerator cannot be null");
			return this;
		}

		public SyptClient build() {
			if (httpClient == null) {
				httpClient = HttpClient.newHttpClient();
			}

			return new SyptClient(this);
		}
	}

	public enum Operation {

		DECRYPT	("/decrypt"),
		SIGN	("/sign"),
		AGENT	("/agents");

		private final String op;

		private Operation(String op) {
			this.op = op;
		}

		public String getOp() {
			return op;
		}

	}
}
