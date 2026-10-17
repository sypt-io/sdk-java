package io.sypt.sdk.signature;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.ComponentValueProvider;
import com.authlete.hms.SignatureBase;
import com.authlete.hms.SignatureBaseBuilder;
import com.authlete.hms.SignatureMetadata;

import io.sypt.sdk.credentials.SyptSignatureParameters;
import io.sypt.sdk.exception.SyptException;
import io.sypt.sdk.util.DigestUtils;

/**
 * Build the RFC 9421 headers of a request according to the "sypt profile v1":
 * covered components {@code @method @path date content-digest}, parameters
 * {@code alg created nonce keyid}, label {@code sig1}.
 */
public final class HttpSignatureBuilder {

	public static final String LABEL = "sig1";

	/** Components covered by the signature ("sypt profile v1"). */
	public static final List<String> COVERED_COMPONENTS = List.of("@method", "@path", "date", "content-digest");

	private String method = "POST";
	private String url;
	private byte[] payload;
	private SyptSignatureParameters parameters;
	private Clock clock = Clock.systemUTC();
	private Supplier<String> nonceGenerator = () -> UUID.randomUUID().toString();

	public static HttpSignatureBuilder newBuilder() {
		return new HttpSignatureBuilder();
	}

	public HttpSignatureBuilder method(String method) {
		this.method = Objects.requireNonNull(method, "method cannot be null");
		return this;
	}

	public HttpSignatureBuilder url(String url) {
		this.url = Objects.requireNonNull(url, "url cannot be null");
		return this;
	}

	public HttpSignatureBuilder payload(byte[] payload) {
		this.payload = Objects.requireNonNull(payload, "payload cannot be null");
		return this;
	}

	public HttpSignatureBuilder parameters(SyptSignatureParameters parameters) {
		this.parameters = Objects.requireNonNull(parameters, "parameters cannot be null");
		return this;
	}

	public HttpSignatureBuilder clock(Clock clock) {
		this.clock = Objects.requireNonNull(clock, "clock cannot be null");
		return this;
	}

	public HttpSignatureBuilder nonceGenerator(Supplier<String> nonceGenerator) {
		this.nonceGenerator = Objects.requireNonNull(nonceGenerator, "nonceGenerator cannot be null");
		return this;
	}

	public SyptSignatureHttpHeaders build() throws SyptException {
		return sign(signatureBase());
	}

	/**
	 * Compute the signature base without signing it (used by the test vectors).
	 */
	public PreparedSignature signatureBase() throws SyptException {
		Objects.requireNonNull(url, "URL must be provided");
		Objects.requireNonNull(payload, "Payload must be provided");
		Objects.requireNonNull(parameters, "Signature parameters must be provided");

		// A single instant for both the Date header and the "created" parameter
		Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
		String formattedDate = DateTimeFormatter.RFC_1123_DATE_TIME.format(now.atZone(ZoneOffset.UTC));

		String digest = DigestUtils.computeSha256Digest(payload)
				.orElseThrow(() -> new SyptException(400, "Request payload cannot be empty"));

		Map<String, List<String>> headerCvp = new HashMap<>();
		headerCvp.put("Date", List.of(formattedDate));
		headerCvp.put("Content-Digest", List.of(digest));

		ComponentValueProvider cvp = new ComponentValueProvider();
		cvp.setMethod(method.toUpperCase(Locale.ROOT));
		cvp.setTargetUri(url);
		cvp.setHeaders(headerCvp);

		List<ComponentIdentifier> components = new ArrayList<>();
		COVERED_COMPONENTS.forEach(component -> components.add(new ComponentIdentifier(component)));
		SignatureMetadata metadata = new SignatureMetadata(components);

		metadata.getParameters()
			.setAlg(parameters.alg())
			.setCreated(now.getEpochSecond())
			.setNonce(nonceGenerator.get())
			.setKeyid(parameters.keyId());

		try {
			return new PreparedSignature(formattedDate, digest, metadata.serialize(), new SignatureBaseBuilder(cvp).build(metadata));
		} catch (java.security.SignatureException e) {
			throw new SyptException("Unable to build the HTTP signature base", e);
		}
	}

	private SyptSignatureHttpHeaders sign(PreparedSignature request) throws SyptException {
		HttpSignatureAlgorithm algorithm = HttpSignatureAlgorithm.fromRfcName(parameters.alg());

		try {
			byte[] signature = request.signatureBase().sign(HttpSigners.create(algorithm, parameters.privateKey()));

			return new SyptSignatureHttpHeaders(
				request.date(),
				request.contentDigest(),
				"application/json",
				"sha-256=10",
				LABEL + "=" + request.signatureParams(),
				LABEL + "=:" + Base64.getEncoder().encodeToString(signature) + ":"
			);
		} catch (java.security.SignatureException e) {
			throw new SyptException("Unable to sign the HTTP request", e);
		}
	}

	/**
	 * Intermediate values of a signature: headers covered by the signature, serialized
	 * {@code @signature-params} (value of {@code Signature-Input} without its label) and signature base.
	 */
	public record PreparedSignature(String date, String contentDigest, String signatureParams, SignatureBase signatureBase) {
	}
}
