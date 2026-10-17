package io.sypt.sdk.request;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * JSON body of a request sent to sypt.io (flat object of strings).
 */
public record SyptRequest(
		
	Map<String, String> elements
		
) {

	public SyptRequest {
		// Insertion order is kept: it is the order of the JSON body
		elements = elements == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(elements));
	}

	/**
	 * Body of {@code POST /{domain}/sign}.
	 *
	 * @param keyId   Key ID of the key material on the platform
	 * @param digest  Base64 digest to sign
	 * @param context free context stored in the audit
	 */
	public static SyptRequest sign(String keyId, String digest, String context) {
		return digestRequest(keyId, digest, context);
	}

	/**
	 * Body of {@code POST /{domain}/decrypt}.
	 */
	public static SyptRequest decrypt(String keyId, String digest, String context) {
		return digestRequest(keyId, digest, context);
	}

	/**
	 * Body of {@code POST /{domain}/agents}.
	 */
	public static SyptRequest agent(String name, String context) {
		Map<String, String> elements = new LinkedHashMap<>();
		elements.put("name", Objects.requireNonNull(name, "name cannot be null"));
		elements.put("context", Objects.requireNonNull(context, "context cannot be null"));
		return new SyptRequest(elements);
	}

	private static SyptRequest digestRequest(String keyId, String digest, String context) {
		Map<String, String> elements = new LinkedHashMap<>();
		elements.put("keyId", Objects.requireNonNull(keyId, "keyId cannot be null"));
		elements.put("digest", Objects.requireNonNull(digest, "digest cannot be null"));
		elements.put("context", Objects.requireNonNull(context, "context cannot be null"));
		return new SyptRequest(elements);
	}

}
