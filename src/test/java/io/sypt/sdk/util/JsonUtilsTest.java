package io.sypt.sdk.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.sypt.sdk.exception.SyptException;

class JsonUtilsTest {

	private static final Set<String> FIELDS = Set.of("keyId", "digest", "context");

	@Test
	void writesOrdinaryValuesLikeBefore() {
		Map<String, String> map = new LinkedHashMap<>();
		map.put("keyId", "sypt_km_1");
		map.put("digest", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
		map.put("context", "a/b \"c\" \\ é\n\t");

		assertThat(new String(JsonUtils.toJsonBytes(map), StandardCharsets.UTF_8))
			.isEqualTo("{\"keyId\":\"sypt_km_1\",\"digest\":\"LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=\",\"context\":\"a/b \\\"c\\\" \\\\ é\\n\\t\"}");
	}

	/**
	 * Regression: control characters other than \b \f \n \r \t were written as is, producing invalid JSON.
	 */
	@Test
	void escapesAllControlCharacters() throws SyptException {
		Map<String, String> map = new LinkedHashMap<>();
		map.put("context", "a\u0001b\u001fc");

		byte[] json = JsonUtils.toJsonBytes(map);

		assertThat(new String(json, StandardCharsets.UTF_8)).isEqualTo("{\"context\":\"a\\u0001b\\u001Fc\"}");
		assertThat(JsonUtils.readStringFields(json, Set.of("context"))).containsEntry("context", "a\u0001b\u001fc");
	}

	@Test
	void writesNullValuesAndEmptyMaps() {
		Map<String, String> map = new LinkedHashMap<>();
		map.put("context", null);

		assertThat(new String(JsonUtils.toJsonBytes(map), StandardCharsets.UTF_8)).isEqualTo("{\"context\":null}");
		assertThat(new String(JsonUtils.toJsonBytes(Map.of()), StandardCharsets.UTF_8)).isEqualTo("{}");
		assertThat(new String(JsonUtils.toJsonBytes(null), StandardCharsets.UTF_8)).isEqualTo("{}");
	}

	@Test
	void readsKnownFieldsAndSkipsUnknownOnes() throws SyptException {
		byte[] json = "{\"other\":{\"nested\":[1,{\"keyId\":\"no\"}]},\"keyId\":\"k\",\"digest\":\"d\",\"context\":null,\"n\":3}"
			.getBytes(StandardCharsets.UTF_8);

		Map<String, String> values = JsonUtils.readStringFields(json, FIELDS);

		assertThat(values).containsEntry("keyId", "k").containsEntry("digest", "d").containsEntry("context", null).hasSize(3);
	}

	/**
	 * Regression: the parsing loops stopped only on END_OBJECT and never ended on such inputs.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "", " ", "[]", "[{\"keyId\":\"k\"}]", "\"text\"", "{\"keyId\":\"k\"", "{\"keyId\":", "not json" })
	void rejectsInvalidInputsWithoutLooping(String input) {
		assertTimeoutPreemptively(Duration.ofSeconds(5), () ->
			assertThatThrownBy(() -> JsonUtils.readStringFields(input.getBytes(StandardCharsets.UTF_8), FIELDS))
				.isInstanceOf(SyptException.class)
				.extracting(e -> ((SyptException) e).getStatusCode())
				.isEqualTo(400)
		);
	}

	@Test
	void rejectsNonStringKnownFields() {
		assertThatThrownBy(() -> JsonUtils.readStringFields("{\"keyId\":42}".getBytes(StandardCharsets.UTF_8), FIELDS))
			.isInstanceOf(SyptException.class)
			.hasMessageContaining("keyId");
	}

	/**
	 * Regression: a missing field used to end in a NullPointerException from Map.of.
	 */
	@Test
	void requireFieldReportsMissingFields() throws SyptException {
		Map<String, String> values = JsonUtils.readStringFields("{\"keyId\":\"k\",\"context\":null}".getBytes(StandardCharsets.UTF_8), FIELDS);

		assertThat(JsonUtils.requireField(values, "keyId")).isEqualTo("k");
		assertThatThrownBy(() -> JsonUtils.requireField(values, "digest"))
			.isInstanceOf(SyptException.class)
			.hasMessageContaining("digest");
		assertThatThrownBy(() -> JsonUtils.requireField(values, "context"))
			.isInstanceOf(SyptException.class)
			.hasMessageContaining("context");
	}
}
