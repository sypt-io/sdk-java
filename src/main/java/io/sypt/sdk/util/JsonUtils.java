package io.sypt.sdk.util;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import io.sypt.sdk.exception.SyptException;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.json.JsonFactory;

/**
 * Flat JSON objects of strings, written and read with the Jackson streaming API only
 * (no data binding and no reflection, so that it works in a GraalVM native image).
 */
public final class JsonUtils {

	private static final JsonFactory FACTORY = new JsonFactory();
	
	private JsonUtils() {}

	/**
	 * Write a flat JSON object. Values are escaped by Jackson, {@code null} values are written as {@code null}.
	 */
	public static byte[] toJsonBytes(Map<String, String> map) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		try (JsonGenerator generator = FACTORY.createGenerator(ObjectWriteContext.empty(), out)) {
			generator.writeStartObject();

			if (map != null) {
				for (Map.Entry<String, String> entry : map.entrySet()) {
					generator.writeName(entry.getKey());

					if (entry.getValue() == null) {
						generator.writeNull();
					} else {
						generator.writeString(entry.getValue());
					}
				}
			}

			generator.writeEndObject();
		}

		return out.toByteArray();
	}

	/**
	 * Read the given string fields of a JSON object. Unknown fields are skipped, missing fields are absent
	 * from the result and {@code null} values are kept as {@code null}.
	 *
	 * @throws SyptException (400) if the input is not a JSON object, is truncated, or if a known field is not a string
	 */
	public static Map<String, String> readStringFields(byte[] json, Set<String> fields) throws SyptException {
		Map<String, String> values = new HashMap<>();

		if (json == null || json.length == 0) {
			throw new SyptException(400, "JSON content is empty");
		}

		try (JsonParser parser = FACTORY.createParser(ObjectReadContext.empty(), json)) {
			if (parser.nextToken() != JsonToken.START_OBJECT) {
				throw new SyptException(400, "JSON content must be an object");
			}

			JsonToken token;
			while ((token = parser.nextToken()) != JsonToken.END_OBJECT) {
				if (token == null) {
					throw new SyptException(400, "JSON content is truncated");
				}

				String name = parser.currentName();
				JsonToken value = parser.nextToken();

				if (!fields.contains(name)) {
					parser.skipChildren();
				} else if (value == JsonToken.VALUE_STRING) {
					values.put(name, parser.getString());
				} else if (value == JsonToken.VALUE_NULL) {
					values.put(name, null);
				} else {
					throw new SyptException(400, "JSON field '" + name + "' must be a string");
				}
			}
		} catch (JacksonException e) {
			throw new SyptException(400, "Invalid JSON content: " + e.getOriginalMessage(), e);
		}

		return values;
	}

	/**
	 * @return the value of a field read by {@link #readStringFields(byte[], Set)}
	 * @throws SyptException (400) if the field is missing or {@code null}
	 */
	public static String requireField(Map<String, String> values, String field) throws SyptException {
		String value = values.get(field);

		if (value == null) {
			throw new SyptException(400, "JSON field '" + field + "' is missing");
		}

		return value;
	}
}
