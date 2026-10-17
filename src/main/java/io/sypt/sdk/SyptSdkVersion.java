package io.sypt.sdk;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Version of the SDK, read from {@code META-INF/io.sypt/sypt-sdk.properties}
 * (declared in the native-image metadata of the jar).
 */
public final class SyptSdkVersion {
	
	public static final String UNKNOWN_VERSION = "unknown";

	private static final String RESOURCE = "/META-INF/io.sypt/sypt-sdk.properties";

	private SyptSdkVersion() {
	}

	public static String get() {
		Properties properties = new Properties();

		try (InputStream input = SyptSdkVersion.class.getResourceAsStream(RESOURCE)) {
			if (input == null) {
				return UNKNOWN_VERSION;
			}

			properties.load(input);
		} catch (IOException _) {
			return UNKNOWN_VERSION;
		}

		return properties.getProperty("version", UNKNOWN_VERSION);
	}
}
