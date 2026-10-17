package io.sypt.sdk;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;

/**
 * Local HTTP server standing for the sypt.io API: records the received requests and answers
 * with the response registered for their path (404 otherwise).
 */
public final class StubServer implements AutoCloseable {

	public record Request(String method, String path, Headers headers, byte[] body) {

		public String header(String name) {
			return headers.getFirst(name);
		}

		public String bodyAsString() {
			return new String(body, StandardCharsets.UTF_8);
		}
	}

	private record Response(int status, String body) {
	}

	private final HttpServer server;
	private final Map<String, Response> responses = new ConcurrentHashMap<>();
	private final List<Request> requests = new CopyOnWriteArrayList<>();

	public StubServer() {
		try {
			server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}

		server.createContext("/", exchange -> {
			String path = exchange.getRequestURI().getRawPath();
			requests.add(new Request(exchange.getRequestMethod(), path, exchange.getRequestHeaders(), exchange.getRequestBody().readAllBytes()));

			Response response = responses.getOrDefault(path, new Response(404, "not found"));
			byte[] body = response.body().getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(response.status(), body.length);

			try (OutputStream os = exchange.getResponseBody()) {
				os.write(body);
			}
		});
		server.start();
	}

	public StubServer respond(String path, int status, String body) {
		responses.put(path, new Response(status, body));
		return this;
	}

	/**
	 * @return base URI of the API, ex: http://127.0.0.1:12345/v1/
	 */
	public String baseUri() {
		return "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/";
	}

	public List<Request> requests() {
		return requests;
	}

	public Request lastRequest() {
		return requests.getLast();
	}

	@Override
	public void close() {
		server.stop(0);
	}
}
