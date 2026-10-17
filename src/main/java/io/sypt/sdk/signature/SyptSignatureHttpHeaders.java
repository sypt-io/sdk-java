package io.sypt.sdk.signature;

import java.util.LinkedHashMap;
import java.util.Map;

public record SyptSignatureHttpHeaders(
    String date,
    String contentDigest,
    String contentType,
    String wantContentDigest,
    String signatureInput,
    String signature
) {
    public Map<String, String> toHeaderMap() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Date", date);
        headers.put("Content-Digest", contentDigest);
        headers.put("Content-Type", contentType);
        headers.put("Want-Content-Digest", wantContentDigest);
        headers.put("Signature-Input", signatureInput);
        headers.put("Signature", signature);
        return headers;
    }
}
