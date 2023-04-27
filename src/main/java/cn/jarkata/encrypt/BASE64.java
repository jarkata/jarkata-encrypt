package cn.jarkata.encrypt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class BASE64 {

    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();

    public static String encodeBase64(byte[] data) {
        return encoder.encodeToString(data);
    }

    public static byte[] decodeBase64(String data) {
        return decoder.decode(data.getBytes(StandardCharsets.UTF_8));
    }
}