package cn.jarkata.encrypt;

import cn.jarkata.commons.utils.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/**
 * Base64编码数据
 */
public class JaBase64 {

    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();

    public static String encodeBase64(byte[] data) {
        if (Objects.isNull(data) || data.length == 0) {
            throw new IllegalArgumentException("Data Empty");
        }
        return encoder.encodeToString(data);
    }

    public static byte[] decodeBase64(String data) {
        if (StringUtils.isBlank(data)) {
            throw new IllegalArgumentException("Data Empty");
        }
        return decoder.decode(data.getBytes(StandardCharsets.UTF_8));
    }
}