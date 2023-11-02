package cn.jarkata.encrypt;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class JaBase64Test {

    @Test
    public void decodeBase64() {
        String encoded = JaBase64.encodeBase64("test".getBytes(StandardCharsets.UTF_8));
        System.out.println(encoded);
        byte[] decoded = JaBase64.decodeBase64(encoded);
        System.out.println(new String(decoded));
    }
}